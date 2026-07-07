import os
import sys
import uuid
import struct
import json
import re
import hmac       
import hashlib    
import threading
import queue
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)

# ================= 核心配置 =================
CHUNK_SIZE = 1024 * 1024 * 4  # 4MB
class AllowAllSet:
    def __contains__(self, item):
        return True
ALLOWED_EXTENSIONS = AllowAllSet()
MAGIC_BYTES = b'ENC3'
VERSION = b'\x01'
KDF_ITERATIONS = 600000
HEADER_FORMAT = '<4s s I 16s 16s'  
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAC_SIZE = 32
CONFIG_FILE = "/app/config/settings.json"

# 全局任务队列，用于向前端推送日志和进度
task_queue = queue.Queue()
is_running = False
# ============================================

def emit_log(msg, progress=None):
    """向前端推送日志和进度的辅助函数"""
    data = {"msg": msg}
    if progress is not None:
        data["progress"] = progress
    task_queue.put(data)

def load_last_path():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f).get('last_path', '/data')
        except:
            pass
    return '/data'

def save_last_path(path):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump({'last_path': path}, f)
    except Exception as e:
        print(f"保存配置失败: {e}")

def derive_keys(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=iterations
    )
    key_material = kdf.derive(password.encode('utf-8'))
    return key_material[:32], key_material[32:]

def best_effort_wipe(filepath: Path):
    try:
        file_size = filepath.stat().st_size
        if file_size == 0:
            filepath.unlink()
            return
        emit_log(f"正在安全擦除源文件(防恢复): {filepath.name}")
        bytes_written = 0
        zero_chunk = b'\x00' * CHUNK_SIZE
        with open(filepath, "r+b") as f:
            while bytes_written < file_size:
                write_size = min(len(zero_chunk), file_size - bytes_written)
                f.write(zero_chunk[:write_size])
                bytes_written += write_size
                progress = (bytes_written / file_size) * 100
                emit_log(None, progress)
            f.flush()
            os.fsync(f.fileno())
        filepath.unlink()
        emit_log(f"[原文件粉碎成功并已安全清理] {filepath.name}")
    except Exception as e:
        emit_log(f"[警告] 尽力覆盖删除失败 {filepath.name}: {e} (已退化为普通删除)")
        if filepath.exists():
            filepath.unlink()

def sanitize_filename(filename: str) -> str:
    safe_name = re.sub(r'[\\/*?:"<>|\x00-\x1f]', "", filename)
    return safe_name.strip() or "unnamed_decrypted_file"

def encrypt_file(filepath: Path, password: str) -> bool:
    tmp_filepath = None
    try:
        tmp_filepath = filepath.with_name(f"{uuid.uuid4().hex}.enc.tmp")
        final_filepath = tmp_filepath.with_suffix('')
        salt = os.urandom(16)
        nonce = os.urandom(16)
        aes_key, hmac_key = derive_keys(password, salt, KDF_ITERATIONS)
        h = hmac.new(hmac_key, digestmod=hashlib.sha256)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        original_name_bytes = filepath.name.encode('utf-8')
        name_len_bytes = struct.pack('<I', len(original_name_bytes))
        header = struct.pack(HEADER_FORMAT, MAGIC_BYTES, VERSION, KDF_ITERATIONS, salt, nonce)
        total_size = filepath.stat().st_size
        processed_size = 0

        with open(filepath, 'rb') as f_in, open(tmp_filepath, 'wb') as f_out:
            f_out.write(header)
            h.update(header)
            enc_name_len = encryptor.update(name_len_bytes)
            enc_name = encryptor.update(original_name_bytes)
            f_out.write(enc_name_len)
            f_out.write(enc_name)
            h.update(enc_name_len)
            h.update(enc_name)
            
            while chunk := f_in.read(CHUNK_SIZE):
                enc_chunk = encryptor.update(chunk)
                f_out.write(enc_chunk)
                h.update(enc_chunk)
                processed_size += len(chunk)
                progress = (processed_size / total_size) * 100 if total_size > 0 else 100.0
                emit_log(None, progress)
                
            enc_final = encryptor.finalize()
            f_out.write(enc_final)
            h.update(enc_final)
            f_out.write(h.digest())
            
        tmp_filepath.rename(final_filepath)
        emit_log(f"[加密完成] -> 混淆名为: {final_filepath.name}")
        best_effort_wipe(filepath)
        return True
    except Exception as e:
        emit_log(f"[加密失败] {filepath.name}: {e}")
        if tmp_filepath and tmp_filepath.exists():
            tmp_filepath.unlink()
        return False

def decrypt_file(filepath: Path, password: str) -> bool:
    tmp_output_filepath = None
    try:
        file_size = filepath.stat().st_size
        if file_size < HEADER_SIZE + MAC_SIZE + 4:
            emit_log(f"[解密失败] {filepath.name}: 文件体积过小，已损坏。")
            return False

        with open(filepath, 'rb') as f_in:
            emit_log(f"[阶段 1/2] 正在验证文件完整性(防篡改)... {filepath.name}")
            header = f_in.read(HEADER_SIZE)
            magic, version, iterations, salt, nonce = struct.unpack(HEADER_FORMAT, header)
            
            if magic != MAGIC_BYTES:
                emit_log(f"[解密失败] {filepath.name}: 魔法字节不匹配，不是受支持的文件或已损坏。")
                return False
                
            aes_key, hmac_key = derive_keys(password, salt, iterations)
            h = hmac.new(hmac_key, digestmod=hashlib.sha256)
            h.update(header)
            
            payload_size = file_size - HEADER_SIZE - MAC_SIZE
            bytes_read = 0
            
            while bytes_read < payload_size:
                chunk_size = min(CHUNK_SIZE, payload_size - bytes_read)
                chunk = f_in.read(chunk_size)
                h.update(chunk)
                bytes_read += len(chunk)
                progress = (bytes_read / payload_size) * 100 if payload_size > 0 else 100.0
                emit_log(None, progress)
                
            stored_mac = f_in.read(MAC_SIZE)
            if not hmac.compare_digest(h.digest(), stored_mac):
                emit_log(f"[拒绝解密] {filepath.name}: HMAC校验失败 (密码错误或文件遭篡改)！")
                return False
            
            emit_log(f"[阶段 2/2] 校验通过，正在解密数据... {filepath.name}")
            f_in.seek(HEADER_SIZE)
            cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            
            enc_name_len_bytes = f_in.read(4)
            name_len = struct.unpack('<I', decryptor.update(enc_name_len_bytes))[0]
            enc_name_bytes = f_in.read(name_len)
            original_name = decryptor.update(enc_name_bytes).decode('utf-8', errors='ignore')
            safe_name = sanitize_filename(original_name)
            
            output_filepath = filepath.with_name(safe_name)
            tmp_output_filepath = filepath.with_name(safe_name + ".tmp")
            
            if output_filepath.exists():
                emit_log(f"[跳过] 解密后的文件 {safe_name} 已存在。")
                return False

            data_size = payload_size - 4 - name_len
            processed_size = 0
            
            with open(tmp_output_filepath, 'wb') as f_out:
                while processed_size < data_size:
                    chunk_size = min(CHUNK_SIZE, data_size - processed_size)
                    chunk = f_in.read(chunk_size)
                    f_out.write(decryptor.update(chunk))
                    processed_size += len(chunk)
                    progress = (processed_size / data_size) * 100 if data_size > 0 else 100.0
                    emit_log(None, progress)

        tmp_output_filepath.rename(output_filepath)
        emit_log(f"[解密成功] -> 还原为: {safe_name}")
        filepath.unlink() 
        return True
    except Exception as e:
        emit_log(f"[解密崩溃] {filepath.name}: 发生异常 ({e})")
        if tmp_output_filepath and tmp_output_filepath.exists():
            tmp_output_filepath.unlink()
        return False

def process_directory_task(target_dir: str, mode: str, password: str):
    global is_running
    is_running = True
    try:
        target_path = Path(target_dir)
        if not target_path.exists() or not target_path.is_dir():
            emit_log(f"错误：目录 {target_dir} 不存在或不是文件夹。")
            return

        processed_count = 0
        files = [f for f in target_path.rglob('*') if f.is_file()]
        
        for filepath in files:
            if mode == 'encrypt':
                if filepath.suffix.lower() in ALLOWED_EXTENSIONS and filepath.suffix.lower() != '.enc':
                    emit_log(f"\n开始处理: {filepath.name}")
                    if encrypt_file(filepath, password):
                        processed_count += 1
            elif mode == 'decrypt':
                if filepath.suffix.lower() == '.enc':
                    emit_log(f"\n开始处理: {filepath.name}")
                    if decrypt_file(filepath, password):
                        processed_count += 1
                        
        emit_log(f"\n[任务结束] 共成功处理了 {processed_count} 个文件。")
        emit_log("DONE")
    except Exception as e:
        emit_log(f"发生致命错误: {e}")
        emit_log("DONE")
    finally:
        is_running = False

@app.route('/')
def index():
    last_path = load_last_path()
    return render_template('index.html', last_path=last_path)

@app.route('/start', methods=['POST'])
def start_task():
    global is_running
    if is_running:
        return jsonify({"status": "error", "msg": "当前已有任务正在运行，请稍候。"}), 400
        
    data = request.json
    target_dir = data.get('target_dir')
    mode = data.get('mode')
    password = data.get('password')
    
    if not target_dir or not mode or not password:
        return jsonify({"status": "error", "msg": "参数不完整。"}), 400
        
    save_last_path(target_dir)
    
    # 清空之前的队列残留
    while not task_queue.empty():
        task_queue.get()
        
    thread = threading.Thread(target=process_directory_task, args=(target_dir, mode, password))
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "success", "msg": "任务已启动"})

@app.route('/stream')
def stream():
    def event_stream():
        while True:
            try:
                data = task_queue.get(timeout=1)
                yield f"data: {json.dumps(data)}\n\n"
            except queue.Empty:
                # 保持连接活跃
                yield ": keep-alive\n\n"
    return Response(event_stream(), mimetype="text/event-stream")

if __name__ == '__main__':
    # 强制不使用缓存，方便在容器中刷新
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(host='0.0.0.0', port=8911, debug=False)