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
from functools import wraps
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")

# ================= 核心配置 =================
CHUNK_SIZE = 1024 * 1024 * 4  # 4MB
class AllowAllSet:
    def __contains__(self, item): return True
ALLOWED_EXTENSIONS = AllowAllSet()
MAGIC_BYTES = b'ENC3'
VERSION = b'\x01'
KDF_ITERATIONS = 600000
HEADER_FORMAT = '<4s s I 16s 16s'  
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAC_SIZE = 32
CONFIG_FILE = "/app/config/settings.json"

task_queue = queue.Queue()
is_running = False
# ============================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except: pass
    return {"paths": []}

def save_config(data):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存配置失败: {e}")

def emit_log(msg, progress=None):
    data = {}
    if msg is not None: data["msg"] = msg
    if progress is not None: data["progress"] = progress
    task_queue.put(data)

def derive_keys(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=salt, iterations=iterations)
    key_material = kdf.derive(password.encode('utf-8'))
    return key_material[:32], key_material[32:]

def best_effort_wipe(filepath: Path):
    try:
        file_size = filepath.stat().st_size
        if file_size == 0:
            filepath.unlink()
            return
        emit_log(f"  正在安全擦除源文件(防恢复)...")
        bytes_written = 0
        zero_chunk = b'\x00' * CHUNK_SIZE
        with open(filepath, "r+b") as f:
            while bytes_written < file_size:
                write_size = min(len(zero_chunk), file_size - bytes_written)
                f.write(zero_chunk[:write_size])
                bytes_written += write_size
                emit_log(None, (bytes_written / file_size) * 100)
            f.flush()
            os.fsync(f.fileno())
        filepath.unlink()
        emit_log(f"  [原文件粉碎成功并已安全清理]")
    except Exception as e:
        emit_log(f"  [警告] 尽力覆盖删除失败: {e} (已退化为普通删除)")
        if filepath.exists(): filepath.unlink()

def sanitize_filename(filename: str) -> str:
    return re.sub(r'[\\/*?:"<>|\x00-\x1f]', "", filename).strip() or "unnamed_decrypted_file"

def encrypt_file(filepath: Path, password: str) -> bool:
    tmp_filepath = None
    try:
        tmp_filepath = filepath.with_name(f"{uuid.uuid4().hex}.enc.tmp")
        final_filepath = tmp_filepath.with_suffix('')
        salt, nonce = os.urandom(16), os.urandom(16)
        aes_key, hmac_key = derive_keys(password, salt, KDF_ITERATIONS)
        h = hmac.new(hmac_key, digestmod=hashlib.sha256)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        
        name_bytes = filepath.name.encode('utf-8')
        name_len_bytes = struct.pack('<I', len(name_bytes))
        header = struct.pack(HEADER_FORMAT, MAGIC_BYTES, VERSION, KDF_ITERATIONS, salt, nonce)
        total_size, processed_size = filepath.stat().st_size, 0

        with open(filepath, 'rb') as f_in, open(tmp_filepath, 'wb') as f_out:
            # 修复：严格分离加密与写操作，确保同一份密文同时写入文件和注入 HMAC
            f_out.write(header)
            h.update(header)
            
            enc_name_len = encryptor.update(name_len_bytes)
            f_out.write(enc_name_len)
            h.update(enc_name_len)
            
            enc_name = encryptor.update(name_bytes)
            f_out.write(enc_name)
            h.update(enc_name)
            
            while chunk := f_in.read(CHUNK_SIZE):
                enc_chunk = encryptor.update(chunk)
                f_out.write(enc_chunk)
                h.update(enc_chunk)
                
                processed_size += len(chunk)
                emit_log(None, (processed_size / total_size) * 100 if total_size > 0 else 100.0)
                
            enc_final = encryptor.finalize()
            f_out.write(enc_final)
            h.update(enc_final)
            f_out.write(h.digest())
            
        tmp_filepath.rename(final_filepath)
        emit_log(f"  [加密完成] -> {final_filepath.name}")
        best_effort_wipe(filepath)
        return True
    except Exception as e:
        emit_log(f"  [加密失败] {filepath.name}: {e}")
        if tmp_filepath and tmp_filepath.exists(): tmp_filepath.unlink()
        return False

def decrypt_file(filepath: Path, password: str) -> bool:
    tmp_output_filepath = None
    try:
        file_size = filepath.stat().st_size
        if file_size < HEADER_SIZE + MAC_SIZE + 4: return False

        with open(filepath, 'rb') as f_in:
            emit_log(f"  [阶段 1] 完整性校验...")
            header = f_in.read(HEADER_SIZE)
            magic, version, iterations, salt, nonce = struct.unpack(HEADER_FORMAT, header)
            if magic != MAGIC_BYTES: return False
                
            aes_key, hmac_key = derive_keys(password, salt, iterations)
            h = hmac.new(hmac_key, digestmod=hashlib.sha256)
            h.update(header)
            
            payload_size, bytes_read = file_size - HEADER_SIZE - MAC_SIZE, 0
            while bytes_read < payload_size:
                chunk = f_in.read(min(CHUNK_SIZE, payload_size - bytes_read))
                h.update(chunk)
                bytes_read += len(chunk)
                emit_log(None, (bytes_read / payload_size) * 100 if payload_size > 0 else 100.0)
                
            if not hmac.compare_digest(h.digest(), f_in.read(MAC_SIZE)):
                emit_log(f"  [拒绝解密] {filepath.name}: HMAC校验失败 (密码错误或篡改)")
                return False
            
            emit_log(f"  [阶段 2] 校验通过，正在解密...")
            f_in.seek(HEADER_SIZE)
            cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            
            name_len = struct.unpack('<I', decryptor.update(f_in.read(4)))[0]
            safe_name = sanitize_filename(decryptor.update(f_in.read(name_len)).decode('utf-8', errors='ignore'))
            output_filepath = filepath.with_name(safe_name)
            tmp_output_filepath = filepath.with_name(safe_name + ".tmp")
            
            if output_filepath.exists(): 
                emit_log(f"  [跳过] 文件 {safe_name} 已存在。")
                return False

            data_size, processed_size = payload_size - 4 - name_len, 0
            with open(tmp_output_filepath, 'wb') as f_out:
                while processed_size < data_size:
                    chunk = f_in.read(min(CHUNK_SIZE, data_size - processed_size))
                    f_out.write(decryptor.update(chunk))
                    processed_size += len(chunk)
                    emit_log(None, (processed_size / data_size) * 100 if data_size > 0 else 100.0)

        tmp_output_filepath.rename(output_filepath)
        emit_log(f"  [解密成功] -> {safe_name}")
        filepath.unlink() 
        return True
    except Exception as e:
        emit_log(f"  [解密崩溃] {filepath.name}: {e}")
        if tmp_output_filepath and tmp_output_filepath.exists(): tmp_output_filepath.unlink()
        return False

# 支持多目录遍历
def process_directory_task(target_dirs: list, mode: str, password: str):
    global is_running
    is_running = True
    try:
        total_processed = 0
        for target_dir in target_dirs:
            target_path = Path(target_dir)
            if not target_path.exists() or not target_path.is_dir():
                emit_log(f"[跳过] 目录 {target_dir} 不存在。")
                continue
            
            emit_log(f"\n>> 正在进入目录: {target_dir}")
            files = [f for f in target_path.rglob('*') if f.is_file()]
            
            for filepath in files:
                if mode == 'encrypt' and filepath.suffix.lower() != '.enc':
                    emit_log(f"[*] 处理文件: {filepath.name}")
                    if encrypt_file(filepath, password): total_processed += 1
                elif mode == 'decrypt' and filepath.suffix.lower() == '.enc':
                    emit_log(f"[*] 处理文件: {filepath.name}")
                    if decrypt_file(filepath, password): total_processed += 1
                    
        emit_log(f"\n[任务结束] 所有勾选目录处理完毕，共成功处理 {total_processed} 个文件。")
        emit_log("DONE")
    except Exception as e:
        emit_log(f"发生致命错误: {e}")
        emit_log("DONE")
    finally:
        is_running = False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="密码错误")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/paths', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_paths():
    config = load_config()
    if request.method == 'GET':
        return jsonify(config.get('paths', []))
    
    if request.method == 'POST':
        data = request.json
        if not data.get("path", "").startswith("/"):
            return jsonify({"status": "error", "msg": "必须使用绝对路径"}), 400
            
        new_path = {
            "id": uuid.uuid4().hex,
            "name": data.get("name"),
            "path": data.get("path")
        }
        config.setdefault("paths", []).append(new_path)
        save_config(config)
        return jsonify({"status": "success"})
        
    if request.method == 'DELETE':
        path_id = request.json.get("id")
        config["paths"] = [p for p in config.get("paths", []) if p["id"] != path_id]
        save_config(config)
        return jsonify({"status": "success"})

@app.route('/start', methods=['POST'])
@login_required
def start_task():
    global is_running
    if is_running:
        return jsonify({"status": "error", "msg": "当前已有任务正在运行，请稍候。"}), 400
        
    data = request.json
    # 接收数组格式的 path_ids
    path_ids = data.get('path_ids', [])
    mode = data.get('mode')
    password = data.get('password')
    
    if not path_ids or not mode or not password:
        return jsonify({"status": "error", "msg": "参数不完整或未勾选任何目录"}), 400
        
    config = load_config()
    target_dirs = [p['path'] for p in config.get('paths', []) if p['id'] in path_ids]
    
    if not target_dirs:
        return jsonify({"status": "error", "msg": "选中的目录非法或不存在"}), 400
    
    while not task_queue.empty(): task_queue.get()
        
    thread = threading.Thread(target=process_directory_task, args=(target_dirs, mode, password))
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "success", "msg": "任务已启动"})

@app.route('/stream')
@login_required
def stream():
    def event_stream():
        while True:
            try:
                data = task_queue.get(timeout=1)
                yield f"data: {json.dumps(data)}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"
    return Response(event_stream(), mimetype="text/event-stream")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8911, debug=False)