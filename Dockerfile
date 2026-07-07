FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# 创建用于持久化存储配置的目录
RUN mkdir -p /app/config
EXPOSE 8911
CMD ["python", "app.py"]