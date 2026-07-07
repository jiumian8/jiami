# 🛡️ NAS Secure Vault (NAS 高安全媒体加解密工具)

![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)
![Python](https://img.shields.io/badge/Python-3.11-yellow?logo=python)
![Security](https://img.shields.io/badge/Security-AES--256-success)
![UI](https://img.shields.io/badge/UI-TailwindCSS-06B6D4?logo=tailwindcss)

NAS Secure Vault 是一个专为 NAS（网络附加存储）环境设计的高安全性、容器化的文件加解密 Web 终端。它采用行业标准的密码学算法，配以现代化的响应式 Web UI，让您可以通过浏览器轻松、安全地批量管理敏感媒体文件。

## ✨ 核心特性

*   **🔏 军工级安全加密**：采用 `AES-256-CTR` 流加密算法，配合 `HMAC-SHA256` 进行文件完整性防篡改校验。
*   **🌐 现代化 Web UI**：基于 Tailwind CSS 构建的深色毛玻璃（Glassmorphism）极客面板，支持响应式布局。
*   **🚀 实时流式反馈**：通过 Server-Sent Events (SSE) 技术，提供带彩色进度条的实时终端日志输出。
*   **📁 多目录映射管理**：支持保存多个自定义目录映射（别名），彻底防御路径穿越（Path Traversal）漏洞。
*   **🔑 会话鉴权保护**：内置基于 Session 的系统登录防护，拒绝未经授权的网络访问。
*   **🐳 容器化原生**：轻量级 Docker 部署，无缝集成 GitHub Actions 实现 CI/CD 自动构建。

## 🚀 快速部署 (Docker Compose)

本项目推荐使用 Docker Compose 在 NAS 或 Linux 服务器上进行部署。

### 1. 准备配置文件

在您的 NAS 上创建一个目录，并在其中创建 `docker-compose.yml` 文件：

```yaml
services:
  nas-encryptor:
    image: ghcr.io/jiumian8/jiami:main
    container_name: nas-encryptor
    ports:
      - "8911:8911"
    environment:
      # 【新增】系统登录密码，请务必修改为强密码
      - ADMIN_PASSWORD=xxxxx
      # 【新增】Session 加密密钥，可随便填一串复杂的随机字符
      - SECRET_KEY=xxxxx
    volumes:
      - ./data:/data
      - /vol1/1000/加密文件夹:/加密
      - /vol1/1000/加密2:/加密2
    restart: unless-stopped
