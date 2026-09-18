DBCAP 2.10.0-rc1
Windows 离线数据库连接故障分析
================================

1. 这是什么
   把一次数据库连接故障的 JDBC 日志、应用侧 PCAP、数据库侧 PCAP、
   以及可选的 Ping 日志，整理成一份可离线打开的 HTML 报告。

2. 支持什么
   - 单个 PCAP 的 TCP 会话检查
   - 一个案例目录自动分析（auto-case）
   - 多个案例目录批量分析（batch）
   - 离线 HTML 报告（report.html）

3. 不支持什么
   - 实时抓包
   - 自动判断“是应用、数据库还是网络设备的责任”
   - 用 Ping 证明 TCP 正常或定位故障设备
   - 数据库协议深度解析
   - 需要联网安装的组件

4. 先准备 TShark（重要）
   本包【不包含】TShark / Wireshark。DBCAP 调用机器上已有的 tshark.exe。

   任选一种方式提供：

   方式一（推荐）：在目标机器安装 Wireshark
     用离线安装包安装 Wireshark（安装时勾选 TShark 组件即可，不需要
     安装 GUI，也不需要 Npcap）。DBCAP 会自动找到：
       C:\Program Files\Wireshark\tshark.exe

   方式二：放一份便携版到本目录
     把整个 Wireshark 目录复制到本包的 tools\tshark\ 下，使路径为：
       tools\tshark\tshark.exe
     这是 DBCAP 的第一搜索路径，效果等同于内置。仍然完全离线。

   方式三：指定路径
     设置环境变量指向任意位置的 tshark.exe：
       set DBCAP_TSHARK=D:\tools\Wireshark\tshark.exe

   若 tshark.exe 已在本机 PATH 中，DBCAP 也能直接找到。

   提示：没有 TShark 时 doctor 会报 Overall: FAIL —— 这是正常提示，
   表示还没准备好，不是程序损坏。装好 TShark 后重跑 doctor 即可。

5. 先运行 doctor
   解压后，在本目录打开命令行：
     doctor.bat
   或：
     run.bat doctor
   应显示 Overall: PASS。
   不访问网络，不要求安装 Npcap。
   若报 TShark: FAIL，回到第 4 节准备 TShark。

6. 分析一个案例目录
   把 JDBC 日志、两份 PCAP、可选 Ping 日志放在同一个文件夹。
   文件名不必固定。
     run.bat auto-case "D:\cases\case001" --port 5236 --server-ip 10.1.1.1
   先只看识别结果：
     run.bat auto-case "D:\cases\case001" --port 5236 --server-ip 10.1.1.1 --dry-run

7. 批量分析
     run.bat batch "D:\cases" --port 5236 --server-ip 10.1.1.1
   每个一级子目录是一个案例。
   汇总：D:\cases\dbcap_batch_output\batch_report.html

8. 报告在哪里
   单案例默认：<案例目录>\dbcap_output\report.html
   同时有 dbcap_report.md 和 CSV。
   用 Chrome 或 Edge 直接双击 report.html。不要用浏览器打开需要联网的页面。

9. 文件怎么放
   见 examples\case-template\README.txt
   程序看文件内容，不靠文件名猜角色。
   如果无法判断哪份是应用侧、哪份是数据库侧，会停止并提示你指定：
     --app-pcap <file> --db-pcap <file>
   没有 Ping 日志也可以分析。没有 JDBC 日志不能分析。

10. AMBIGUOUS 是什么意思
   表示当时有多条可能的数据库 TCP 连接，证据不够唯一确定
   JDBC 错误属于哪一条。这不是分析失败。
   排名第一的候选只是建议，不是已确认连接。

11. Ping 为什么不能证明 TCP 正常
   ICMP 通或超时只说明 Ping 本身。
   它不能证明 TCP 连接健康，也不能单独解释 JDBC 报错。

12. 常见报错
   ERROR: No JDBC log was identified.
     指定 --jdbc-log <文件>
   Dual-PCAP case requires 2 captures.
     需要应用侧和数据库侧各一份可读 PCAP。
   PCAP roles are AMBIGUOUS.
     指定 --app-pcap 和 --db-pcap。
   Built-in Python runtime not found.
     不要移动 runtime\python，先运行 doctor.bat。
   TShark: FAIL
     没找到 tshark.exe，见第 4 节。
     Wireshark 官方下载：https://www.wireshark.org/download.html

13. 单份 PCAP
    run.bat <pcap文件> <数据库端口>
    这只做单侧 TCP 检查，不能替代双端案例报告。

14. 许可证
   DBCAP 本身采用 Apache License 2.0，全文见 LICENSES.txt 与
   licenses\Apache-2.0.txt。
   第三方组件及其许可证见 LICENSES.txt。
   本包不含 Wireshark/TShark 二进制，因此不承担其 GPL 分发义务。
