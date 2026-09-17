DBCAP Offline Analyzer V1.0.0
================================

一、这是什么
  应用服务器 <-> 数据库服务器 之间 TCP 抓包（PCAP）的离线故障分析工具。
  当前重点：达梦等数据库端口可配置；不写死 5236。

二、支持什么
  - 离线分析 .pcap / .pcapng
  - tcp.stream 会话、握手、重传、ACK_STALLED、RST、截断检查
  - 输出 report.md / evidence.csv / flows.csv / anomalies.json / payload/

三、不支持什么
  - 实时抓包
  - 自动判定交换机/防火墙/网卡根因（单侧 PCAP 做不到）
  - 达梦/Oracle/MySQL 深度协议逆向
  - 双端 PCAP 自动关联（后续版本）

四、现场 5 步
  1) 解压 dbcap-v1.0.0-windows-x64.zip
  2) 双击 doctor.bat   （应显示 Overall: PASS）
  3) 把 PCAP 放入 input\ 目录（可选）
  4) 打开 CMD，进入本目录，执行：
       run.bat input\case01.pcap 5236
     或：
       run.bat H:\case\2.pcap 5236
  5) 用记事本 / VS Code / Typora 打开：
       output\<名称>_<时间>\report.md

五、输出在哪里
  默认：output\<pcap名>_<时间戳>\
  也可指定：run.bat case.pcap 5236 D:\result\case01

六、常见错误
  - 未找到 TShark → 运行 doctor.bat，检查 tools\tshark\
  - PCAP 不存在 → 检查路径/中文/空格，或放到 input\
  - 端口不是数字 → 第二个参数必须是端口，例如 5236

七、详细文档
  docs\USER_GUIDE.md
  docs\OFFLINE_DEPLOYMENT.md
  docs\TROUBLESHOOTING.md
  docs\DBCAP_V1_ACCEPTANCE.md

八、版本
  见根目录 VERSION 文件（当前 1.0.0）

九、许可证提示
  见 LICENSES.txt（含 Wireshark/TShark GPL 说明）
