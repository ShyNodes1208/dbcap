# DBCAP — Offline Database Connection Analyzer

DBCAP 是一个面向 DBA / 运维人员的 **数据库连接故障离线分析工具**。

它主要用于分析：

```text
应用服务器
    │
    │ TCP
    ▼
数据库服务器
```

发生数据库连接异常时，将：

* JDBC 全量日志
* 应用侧 PCAP / PCAPNG
* 数据库侧 PCAP / PCAPNG
* 可选 Ping 日志

放入同一个案例目录，DBCAP 可以自动整理为：

```text
JDBC 报错时间
    ↓
可能对应的 TCP 会话
    ↓
双端 PCAP 对应关系
    ↓
SEQ / ACK / LEN
    ↓
重传 / ACK_STALLED / RST
    ↓
Ping 辅助证据
    ↓
抓包质量
    ↓
统一时间线
    ↓
离线 HTML 报告
```

当前重点场景是数据库 JDBC 连接问题，包括达梦等数据库；数据库端口可以自行指定，不写死为 `5236`。

---

## 1. 当前版本

当前 Release Candidate：

```text
DBCAP v2.10.0-rc1
```

发布模式：

```text
Mode B
```

即：

> DBCAP 发布包中 **不包含 Wireshark / TShark 二进制**。

DBCAP 自身包含 Windows Python Runtime，但分析 PCAP 前需要用户提供 `tshark.exe`。

---

## 2. DBCAP 能做什么

当前主要支持：

* 单 PCAP TCP 会话分析
* 双端 PCAP 自动关联
* `tcp.stream` 会话识别
* TCP 三次握手分析
* `SEQ / ACK / LEN`
* Expected ACK 计算
* TCP 重传分析
* `ACK_STALLED`
* RST 分类
* Window / TCP 状态检查
* 抓包截断与 Capture Quality 判断
* JDBC 网络异常识别
* JDBC 报错时间线
* JDBC ↔ TCP Candidate 关联
* 多 JDBC Error 分析
* Ping 辅助证据
* APP / DB 双端报文对应
* 自动 Case 分析
* Batch 多案例分析
* 离线 HTML 报告
* Wireshark 复核过滤表达式

---

## 3. DBCAP 不做什么

DBCAP 当前不是：

* 实时抓包工具
* Wireshark 替代品
* 网络监控平台
* AWR / 数据库性能平台
* 数据库协议深度逆向工具
* 自动“甩锅”工具

DBCAP 不会仅凭一两份 PCAP 就直接判断：

```text
交换机故障
防火墙故障
数据库故障
应用故障
网卡故障
```

报告会尽量区分：

```text
CONFIRMED FACTS
CORRELATED EVIDENCE
SUPPORTING EVIDENCE
UNKNOWN / CANNOT DETERMINE
```

---

## 4. Windows 离线环境要求

推荐环境：

```text
Windows 10 x64
```

Release ZIP 已自带：

```text
Python Runtime
DBCAP
Python 依赖
启动脚本
HTML 报告组件
```

目标机器不需要预先安装：

```text
Python
Git
WSL
Node.js
```

离线分析已有 PCAP 时，也不需要 Npcap。

但是必须提供：

```text
tshark.exe
```

---

## 5. 下载与解压

从 GitHub Releases 下载：

```text
dbcap-v2.10.0-rc1-windows-x64.zip
```

建议解压，例如：

```text
D:\DBCAP\
```

也支持：

```text
D:\DBCAP Test\
D:\DBCAP(test)\
D:\数据库分析\DBCAP\
```

程序已经针对：

* 空格路径
* 括号路径
* 中文路径

进行过测试。

---

## 6. Release 目录结构

解压后大致如下：

```text
DBCAP\
│
├─ run.bat
├─ doctor.bat
├─ README.txt
├─ VERSION
├─ VERSION.txt
├─ NOTICE
├─ LICENSES.txt
├─ SHA256SUMS.txt
│
├─ app\
│   └─ dbcap\
│
├─ runtime\
│   └─ python\
│
├─ tools\
│   └─ tshark\
│
├─ config\
│
├─ input\
├─ output\
│
├─ examples\
│   └─ case-template\
│
└─ docs\
```

不要移动：

```text
runtime\python\
```

否则内置 Python Runtime 无法正常启动。

---

## 7. 第一步：准备 TShark

这是 Mode B 最重要的一步。

DBCAP Release **不包含 TShark**。

可以使用以下任意一种方式。

### 方式一：安装 Wireshark / TShark

在目标机器准备 Wireshark。

典型路径：

```text
C:\Program Files\Wireshark\tshark.exe
```

DBCAP 会尝试自动查找。

对于 DBCAP：

```text
只需要读取已有 PCAP
```

不需要使用实时抓包功能，因此不要求 Npcap。

### 方式二：放到 DBCAP tools 目录

可以自行准备一套 Wireshark/TShark Runtime，然后放到：

```text
DBCAP\
└─ tools\
   └─ tshark\
      ├─ tshark.exe
      ├─ capinfos.exe
      ├─ ...
      └─ 所需 DLL
```

最终保证：

```text
tools\tshark\tshark.exe
```

存在。

DBCAP 会优先使用这个位置。

注意：

> 不要只复制单独一个 `tshark.exe` 而遗漏它运行需要的 DLL。建议保持其运行时目录完整。

### 方式三：通过环境变量指定

CMD：

```bat
set DBCAP_TSHARK=D:\tools\Wireshark\tshark.exe
```

然后：

```bat
doctor.bat
```

PowerShell：

```powershell
$env:DBCAP_TSHARK="D:\tools\Wireshark\tshark.exe"
.\doctor.bat
```

### 方式四：使用 PATH

如果：

```bat
tshark --version
```

已经可以正常执行，DBCAP 也可以使用系统 PATH 中的 TShark。

---

## 8. 第二步：运行 doctor

第一次使用 DBCAP 时不要直接分析 PCAP。

先执行：

```bat
doctor.bat
```

或者：

```bat
run.bat doctor
```

重点检查：

```text
DBCAP Version
Python Runtime
Python isolated runtime
DBCAP Import
TShark Path
TShark Version
capinfos
Config
output directory
temporary directory
disk space
```

正常环境最终应该看到：

```text
Overall: PASS
```

---

## 9. Mode B 下 doctor 提示 TShark FAIL

刚解压 ZIP、还没有提供 TShark 时：

```text
TShark: FAIL
Overall: FAIL
```

这是正常现象。

它表示：

```text
DBCAP 本身已经存在
但是还没有找到 PCAP 解析引擎 TShark
```

按照第 7 节准备 TShark，然后重新：

```bat
doctor.bat
```

即可。

---

## 10. 推荐的案例目录结构

假设需要分析一次数据库连接异常：

```text
D:\cases\case001\
```

推荐放：

```text
case001\
│
├─ jdbc.log
│
├─ app.pcap
│
├─ db.pcap
│
└─ ping.log
```

其中：

```text
JDBC 日志       必需
应用侧 PCAP     必需
数据库侧 PCAP   必需
Ping 日志       可选
```

文件名实际上不要求叫：

```text
jdbc.log
app.pcap
db.pcap
ping.log
```

例如：

```text
应用日志_20260916.log
capture01.pcap
capture02.pcap
网络检测.txt
```

也是允许的。

`auto-case` 会根据**文件内容**识别类型，而不是简单根据文件名猜测。

---

## 11. 推荐先执行 dry-run

正式分析前建议先执行：

```bat
run.bat auto-case "D:\cases\case001" --port 5236 --server-ip 10.1.1.1 --dry-run
```

其中：

* `D:\cases\case001` 是案例目录
* `5236` 是数据库端口
* `10.1.1.1` 是数据库服务器 IP

`--dry-run` 只检查：

* 哪个文件是 JDBC 日志
* 哪个文件是 Ping 日志
* 哪两个是 PCAP
* 哪个可能是 APP_SIDE
* 哪个可能是 DB_SIDE
* 输入是否完整

不会进行完整分析。

同时会生成：

```text
input_manifest.json
```

用于查看文件识别结果。

---

## 12. Auto Case：自动分析一个案例

输入检查没有问题后执行：

```bat
run.bat auto-case "D:\cases\case001" --port 5236 --server-ip 10.1.1.1
```

DBCAP 会自动完成：

```text
文件发现
   ↓
JDBC 日志解析
   ↓
PCAP Role 判断
   ↓
双端 Flow Mapping
   ↓
JDBC Error Classification
   ↓
Candidate Flow 过滤
   ↓
Candidate Ranking
   ↓
TCP Evidence
   ↓
Ping Evidence
   ↓
Unified Timeline
   ↓
HTML Report
```

---

## 13. 如果 APP / DB 两份 PCAP 无法自动判断

DBCAP 不会为了给出结果而强行猜测。

如果证据不足，可能看到：

```text
PCAP roles are AMBIGUOUS.
```

此时手工指定：

```bat
run.bat auto-case "D:\cases\case001" ^
  --port 5236 ^
  --server-ip 10.1.1.1 ^
  --app-pcap "D:\cases\case001\capture01.pcap" ^
  --db-pcap "D:\cases\case001\capture02.pcap"
```

这比根据：

```text
文件名
文件顺序
创建时间
```

盲目猜测哪份是 APP / DB 更安全。

---

## 14. 没有 Ping 日志可以吗？

可以。

Ping 是：

```text
Supporting Evidence
```

不是核心输入。

没有 Ping 时仍然可以完成：

```text
JDBC
+
双端 PCAP
+
TCP
```

分析。

报告会显示类似：

```text
Ping Evidence:
NOT PROVIDED
```

---

## 15. 没有 JDBC 日志可以吗？

对于完整：

```text
JDBC → TCP
```

关联分析不可以。

因为程序需要 JDBC 报错时间作为主要关联依据。

如果 Auto Case 找不到 JDBC 日志，会提示：

```text
ERROR: No JDBC log was identified.
```

此时可以显式指定：

```bat
--jdbc-log "D:\cases\case001\jdbc.log"
```

---

## 16. 单份 PCAP 分析

如果只是分析一份 PCAP，不做 JDBC 双端 Case：

```bat
run.bat "D:\cases\capture.pcap" 5236
```

例如达梦数据库：

```bat
run.bat "D:\pcap\dm-app.pcap" 5236
```

这种模式主要检查：

* TCP Stream
* Handshake
* SEQ / ACK / LEN
* Retransmission
* ACK_STALLED
* RST
* Window
* Capture Quality

但它不能替代：

```text
双端 PCAP + JDBC
```

完整关联分析。

---

## 17. Batch：批量分析多个案例

例如：

```text
D:\cases\
│
├─ case001\
│   ├─ jdbc.log
│   ├─ app.pcap
│   └─ db.pcap
│
├─ case002\
│   ├─ jdbc.log
│   ├─ app.pcap
│   ├─ db.pcap
│   └─ ping.log
│
└─ case003\
    ├─ ...
```

执行：

```bat
run.bat batch "D:\cases" --port 5236 --server-ip 10.1.1.1
```

默认 `D:\cases\` 下的**一级子目录**分别作为独立 Case。

一个 Case 分析失败不会阻止后面的 Case。

---

## 18. Batch 输出

默认生成：

```text
D:\cases\dbcap_batch_output\
```

其中包括：

```text
batch_summary.csv
batch_summary.json
batch_report.html
```

以及每个 Case 自己的报告目录。

例如：

```text
dbcap_batch_output\
│
├─ batch_summary.csv
├─ batch_summary.json
├─ batch_report.html
│
├─ case001\
│   └─ report.html
│
├─ case002\
│   └─ report.html
│
└─ case003\
    └─ case_error.json
```

---

## 19. 单案例报告在哪里

Auto Case 默认输出到：

```text
<案例目录>\dbcap_output\
```

例如：

```text
D:\cases\case001\dbcap_output\
```

主要文件包括：

```text
report.html
dbcap_report.md
input_manifest.json
*.csv
```

具体输出文件会根据分析内容有所不同。

---

## 20. 推荐先看 report.html

普通 DBA / 运维人员建议首先打开：

```text
report.html
```

直接双击即可。

推荐浏览器：

```text
Chrome
Edge
```

报告是：

```text
Self-contained HTML
```

不需要：

```text
Web Server
Internet
CDN
```

---

## 21. HTML 报告重点看什么

建议按照下面顺序查看。

### ① Executive Summary

先看：

```text
JDBC Event
Correlation Status
Top Candidate
Capture Quality
```

### ② JDBC Events

确认：

```text
错误时间
错误类型
异常类
Caused by
```

例如：

```text
CONNECTION_RESET
READ_TIMEOUT
CONNECT_TIMEOUT
BROKEN_PIPE
```

### ③ Candidate Table

这里表示：

```text
哪个 TCP Flow 最可能对应 JDBC 错误
```

重点字段：

```text
Correlation ID
APP Stream
DB Stream
Identity Score
Health Score
```

注意：

`Identity Score` 用于回答：

> 这条 TCP 连接是不是 JDBC 报错对应的连接？

`Health Score` 用于描述：

> 这条 TCP 连接本身有多少异常？

两者不是一回事。

---

## 22. AMBIGUOUS 是什么意思

报告出现：

```text
AMBIGUOUS
```

不代表程序分析失败。

它表示：

```text
当前证据不足以唯一确认
JDBC 报错到底对应哪一条 TCP Connection
```

常见场景：

```text
连接池同时存在多条数据库连接
+
JDBC 日志没有记录 client source port
```

此时可能出现：

```text
Candidate #1
Candidate #2
```

分数非常接近。

DBCAP 会保留：

```text
AMBIGUOUS
```

而不是强行把第一名宣布为：

```text
CONFIRMED
```

---

## 23. NO_MATCH 是什么意思

如果：

```text
JDBC 报错时间附近
```

没有找到满足基本条件的 TCP Candidate，DBCAP 应返回：

```text
NO_MATCH
```

这比：

```text
随便挑一条最近 TCP Flow
```

更可靠。

---

## 24. SEQ / ACK / LEN 怎么看

DBCAP 报告会尽量给出 Frame 级证据：

```text
Frame
Direction
Seq
Ack
Len
Expected ACK
```

对于普通 TCP Payload：

```text
Expected ACK = Seq + Len
```

如果包含 SYN / FIN：

```text
Expected ACK = Seq + Len + 1
```

因为 SYN 和 FIN 各自会消耗一个 Sequence Number。

例如：

```text
Seq = 4895
Len = 73
```

则：

```text
Expected ACK = 4968
```

后续可在 Wireshark 中核对 ACK 是否推进到这个位置。

---

## 25. Retransmission 表示什么

TCP Retransmission 表示：

```text
发送方没有按预期得到确认
```

因此重新发送同一段数据。

但：

```text
出现 TCP 重传
```

并不能单独证明：

```text
交换机丢包
防火墙丢包
数据库故障
应用故障
```

仍然需要结合：

* 双端 PCAP
* ACK
* 时间
* RST
* Capture Quality
* JDBC Error

综合判断。

---

## 26. ACK_STALLED 是什么意思

假设：

```text
Seq = 1000
Len = 100
Expected ACK = 1100
```

但对端 ACK 长时间停留：

```text
ACK = 1000
```

同时发送方不断重传：

```text
Seq=1000 Len=100
```

DBCAP 可能识别为：

```text
ACK_STALLED
```

表示：

> ACK 没有推进到当前 Payload 的 Expected ACK。

---

## 27. Ping 怎么理解

Ping 只作为：

```text
SUPPORTING EVIDENCE
```

例如：

```text
Ping Reply
Ping Timeout
Destination Unreachable
```

不能直接得出：

```text
Ping 通
→ TCP 一定正常
```

也不能得出：

```text
Ping Timeout
→ 就是 JDBC 故障根因
```

ICMP 和数据库 TCP Connection 是不同协议链路证据。

---

## 28. Capture Quality 怎么理解

如果报告显示：

```text
Capture Quality:
DEGRADED
```

例如：

```text
file_cut_short=True
```

表示：

```text
抓包文件自身可能不完整
```

这与：

```text
TCP Connection 一定存在故障
```

不是同一个结论。

抓包质量问题会降低分析证据的完整程度。

---
