# DBCAP 用户指南（V1.0.0）

## 1. 工具用途

DBCAP Offline Analyzer 用于分析 **应用服务器 ↔ 数据库服务器** 之间的 TCP 抓包文件（`.pcap` / `.pcapng`），自动输出可人工复核的证据。

它把 DBA 在 Wireshark 中手工做的会话识别、握手、重传、ACK 推进、RST、窗口与截断检查自动化。

## 2. 支持的 PCAP

- `.pcap`
- `.pcapng`
- 单侧抓包即可分析（应用侧或数据库侧）

不支持：实时抓包、在线下载、自动根因定罪。

## 3. 基本命令

```bat
doctor.bat
run.bat <pcap文件> <数据库端口>
run.bat <pcap文件> <数据库端口> <输出目录>
```

示例：

```bat
run.bat input\case01.pcap 5236
run.bat H:\case\2.pcap 5236
run.bat "D:\抓包\案例 01.pcap" 5236 D:\result\case01
```

等价 Python（发布包内部）：

```bat
runtime\python\python.exe -m dbcap --version
runtime\python\python.exe -m dbcap doctor
```

## 4. 数据库端口参数

第二个参数是数据库监听端口，**任意可配置**：

| 类型 | 常见端口 |
|------|----------|
| 达梦 | 5236 |
| Oracle | 1521 |
| MySQL | 3306 |
| PostgreSQL | 5432 |
| SQL Server | 1433 |

不要假设永远是 5236。

## 5. 输出文件说明

默认输出到：

```text
output\<pcap文件名>_<时间戳>\
```

包含：

| 文件 | 含义 |
|------|------|
| `report.md` | 给人看的主报告 |
| `evidence.csv` | Frame 级证据表 |
| `flows.csv` | TCP 会话汇总 |
| `anomalies.json` | 异常结构化数据 |
| `payload/` | 异常 Segment 的 payload 样本 |
| `dbcap_report_*.json` | 完整 JSON（兼容） |

## 6. 如何阅读 report.md

建议顺序：

1. 分析对象 / 抓包完整性
2. 总体结论
3. 持续重传 / ACK 未推进 / RST
4. Wireshark 人工复核过滤器
5. 当前无法确认的事项

## 7. evidence.csv

每个异常相关 Frame 一行，关键列：

- frame_number, timestamp, tcp_stream, direction
- seq, ack, len, expected_ack
- payload_sha256, anomaly_type, severity, evidence_level
- wireshark_filter

可用 Excel 打开。

## 8. flows.csv

每个 `tcp.stream` 一行会话统计（包数、方向字节、RST/FIN、握手延迟等）。

## 9. anomalies.json

程序判定的异常列表，含 facts / inferences / unknowns，便于二次处理。

## 10. payload/

异常持续重传 Segment 的二进制样本。若 PCAP 被 snaplen 截断，这里也是截断后的字节，**不会猜测 SQL**。

## 11. Wireshark Filter

报告中的 Filter 可直接粘贴到 Wireshark 显示过滤器，例如：

```text
tcp.stream eq 14 && (frame.number == 8721 || frame.number == 8724)
```

## 12. Evidence Level

| 等级 | 含义 |
|------|------|
| CONFIRMED | PCAP 可直接确认的事实 |
| STRONG | 强证据推断 |
| SUSPECTED | 可疑，需复核 |
| UNKNOWN | 当前无法确认 |

## 13. Severity

| 级别 | 含义 |
|------|------|
| INFO | 记录 / 低影响（如 FIN 后 RST） |
| WARNING | 需关注 |
| HIGH | 高优先级（如数据面持续重传、ACK_STALLED） |

控制面重传（SYN/FIN/零长度）与数据面重传已分类：

- `CONTROL_PLANE_RETRANSMISSION`
- `DATA_RETRANSMISSION`

## 14. 常见故障案例（如何理解）

### 持续重传
同一 Seq/Len/Payload Hash 重复出现 → 同一 Segment 被多次发送。

### ACK_STALLED
发送侧重复同一数据段，对端累计 ACK 长期不推进到 Expected ACK。

### RST_AFTER_FIN
常见于连接清理，通常是 INFO，不一定是网络故障。

### PACKET_TRUNCATED
`cap_len < frame.len`，Payload/协议可信度下降。

## 15. 当前限制

**单侧 PCAP 不能自动确定交换机、防火墙、网卡等具体根因。**

PCAP 可以确认方向、Segment、是否重复发送、ACK 是否推进、是否 RST、Window 状态；  
不能确认丢包发生在哪一段路径。需要双端 PCAP 或网络设备数据进一步定位。

详见 `docs/DBCAP_V1_ACCEPTANCE.md`。
