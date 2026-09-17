# DBCAP V1 验收报告

**验收日期**: 2026-09-15  
**项目路径**: `C:\DBCAP`（示例路径；验收在独立工程目录完成）  

**验收结论**: **PASS**

---

## 1. 当前版本

| 项 | 值 |
|----|----|
| 工具 | DBCAP Offline Analyzer |
| 版本 | **1.0.0**（功能验收基线曾记为 0.2.0 / 24 tests；发布前增至 27+ tests） |
| 定位 | 单侧 PCAP 离线 TCP 故障分析（应用 ↔ 数据库） |
| 入口 | `python -m dbcap` / `run.bat` / `python -m dbcap doctor` |

---

## 2. 第一阶段 10 项状态

| # | 功能 | 状态 |
|---|------|------|
| 1 | tcp.stream 会话 | ✅ |
| 2 | TCP 会话汇总 | ✅ |
| 3 | 三次握手 / 缺 SYN → N/A | ✅ |
| 4 | SEQ / ACK / LEN / Expected ACK | ✅ |
| 5 | SYN / FIN Seq +1 | ✅ |
| 6 | 持续重传（Segment Key） | ✅ |
| 7 | ACK_STALLED | ✅ |
| 8 | RST 分类 | ✅ |
| 9 | 抓包完整性 | ✅ |
| 10 | Frame 级证据报告 | ✅ |

V1 验收期间补充（非新阶段功能，属误报治理）：

- `DATA_RETRANSMISSION` / `CONTROL_PLANE_RETRANSMISSION` 分类
- 控制面重传最高 `WARNING`，不计入多流 HIGH
- `ACK_STALLED` / `RST` / 截断样本写入 `evidence.csv`
- `run.bat`、`python -m dbcap doctor`

---

## 3. 自动化测试结果

```text
python -m pytest -v
24 passed, 0 failed, 0 skipped
```

（验收初跑 22 passed；补充控制面分类测试后为 24 passed。）

---

## 4. 真实 PCAP 清单

| 标签 | 路径 |
|------|------|
| normal | `dm-jdbc-pool-lab/captures/acceptance-normal-20260915-093115/db-pcap/db-side.pcap` |
| app-close | `.../acceptance-app-close-20260912-211011/db-pcap/db-side.pcap` |
| fault | `.../fault-app-loss-20260915-093710/db-pcap/db-side.pcap` |
| twopcap | `D:\case\2.pcap`（示例） |

输出目录：`output\v1_*` 与 `output\demo`。

每份均生成：

```text
report.md / evidence.csv / flows.csv / anomalies.json / payload/ / dbcap_report_*.json
```

---

## 5. 正常样本验证

### acceptance-normal
- Overall: **INFO**
- Sessions: 1
- Persistent Retx: 0
- ACK Stalled: 0
- RST: 0
- Zero Window: 0
- Anomalies: **0**
- **无 HIGH** → 通过

### acceptance-app-close
- Overall: **INFO**
- Persistent Retx / ACK_STALLED / RST / ZW: 均为 0
- Anomalies: **0**
- **无 HIGH** → 通过

---

## 6. 故障样本验证

### fault-app-loss-093710
- Overall: **HIGH**
- DATA_RETRANSMISSION: Seq=9256/99 ×8；Seq=15070/166 ×7 等
- ACK_STALLED: Expected=15236 Observed=15070
- RST: ACK_TO_RST / RST_AFTER_SYN
- CONTROL_PLANE_RETRANSMISSION: Seq=0 Len=0 → **WARNING**（不再与数据面混为同一 HIGH）

### 2.pcap
- Overall: **HIGH**
- 数据面持续重传 + ACK_STALLED + PACKET_TRUNCATED + 大量 RST_AFTER_FIN(INFO)
- 控制面重传单独分类为 WARNING

---

## 7. 2.pcap Seq/Ack/Len 证据

### Case A — Seq=4453 Len=73

| 字段 | 程序结果 |
|------|----------|
| Expected ACK | **4526** |
| tcp.stream | **14** |
| Direction | client_to_server（应用 → 数据库） |
| count | 12 |
| duration_ms | 4584.16 |
| Frame | **8720**, 8722, 8725, … |
| Payload SHA256 | `20e0379eb6896497e0dc7f8779f1730546d082a5f7ed44a3c368243271de32df` |
| 分类 | DATA_RETRANSMISSION / HIGH |

### Case B — Seq=5810 Len=124

| 字段 | 程序结果 |
|------|----------|
| Expected ACK | **5934** |
| Observed ACK | **5810** |
| 判定 | **ACK_STALLED** / HIGH / CONFIRMED |
| tcp.stream | **14** |
| Direction | server_to_client（数据库 → 应用） |
| 重传次数 | 11 |
| 持续时间 | 3208.926 ms |
| Frames | 8721, 8724, 8727, … 8759 |
| Payload SHA256 | `34fa422f05a0c9fe…` |

Wireshark Filter（可直接复制）：

```text
tcp.stream eq 14 && (frame.number == 8721 || frame.number == 8724 || frame.number == 8727 || frame.number == 8730 || frame.number == 8733 || frame.number == 8736 || frame.number == 8739 || frame.number == 8743 || frame.number == 8748 || frame.number == 8752 || frame.number == 8759)
```

---

## 8. TShark 交叉验证

| 验证项 | 结果 |
|--------|------|
| Case A Frame 8720 seq/len/payload SHA256 | 与程序一致（SHA256 完全匹配） |
| Case B Frame 8721+ seq=5810 len=124 + analysis.retransmission | 与程序 frames 一致 |
| stream 14 对端 ACK 停留在 5810 | 与 ACK_STALLED Observed=5810 一致 |
| Expected ACK 4526 / 5934 | `seq+len` 与程序一致 |
| 正常握手 latency | TShark Δt ≈ 0.072 ms（历史验收已交叉） |

---

## 9. 误报检查

| 检查 | 结果 |
|------|------|
| 纯 SYN → ACK_STALLED | **无**（len==0 不进入 ACK_STALLED） |
| SYN/FIN/零长度重传 → HIGH 数据面 | **无**；归类 `CONTROL_PLANE_RETRANSMISSION`，最高 WARNING |
| 正常样本 HIGH | **无** |
| 正常关闭（app-close）严重异常 | **无** |
| Keepalive/控制段与业务重传混级 | **已分离** |

---

## 10. 输出文件一致性检查

随机抽查 5 类异常（2.pcap）：

| 异常 | report.md | evidence.csv | anomalies.json | 结果 |
|------|-----------|--------------|----------------|------|
| DATA_RETRANSMISSION Seq=4453 | ✅ | frame 8720 / stream 14 / exp 4526 | ✅ | 一致 |
| ACK_STALLED Seq=5810 | ✅ | frame 8721 / exp 5934 | ✅ | 一致 |
| DATA_RETRANSMISSION Seq=7335 | ✅ | frame 1374 / stream 1 | ✅ | 一致 |
| RST_AFTER_FIN frame 2688 | ✅ | 1 行证据 | ✅ | 一致 |
| PACKET_TRUNCATED | ✅ | 20 行样本证据 | ✅ | 一致 |

**CONSISTENCY_PASS**

---

## 11. Windows 命令验证

```bat
REM Dev/source mode example (not required for offline release package):
set PYTHONPATH=C:\DBCAP
set PATH=C:\Program Files\Wireshark;%PATH%
python -m dbcap -f D:\case\2.pcap -p 5236 -o C:\DBCAP\output\demo
```

**通过**（Loaded 48326 packets，72 sessions，产出完整报告）。

```bat
run.bat D:\case\2.pcap 5236 C:\DBCAP\output\demo
run.bat doctor
python -m dbcap doctor
```

**通过**（doctor: PASS — Python / TShark / 导入 / 输出可写）。

---

## 12. 当前限制

1. 依赖本机 TShark；无网络探测（符合离线定位）
2. 单侧 PCAP **不能**确认交换机/防火墙/网卡根因；报告写明「当前单侧 PCAP 无法进一步定位」
3. snaplen 截断时 Payload 不完整
4. 达梦协议 Decoder 仍为 stub
5. 超大 PCAP 全量驻留内存
6. 未打包 EXE（非 V1 阻断）

---

## 13. 是否满足 V1 发布条件

### **PASS**

阻断项均已关闭：

- 正常样本无 HIGH
- Case A/B 证据与 TShark 一致
- 控制面/数据面重传已分类，无纯 SYN ACK_STALLED 回归
- 多输出文件关键字段一致
- 报告无未经证据支持的确定性设备根因措辞
- Windows `run.bat` / `doctor` 可用

**V1 可作为单侧 PCAP 离线分析工具稳定使用。**  
按验收要求：不继续自行增加第二阶段功能。
