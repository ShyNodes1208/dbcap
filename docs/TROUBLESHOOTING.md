# DBCAP 故障排查（V1.0.0）

## TShark 找不到

**现象**：`[ERROR] 未找到 TShark` 或 doctor 显示 TShark: FAIL

**可能原因**：
- Mode A 包未带 `tools\tshark\tshark.exe`
- Mode B 未安装 Wireshark / 未勾选 TShark
- PATH 未包含 Wireshark

**检查**：
1. 运行 `doctor.bat`，看 TShark Path
2. 确认 `tools\tshark\tshark.exe` 或 `C:\Program Files\Wireshark\tshark.exe`

**处理**：
- 复制合法 TShark 运行时到 `tools\tshark\`
- 或安装 Wireshark（TShark 组件）

---

## Python Runtime 找不到

**现象**：`未找到内置 Python Runtime`

**可能原因**：zip 解压不完整；杀软隔离

**检查**：`runtime\python\python.exe` 是否存在

**处理**：重新解压完整发布包；加入杀软白名单后重试

---

## PCAP 文件不存在

**现象**：`PCAP 文件不存在`

**可能原因**：路径错误；相对路径基准不对；中文/空格未加引号

**检查**：
```bat
dir "D:\抓包\案例 01.pcap"
```

**处理**：
```bat
run.bat "D:\抓包\案例 01.pcap" 5236
```
或将文件放到 `input\` 后：
```bat
run.bat input\case01.pcap 5236
```

---

## PCAP 损坏 / TShark 返回异常

**现象**：TShark 报错、无会话、异常退出

**可能原因**：文件截断下载；不是 pcap/pcapng；权限不足

**检查**：用 Wireshark 能否打开同一文件

**处理**：重新导出抓包；确认扩展名；换到本地磁盘再分析

---

## 输出目录不可写

**现象**：无法创建输出目录 / 写入失败

**可能原因**：只读介质；权限；磁盘满

**检查**：`doctor.bat` 的 output writable / disk free

**处理**：换到可写目录：
```bat
run.bat case.pcap 5236 D:\result\case01
```

---

## 路径含中文 / 空格

**现象**：参数被拆开；找不到文件

**处理**：路径加引号；优先使用 `run.bat`（已按脚本目录定位运行时）

---

## 磁盘空间不足

**现象**：doctor 报 disk space FAIL；写入中断

**处理**：清理磁盘；换输出盘；大 PCAP 先评估输出体积

---

## report 没有异常

**现象**：Overall INFO，No anomalies

**可能原因**：确实正常；端口过滤不对；抓包时段未覆盖故障

**检查**：
- 端口是否正确（第二个参数）
- Wireshark 中 `tcp.port == <port>` 是否有包
- 是否看错输出目录

---

## PCAP 被 snaplen 截断 / Payload 不完整

**现象**：`PACKET_TRUNCATED`；payload 很短

**原因**：抓包 snaplen 过小（如 128）

**处理**：用更大 snaplen 重抓；不要根据截断 payload 猜测 SQL

---

## doctor Overall: FAIL

按失败项逐条处理，优先保证：

1. Python Runtime PASS
2. DBCAP Import PASS
3. TShark PASS
4. output writable PASS
