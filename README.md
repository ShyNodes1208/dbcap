# dbcap — DBCAP Offline Analyzer

应用服务器 ↔ 数据库服务器之间的 **TCP 抓包离线故障分析**工具。

当前重点场景是达梦，但端口与类型均可配置，不写死为 5236。

## 定位

自动化 DBA 在 Wireshark 中人工完成的：

- TCP 会话识别（优先 `tcp.stream`）
- 三次握手 / SEQ·ACK·LEN / 持续重传
- ACK 是否推进 / RST 分类 / Window
- 抓包完整性 / Payload 证据 / Wireshark 复核过滤器

**不是**通用网络平台、Wireshark 替代品、实时监控或 AWR/性能平台。

## 环境要求

- Python 3.10+
- Wireshark（含 TShark）
- Windows 离线可用（见下方）

## 安装

```bash
pip install -r requirements.txt
# 确认 tshark
tshark --version
```

若 tshark 不在 PATH，可设置：

```text
DBCAP_TSHARK=C:\Program Files\Wireshark\tshark.exe
```

## 快速开始

```bash
# 在项目根目录（推荐现场用法）
run.bat capture.pcap 5236

# 或显式 Python
set PYTHONPATH=%CD%
python -m dbcap -f capture.pcap -d dameng -o .\output
python -m dbcap doctor
```

## 输出

```text
output/
├── report.md
├── evidence.csv
├── flows.csv
├── anomalies.json
├── dbcap_report_*.json
└── payload/
    └── stream_<id>/
        ├── client_seq_<seq>_len_<len>.bin
        └── server_seq_<seq>_len_<len>.bin
```

终端仍输出彩色摘要（依赖 rich）。

## 第一阶段能力

| 能力 | 说明 |
|------|------|
| tcp.stream 会话 | 同 stream 双向同一会话 |
| 会话汇总 | stream / 端点 / 时长 / 包数 / RST / FIN / ZW 等 |
| 握手延迟 | `synack - syn`；缺 SYN → **N/A**（禁止 timestamp-0） |
| Expected ACK | `seq + len (+1 SYN/FIN)` |
| 持续重传 | Segment Key = (stream, dir, seq, len, payload SHA256) |
| ACK_STALLED | 累计 ACK 未推进到 Expected ACK |
| RST 分类 | AFTER_SYN / DURING_DATA / ACK_TO_RST / AFTER_FIN |
| 抓包截断 | `cap_len < frame.len` → PACKET_TRUNCATED |
| Frame 证据 | Frame / Seq / Ack / Len / Expected ACK / Filter |

证据原则：区分 **事实 / 推断 / 未知**；不编造交换机/防火墙根因。

## 严重级别

`INFO` / `WARNING` / `HIGH`（阈值集中在 `thresholds.py` / `--thresholds`）

## 测试

```bash
set PYTHONPATH=%CD%
python -m pytest tests -v
```

## 离线部署（Windows）

```powershell
.\install_offline.ps1
python -m dbcap -f capture.pcap -d dameng -o .\output
```

仓库亦附带 `python-3.12.9-embed-amd64.zip` 与 `get-pip.py` 供完全离线环境使用。本轮优先保证分析正确性，EXE 打包后续再做。

## 项目结构

```text
dbcap/
├── cli.py
├── capture.py          # TShark 字段提取
├── session.py          # tcp.stream 会话
├── handshake.py
├── seq_ack.py
├── retransmission.py
├── ack_analysis.py
├── rst_analysis.py
├── window_analysis.py
├── capture_quality.py
├── payload.py
├── analyzer.py
├── report.py
├── models.py
├── thresholds.py
└── protocols/          # 可选 Decoder 接口（本阶段不逆向 DM）
tests/
output/
DBCAP_OLD_PROJECT_AUDIT.md
DBCAP_DEVELOPMENT_RESULT.md
```

## 退出码

| 码 | 含义 |
|----|------|
| 0 | INFO / 无高危 |
| 1 | WARNING |
| 2 | HIGH |
| 3 | 运行错误 |

## 许可证

DBCAP 采用 **Apache License 2.0**。

```text
Copyright (C) 2026 ShyNodes1208

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

全文见 `LICENSE`，第三方组件归属见 `NOTICE` 与 `LICENSES.txt`。

除非单个文件头部另有声明，`dbcap/` 下全部源文件均按上述 Apache-2.0 授权。

### 关于 Wireshark / TShark

DBCAP **不再随包分发** Wireshark/TShark。程序通过子进程调用使用者自行提供的
`tshark.exe`，不链接、不嵌入、不再分发 Wireshark 代码，因此不承担 Wireshark
GPL 的源码与通告义务。

TShark 的获取方式见下方「离线部署（Windows）」。

### 第三方组件

| 组件 | 许可证 | 许可证文本位置 |
|------|--------|----------------|
| CPython 3.12.9 | PSF-2.0 | `runtime/python/LICENSE.txt` |
| OpenSSL | Apache-2.0 | `licenses/Apache-2.0.txt` |
| libffi | MIT | `licenses/libffi-MIT.txt` |
| rich / markdown-it-py / mdurl | MIT | 各自 `.dist-info/licenses/` |
| Pygments | BSD-2-Clause | `pygments-2.20.0.dist-info/licenses/LICENSE` |
| SQLite | Public Domain | 无需通告 |
| Microsoft VC++ Runtime | Microsoft 可再分发 | 未修改的微软原始二进制 |
