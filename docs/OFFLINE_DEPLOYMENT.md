# DBCAP 离线部署说明（Windows 10 x64）

## 1. 发布包形态

推荐：**目录式离线包**（本版本交付）

```text
dbcap-v1.0.0-windows-x64.zip
```

解压后结构（摘要）：

```text
dbcap-v1.0.0/
  run.bat
  doctor.bat
  README.txt
  VERSION
  LICENSES.txt
  app/dbcap/
  runtime/python/
  tools/tshark/
  config/thresholds.json
  input/
  output/
  docs/
```

本轮 **不** 优先提供单文件 `dbcap.exe`。

## 2. 部署步骤

1. 在联网构建机生成发布包（开发侧执行 `scripts\build_release.ps1`）
2. 用 U 盘 / 内网文件柜拷贝 zip 到目标机
3. 解压到任意目录（支持空格、中文路径）
4. 运行 `doctor.bat`
5. 看到 `Overall: PASS` 后即可分析 PCAP

目标机 **不需要**：

- 安装 Python
- 执行 pip install
- 手工设置 PYTHONPATH
- 理解包结构

## 3. TShark 两种模式

### 模式 A（推荐便利性）：包内置 TShark

`tools\tshark\tshark.exe` 存在。  
`doctor.bat` 会显示 Mode: bundled。

注意：Wireshark/TShark 为 **GPL**。组织若不能再分发 GPL 二进制，请改用模式 B。详见 `LICENSES.txt`。

### 模式 B（推荐合规性）：使用现场 Wireshark

1. 在目标机安装官方 Wireshark，勾选 TShark
2. 确保 `tshark.exe` 在 PATH，或留在默认安装目录
3. 发布包可不带 `tools\tshark\` 二进制
4. `doctor.bat` 显示系统 TShark 路径即可

**DBCAP 推荐现场默认策略：**

- 对外交付若需最省事：Mode A + 完整许可证文本
- 对合规敏感环境：Mode B

## 4. 不包含 Npcap / 实时抓包

DBCAP V1 只离线读 PCAP，不负责抓包。  
发布包刻意不依赖 dumpcap/Npc 实时捕获链路。

## 5. 构建机要求（开发侧）

- Windows x64
- 仓库内 `python-3.12.9-embed-amd64.zip`
- 仓库内 `vendor\*.whl`（rich 及其依赖）
- 可选：本机已安装 Wireshark（用于 Mode A 复制）

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_release.ps1
```

仅 Mode B：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_release.ps1 -SkipTShark
```

## 6. 升级

替换整个 `dbcap-v1.x.x` 目录即可。  
不要混用旧 `runtime\python` 与新 `app`。

## 7. 卸载

删除解压目录即可，无系统服务、无强制注册表依赖。
