# 公开授权节点聚合器 (Public Authorized Node Aggregator)

一个轻量、高效且安全的公开授权节点聚合与格式转换工具。能够自动识别多种订阅与协议格式，进行统一结构转换、合法性校验、指纹去重，并生成标准 Clash 订阅配置文件（`output/sub.yaml`）。

---

## 目录结构

```text
project/
├── aggregator.py                 # 核心聚合与解析脚本
├── sources.txt                   # 数据源配置文件（每行一个 URL 或测试文件路径）
├── requirements.txt              # Python 依赖清单
├── README.md                     # 项目使用与设计文档
├── output/                       # 输出目录
│   └── sub.yaml                  # 最终聚合生成的 Clash 配置文件
├── tests/                        # 单元测试与测试数据
│   ├── test_parser.py            # 完整单元测试集
│   └── mock_sources/             # 预置本地测试数据源（供开箱体验）
│       ├── source1_clash.yaml    # Clash YAML 格式测试源
│       ├── source2_uris.txt      # 原生 URI 格式测试源
│       └── source3_b64.txt       # Base64 编码测试源
└── .github/
    └── workflows/
        └── update.yml            # GitHub Actions 自动化工作流（Phase 2）
```

---

## 核心设计与数据流

整个聚合流程分为 6 个清晰解耦的模块阶段：

```text
sources.txt 
   ↓ (1. download_sources) 带有超时限制与异常隔离的下载机制
原始数据
   ↓ (2. parse_source) 自动识别 Clash YAML / JSON / Base64 / URI 格式
协议节点数据 (SS / VMess / VLESS / Trojan)
   ↓ (3. normalize_node) 转换为统一字典数据结构
内部规范节点
   ↓ (4. validate_node) 过滤非法端口、空服务器及缺失凭据的脏数据
合法节点
   ↓ (5. deduplicate_nodes) SHA-256 结构指纹去重，保留节点并合并 sources 来源列表
去重后节点
   ↓ (6. generate_clash_yaml) 处理同名冲突（自动增加 -01, -02 后缀）并导出标准 Clash 配置
output/sub.yaml
```

---

## 支持格式与协议

- **输入订阅格式**：
  - Clash YAML 格式订阅
  - JSON 格式订阅（Clash 格式 / V2Ray outbounds 格式）
  - Base64 编码订阅（自动填充 padding，支持 URL-safe 模式）
  - 纯文本 URI 列表
- **支持节点协议**：
  - **Shadowsocks (ss)**：支持 SIP002 标准格式与旧版 Legacy 格式
  - **VMess (vmess)**：标准 Base64 JSON 格式，支持 TCP/WS/gRPC/H2 及 TLS
  - **VLESS (vless)**：标准 URI 格式，支持 WS/gRPC 及 TLS/Reality（含 public-key 与 short-id）
  - **Trojan (trojan)**：标准 URI 格式，支持 SNI、WS/gRPC 与 TLS

---

## 安全与合规边界

本项目严格遵循合法授权与最小权限原则：
1. **仅处理显式声明的数据源**：只读取并解析 `sources.txt` 中用户自行填写的链接。
2. **严禁主动网络扫描**：不包含任何随机扫描互联网 IP、开放端口或网络嗅探的逻辑。
3. **严禁越权破解**：不绕过目标服务器的访问控制、验证码或防盗链限制。
4. **无凭据泄露风险**：代码与测试用例中不硬编码真实敏感密码、Token 或 GitHub 用户名。

---

## 快速上手指南（本地运行）

### 1. 准备环境
确保本地已安装 Python 3.8 或更高版本。进入 `project` 目录：
```bash
cd project
```

### 2. 安装依赖
使用 `pip` 安装运行所需的依赖项（主要是 `requests` 与 `PyYAML`）：
```bash
pip install -r requirements.txt
```

### 3. 配置数据源（sources.txt）
编辑 `sources.txt`，每一行填入一个公开授权的订阅 URL。

> **提示**：仓库默认内置了 3 个本地测试源（位于 `tests/mock_sources/`），无需联网即可直接进行本地测试！

如果添加您的远程公开授权订阅，请追加到文件中：
```text
https://example.com/my-authorized-nodes.yaml
https://example.com/my-subscription.txt
```

### 4. 执行聚合程序
运行以下命令：
```bash
python aggregator.py
```
控制台将输出详细的聚合执行日志，包括：
- 成功读取的数据源数量
- 每个源的下载字节数与格式识别情况
- 各源解析出的有效节点数量
- 指纹去重结果（合并相同节点并保留多数据源来源记录）
- 最终生成的 `output/sub.yaml` 代理数量

### 5. 查看聚合结果
生成的 Clash 订阅位于 `output/sub.yaml`，可在 Clash / Clash Verge / Clash Meta / Mihomo 等客户端中直接导入测试。

---

## 运行单元测试

项目配备了完善的单元测试套件，覆盖了文件读取、网络异常容错、各类 URI 解析（SS/VMess/VLESS Reality/Trojan）、数据验证、指纹去重和 Clash YAML 格式导出。

使用 Python 内置 unittest 运行：
```bash
python -m unittest discover -s tests -v
```
或者使用 pytest（如果已安装）：
```bash
pytest -v
```

---

## 后续路线图 (Roadmap)

- **Phase 1（当前已完成）**：核心下载、多格式识别、协议解析、统一标准化、指纹去重与 Clash YAML 生成。
- **Phase 2（待开启）**：接入 GitHub Actions 定时（每 6 小时）和手动触发更新，仅在内容变化时自动 commit & push。
- **Phase 3+**：
  - 节点连通性与延迟测试
  - 节点质量与稳定性评分
  - 自动过滤失效节点
  - 多格式输出（如 Sing-box、V2Ray、Surge 等）
  - 生成漂亮的 Web 状态与节点统计页面
