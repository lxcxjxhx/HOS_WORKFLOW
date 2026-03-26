# HOS-LS 安全检测工具

## 项目简介

HOS-LS 安全检测工具，用于扫描AI工具中的安全问题，包括代码安全、权限安全、网络安全、依赖安全和配置安全。

## 目录结构

```
HOS-LS/
├── src/             # 核心代码
│   ├── main.py            # 主入口文件
│   ├── security_scanner.py # 安全扫描模块
│   └── report_generator.py # 报告生成模块
├── templates/       # 定制化输出模板
│   ├── html_template.html # HTML报告模板
│   └── md_template.md     # MD报告模板
├── tests/           # 测试目录
│   ├── test-ai-tool/   # 测试工具
├── reports/         # 报告输出目录
├── docs/            # 文档目录
├── requirements.txt # 依赖文件
├── setup.py         # 安装配置
├── hos-ls.sh        # Linux脚本
└── README.md        # 使用指南
```

## 安装方法

1. 克隆项目到本地：

```bash
git clone <项目地址>
cd HOS-LS
```

2. 安装依赖：

```bash
pip install -r requirements.txt
```

3. 安装工具：

```bash
pip install -e .
```

## 使用方法

### 基本用法

```bash
hos-ls <目标路径>
```

### 命令行参数

- `-o, --output`：报告输出格式，支持 html、docx、md（默认：html）
- `-d, --output-dir`：报告输出目录（默认：reports）
- `-v, --verbose`：显示详细输出
- `--version`：显示版本信息

### 示例

1. 扫描当前目录并生成 HTML 报告：

```bash
hos-ls .
```

2. 扫描特定目录并生成 MD 报告：

```bash
hos-ls /path/to/ai-tool -o md
```

3. 扫描特定目录并指定输出目录：

```bash
hos-ls /path/to/ai-tool -d /path/to/output
```

## 检测内容

1. **代码安全**：检测硬编码的敏感信息（API密钥、密码、token等）、潜在的后门代码、网络访问代码
2. **权限安全**：检测文件执行权限
3. **网络安全**：检测硬编码的IP地址和端口号
4. **依赖安全**：检测依赖包
5. **配置安全**：检测配置文件中的敏感信息

## 报告格式

工具支持生成三种格式的报告：

1. **HTML**：交互式网页报告，包含详细的安全问题列表
2. **DOCX**：Word文档报告，适合正式文档
3. **MD**：Markdown格式报告，适合GitHub等平台

## 定制化模板

可以在 `templates` 目录下修改或添加模板文件，以定制报告的格式和样式：

- `html_template.html`：HTML报告模板
- `md_template.md`：MD报告模板

## 测试

工具包含测试用例，位于 `tests/test-ai-tool` 目录中。可以使用以下命令运行测试：

```bash
hos-ls tests/test-ai-tool
```

## 版本信息

当前版本：v1.0.0
