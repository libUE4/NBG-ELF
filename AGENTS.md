# 仓库指南

## 项目结构与模块组织

这是 Go 1.22 CLI 模块，模块名为 `nbg-elf`。入口在 `cmd/nbg-elf/main.go`，提供 `inspect`、`encrypt`、`manifest`、`verify` 等命令。核心 ELF 扫描、字符串加密、manifest、运行时注入和 AArch64 调用点逻辑位于 `internal/elfstr/`。嵌入的 runtime 字节和 Go 包装位于 `internal/assets/`。ARM64 runtime stub 汇编源码和链接脚本位于 `stub/arm64/`。`build/` 是本地构建和样本输出目录，除非明确刷新产物，否则不要提交。

测试与被测代码放在同一包内，使用 Go `_test.go` 文件，例如 `cmd/nbg-elf/main_test.go` 和 `internal/elfstr/elfstr_test.go`。

## 构建、测试与开发命令

- `go test ./...`：运行 CLI 和内部包的全部单元测试。
- `go test ./internal/elfstr -run TestName`：迭代时运行指定包的单个测试。
- `go build -o build/nbg-elf ./cmd/nbg-elf`：构建 CLI 到 `build/`。
- `go run ./cmd/nbg-elf --help`：不生成二进制，直接运行本地 CLI。
- `go run ./cmd/nbg-elf encrypt -preset aggressive -report <input.elf>`：只输出保护计划，不写文件。

## 代码风格与命名约定

使用标准 Go 格式，提交前运行 `gofmt`。缩进使用 tab。包名保持短小、小写。只有跨包边界需要的符号才导出；`internal/elfstr` 内优先使用未导出 helper。测试名使用描述性形式，例如 `TestResolveManifestOutputPath`。命令行 flag 保持小写和连字符风格，例如 `-manifest-detail`、`-lazy-callsite-limit`。

## 测试要求

使用 Go 内置 `testing` 包。修改 manifest、输出结构、runtime 注入、AArch64 callsite 或配置解析时，必须增加聚焦测试。文件系统测试优先使用 `t.TempDir()`。修改保护输出后至少运行 `go test ./...`，并用 `/tmp` 输出路径做一次样本 `encrypt` 与 `verify`，避免污染仓库。

## 提交与 Pull Request 指南

提交信息使用简短祈使句，例如 `Add manifest validation test` 或 `Validate lazy dispatch metadata`。PR 需要说明行为变化、列出验证命令、标明是否触碰 `build/` 产物，并解释对既有 manifest 或已保护 ELF 的兼容影响。CLI 输出变化应附关键终端片段。

## 安全与配置提示

不要提交私有 ELF、客户样本、水印、密钥或敏感 manifest。`manifest-detail` 会暴露字符串偏移和哈希，仅在诊断时使用。保护器目标是合法软件加固，不实现持久化、破坏性行为或恶意规避能力。
