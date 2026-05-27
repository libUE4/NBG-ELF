# NBG-ELF

NBG-ELF 是面向自有商业软件的 Linux ARM64 ELF 字符串加密与运行时保护工具。项目重点是保护合法拥有和分发的 ELF 程序，提供字符串加密、运行时解密 stub 注入、按需解密调用点补丁、反调试/反 Frida 探测、manifest 审计和保护报告。

## 主要能力

- 字符串扫描与加密：支持 `.rodata`，可选 `.data`。
- ARM64 运行时 stub 注入：入口点预 main 解密，运行时表加密与回封。
- 保护预设：`safe`、`balanced`、`aggressive`。
- JSON 配置：通过 `-config protection.json` 覆盖保护策略。
- 按需解密：`aggressive` 预设启用保守 lazy callsite 补丁。
- 审计校验：输出结构、sha256、明文残留、lazy dispatch 表和 callsite 补丁校验。

## 快速使用

```bash
go test ./...
go run ./cmd/nbg-elf --help
go run ./cmd/nbg-elf inspect -min 6 build/NBG.sh
go run ./cmd/nbg-elf encrypt -preset balanced -report build/NBG.sh
go run ./cmd/nbg-elf encrypt -preset aggressive -o /tmp/NBG.sh.vmp -manifest /tmp/NBG.sh.manifest.json build/NBG.sh
go run ./cmd/nbg-elf verify /tmp/NBG.sh.manifest.json
```

## 仓库结构

- `cmd/nbg-elf/`：CLI 入口和命令处理。
- `internal/elfstr/`：ELF 扫描、加密、manifest、runtime 注入、callsite 补丁逻辑。
- `internal/assets/`：嵌入的 ARM64 runtime stub 二进制。
- `stub/arm64/`：runtime stub 汇编源码和链接脚本。
- `build/`：本地构建和样本产物，默认不提交。

## 安全说明

请只用于你拥有授权的软件。不要提交私有 ELF、客户样本、水印、manifest 明细或其他敏感产物。`manifest-detail` 会记录字符串偏移和哈希，仅建议诊断时启用。
