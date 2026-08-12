# 贡献说明

## 提交前检查

提交代码前，在仓库根目录执行以下命令：

```bash
nix develop -c cargo fmt --check
nix develop -c cargo test --locked
nix develop -c cargo clippy --locked --all-targets -- -D warnings
```

没有 Nix 时，使用 `rust-toolchain.toml` 指定的 Rust 工具链执行等价命令。涉及 Debian 包时，还应执行：

```bash
nix develop .#static -c scripts/build-deb.sh
```

涉及转发、链路切换、MTU、FEC、队列或 mesh 行为时，在具备 Docker、`/dev/net/tun` 和特权网络命名空间的 Linux 主机上执行：

```bash
tests/netns/run-all.sh
```

## 变更要求

- Rust 代码遵循 `rustfmt` 的输出；Clippy 警告按错误处理。
- 配置字段、控制接口、wire format 和 Presence 格式的变更，应同步更新 `config/example.toml`、README 与 `docs/`。
- 文档使用简体中文，说明前提、命令、预期结果和回滚方式；不使用营销性描述。
- 不提交密钥、身份文件、已密封的本地配置、构建产物或测试状态目录。
- 每个提交只处理一个可审查的主题。提交标题使用 `type: 简短说明`，例如 `docs: 补充静态拓扑配置示例`。

## 合并请求内容

合并请求说明应包含：

1. 变更目的和影响范围；
2. 配置或协议兼容性影响；
3. 已执行的检查及其结果；
4. 对网络行为有影响时，使用的测试拓扑、关键观测值和回滚步骤。
