# Phase 0 runtime spike：历史复现源码

该目录保留 2026-08-21 WASM 策略 runtime 选型的最小 guest、host、WIT 和锁文件。原始结论和测量数字在[历史报告](../../docs/archive/wasm-policy/WASM策略Phase0-runtime-spike.md)；当前生产策略架构见[策略运行时架构](../../docs/策略运行时架构.md)。

## 保留与清理边界

保留的内容：

- `guest/`：最小 `wasm32-unknown-unknown` component guest；
- `host/`：Wasmtime 43 host 与 `pulley` / `cranelift` 测量入口；
- `wit/`：Phase 0 WIT；
- `nix-wasm-shell/flake.nix` 与 `flake.lock`、两个 Cargo lockfile：锁定当时的工具链与依赖；
- `run.sh`：从源码重新生成 component、AOT `.cwasm` 和文本测量输出。

不保留的内容：guest `.wasm`、`.cwasm`、host 二进制、构建日志和单次结果文本。它们是可再生成的本地证据，统一写入忽略的 `out/`（或环境变量 `OUT` 指定的位置）。

## 复现

从仓库根目录运行：

```bash
nix develop ./tools/phase0-spike/nix-wasm-shell -c ./tools/phase0-spike/run.sh
```

默认输出为 `tools/phase0-spike/out/`。将生成物放在空间更大的本地目录：

```bash
OUT=/var/tmp/ironet-phase0 \
  nix develop ./tools/phase0-spike/nix-wasm-shell -c ./tools/phase0-spike/run.sh
```

可用 `ITERS` 和 `INPUT_BYTES` 调整调用次数与输入大小。脚本使用 `--locked`，但微秒级数字仍会受机器、内核、CPU 频率和缓存状态影响；将输出与历史报告的趋势比较，而非要求完全相同的绝对值。
