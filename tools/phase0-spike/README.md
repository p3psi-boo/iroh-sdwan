# Phase 0 runtime spike 源码存档

来源：2026-08-21 WASM 策略模块化 Phase 0 spike（原 Claude 会话 scratchpad）。
报告与结论见 `docs/WASM策略Phase0-runtime-spike.md`，此处仅保留源码/脚本/结果以便复现。

- `host/`：wasmtime 宿主基准（构建方式见 `build-hosts.sh` / `build-hosts-2.sh`，日志同名 `.log`）
- `guest/`：wasm32-unknown-unknown guest 组件源码
- `wit/policy.wit`：spike 用 WIT（正式草案在 `crates/ironet-policy-abi/wit/`）
- `nix-wasm-shell/`：带 wasm32 rust-std + wasm-tools + wit-bindgen 的独立 flake（复用仓库 flake.lock）
- `results/`：延迟/体积实测输出与预编译 `.cwasm`

已剔除构建产物（`bin/`、`bin-warm/`、`baseline-empty/`、各 `target/`）。
