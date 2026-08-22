# WASM 策略模块化：实施交接记录

记录时间：2026-08-21。对应计划：`docs/WASM策略模块化实施计划.md`（已按评审修订过一轮）。

本记录写于第二波 agent 仍在运行时，"进行中"小节的内容以各文件落地后的测试结果为准。**所有改动均未 git commit**，工作区本来就有大量未提交改动（iroh-v2/noq 子 crate、V1 清理等），请勿把本次改动与其混为一次提交。

## 0. 环境备忘

- **toolchain 已升级到 Rust 1.98.0**（第三波完成）：`flake.nix`（`rust-bin.stable."1.98.0"`，targets 含 `wasm32-unknown-unknown`，devShell 加 `wasm-tools`/`wit-bindgen`/`bc`/`file`）、`flake.lock`（只更新 `rust-overlay`）、`rust-toolchain.toml`、根与各 crate `rust-version = "1.98"`、`.forgejo`/`.github` CI 的 toolchain 版本、`docs/开发与测试.md`。新 clippy lint 只出现 3 处（`fec.rs`/`repair.rs`/`routing.rs` 的 `chunks_exact`→`as_chunks`），已修。`cargo check -p ironet-policy-abi --target wasm32-unknown-unknown` 通过。
- 统一用 `nix develop -c cargo ...` 运行（首次进入要从 static.rust-lang.org 下 1.98 tarball，可能很慢）。旧的 nix store 1.91/1.94 路径不再适用；若仍用它们需加 `--ignore-rust-version`。
- **磁盘**：`/home` 与 `/nix` 同分区，曾被打满触发 ENOSPC；`target/` 约 187 GB，其中 `target/debug/deps` ~60 GB、`incremental` ~21 GB 是可再生 cargo 缓存，其余是实验数据目录（netns/profile 结果），**不要整体 `cargo clean` 以外的方式误删**。已清理 2 天以上的 incremental；当前约 22 GB 可用。
- 汇总验证命令（全部应通过）：

```bash
cargo test --lib protocol::v2::policy
cargo test --lib protocol::v2::replay
cargo test --lib protocol::v2::tuning
cargo test --lib config
cargo test --test autotune_golden
cargo test -p ironet-policy-abi
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
python3 scripts/check-doc-links.py
```

## 1. 已完成

### 1.1 计划文档评审修订（已写入计划）

三层 backend（`native`/`builtin`/外部 `.wasm`）、宿主计算 utility、每 peer 一次 `decide`、WIT TLV 扩展袋、状态键 `(policy_id, state_schema, peer_id)` + 定时落盘、Ed25519 + 末尾签名段 + 顶层 only + 防回滚 + trust store 进 seal、Pulley vs Cranelift 评估、单源两目标 `ironet-policy-core`、`builtin.wasm` 提交仓库 + 脚本复现 + CI digest 校验、工期/风险/DoD 同步。

### 1.2 Phase 0：逐样本 golden（完成，已测试）

- `src/protocol/v2/replay.rs`：新增 `replay_with_golden()`（`replay()` 委托给它，签名与输出不变）、`ReplayGoldenV2`/`ReplaySampleTraceV2` 等 serde 类型、`REPLAY_GOLDEN_SCHEMA_V2 = 1`。
- `examples/autotune_replay.rs`：新增 `--golden-output PATH`。
- `tests/fixtures/autotune-golden-v1.json`：8 样本，逐样本含输入遥测（43 字段）、utility（f64 `to_bits`）、`baseline`/`candidate`/`effective` 完整 `TuneDecisionV2`、learner trace、memory digest 与 per-context memory。头部含再生命令、policy digest、objective、seed、learner_mode。
- `tests/autotune_golden.rs`：逐样本断言 + 同 seed/输入两次运行一致。
- 注意：replay 以 `LearnerModeV2::Shadow` 运行，`effective.bbr` 等于 baseline，`candidate` 才是 learner 的反事实；若 Phase 2 需要 On 模式 trace，需给 `replay_with_golden` 加 mode 参数。零权重 utility 分项存的是 `-0.0` 的 bits，ABI 文档要写明零值符号约定。

### 1.3 ABI V1 宿主侧类型（完成，已测试；正在被抽成独立 crate，见 2.2）

- `src/protocol/v2/policy/api.rs`（2671 行，含约 560 行单测，18 测试通过）。`policy.rs` 顶部加了 `pub mod api;`。
- 类型：`PolicyInputV1`、`PolicyTelemetryV1`（41 字段，与 `PathTelemetryV2` 往返无损）、`HostUtilityV1`、`HostLimitsV1::from_bounds`、`HostCapabilitiesV1`、`EgressAllocationViewV1`、`PolicyExtensionV1`、`CandidateActionV1`（8 个 Option 子域 + `apply_over` + `validate`）、`BbrCandidateV1`（5.4 全部 20 个 tunable）、`EffectiveActionV1`（与 `TuneDecisionV2` 往返无损）、`ClampReportV1`/`ClampEntryV1`/`ClampFieldV1`(48)/`ClampReasonV1`(17)、`PolicyDiagnosticsV1`、`PolicyOutputV1`、`PolicyIdentityV1`、`PolicyFaultV1`(11)、`PolicyHealthV1`、`trait PolicyBackend: Send { identity(&self); decide(&mut self, &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> }`。
- 决定：`decide` 取 `&mut self`（Wasm backend 持 Store，需重置 fuel/deadline；同一实例不可并发），state 在 `input.state` 内，不再单独传。
- 已知有损/未对齐：`Bbr3ProposalV2` 只有 5 字段，`BbrEffectiveV1::from_proposal` 其余 15 个按 preset 表填充，**runtime 的 adaptive cwnd floor 未纳入**（接管 `apply_bbr3_proposal` 时补）；`TuneDecisionV2` 不携带的字段（bulk admission window、retention、wait policy、responsibility、datagram admission、producer window、reassembly budget、active train budget、egress、hints）在 effective 中为 0/HostDefault；`local-rx goodput` 在 `PathTelemetryV2` 中不存在，未发明；`extensions` 在 `apply_over` 中不合并。

### 1.4 配置层（完成，已测试）

- `src/config.rs`：`autotune.policy` 接受 `native`/`builtin`/绝对路径；新增 `AutotuneWasmConfig { require_signature=true, maximum_module_bytes=8 MiB, maximum_memory_bytes=8 MiB, maximum_state_bytes=64 KiB, deadline_millis=10, state_flush_interval_secs=60, signers: Vec<AutotuneSignerConfig{signer_id, public_key: "ed25519:<hex|base32>", minimum_policy_version, expires_at}>, digest_pins: Vec<"blake3:<64hex>"> }`，挂在 `AutotuneConfig.wasm`；校验规则 10 条（见 `docs/配置参考.md` 的 `[autotune.wasm]` 小节）；`AutotuneConfig::uses_wasm_artifact()`。22 个 config 测试通过。
- seal 是对整个配置文件的 BLAKE3，`autotune.wasm` 自动纳入。
- `config/example.toml`、`docs/配置参考.md` 已更新。
- `src/v2_runtime.rs`：仅新增本地 `fn load_autotune_policy`（`native` 暂时加载内置 JSON artifact，`policy_source="native"`），移除了 `policy::load_or_builtin as load_autotune_policy` 的 use 别名。**已知跟进**：`tuner_loop` 约 6365 行的 5 秒热重载判断仍是 `policy != "builtin"`，`native` 会触发一次无害的 dedup warn；接线 `tuner_loop` 时改为同时排除 `native`。

### 1.5 Phase 0 runtime spike（完成）

报告：`docs/WASM策略Phase0-runtime-spike.md`。spike 源码已存档进仓库 `tools/phase0-spike/`（2026-08-21，已剔除构建产物）。

- 工具链：裸 shell 无 cargo；仓库 `nix develop` 有 Rust 1.91 但**无 wasm32 rust-std**。用复用仓库 flake.lock 的独立 flake（rust-overlay `targets += wasm32-unknown-unknown` + `pkgs.wasm-tools` 1.254 + `pkgs.wit-bindgen` 0.60）可用，报告给出 `flake.nix` diff 建议（未改）。网络正常。
- wasmtime：48.0.0 需 Rust 1.95；Rust 1.91 下最新可用 **43.0.2**（实测），36.x 为 LTS。**已决策（2026-08-21，用户）**：升 toolchain ≥1.95，用 wasmtime 48 LTS。
- 体积（stripped，仓库 profile）：`pulley` 无编译器 +1.10 MiB；`cranelift` +11.23 MiB；`cranelift,pulley` +11.29 MiB。
- 延迟：Cranelift JIT p99 3.5–4.1 µs；Pulley p99 72–164 µs（64 KiB 极限输入 1.93 ms）。fuel 7,379/次（1 KiB），四种执行方式输出逐位相同；Pulley ≈ 8–10 ns/fuel，10 ms ≈ 1.0–1.2 M fuel。
- **对计划 7.1 的修正**：Pulley 字节码由 Cranelift 编译，不开 `cranelift` feature 就只能加载预编译 `.cwasm`。"Pulley = 小数 MB 增量"只对 AOT-only 成立。**已决策（2026-08-21，用户）**：默认 `features = ["runtime","component-model","std","cranelift","pulley"]` + `Config::target("pulley64")`（接受 +~11 MiB，保留无 JIT 页、确定性、热路径无编译器优点）；AOT-only（builtin 预编译 pulley64 .cwasm、第三方由 `ironet` CLI 预编译）列为体积优化备选。
- API 名称清单（`wasm_relaxed_simd`、`cranelift_nan_canonicalization`（对 Pulley 同样生效）、`consume_fuel`、`epoch_interruption`、`StoreLimitsBuilder`、`memory_reservation`、`max_wasm_stack`）见报告第 6 节；`wasm_threads/wasm_gc` 在不开对应 feature 时方法不存在。

## 2. 第二波 agent 结果（2026-08-21 07:30 核实：三个 agent 因 Claude 限额中断，但磁盘状态已逐项验证）

验证结果（rust 1.94.1）：`cargo check --workspace --all-targets`、`cargo clippy --workspace --all-targets -- -D warnings`、policy 30 / replay 3 / tuning 30 / config 24 / autotune_golden 2 测试、`check-doc-links.py` 全部通过；`cargo fmt` 的两处残留（main.rs）已修正。

### 2.2 抽取 `crates/ironet-policy-abi` + WIT 草案（已完成，已验证）

- 目标：把 api.rs 的纯类型/常量/trait/`apply_over`/`validate` 移到 workspace 成员 `crates/ironet-policy-abi`（只依赖 serde，可在 wasm32-unknown-unknown 上编译）；`src/protocol/v2/policy/api.rs` 变为 `pub use ironet_policy_abi::*;` + 宿主适配（因孤儿规则改为扩展 trait/自由函数）；对外路径 `crate::protocol::v2::policy::api::*` 保持可用；起草 `crates/ironet-policy-abi/wit/ironet-policy.wit`（package `ironet:policy@1.0.0`，world `policy`，`decide`）并尽量用 wasm-tools 校验；加 Rust↔WIT 字段名一致性测试。
- 落地状态：`crates/ironet-policy-abi/`（src 8 个模块 + `tests/wit_consistency.rs` + `wit/ironet-policy.wit`）已完整，`api.rs` 已是 924 行的 re-export + host adapter。agent 的"失败"通知发生在交付最终报告时，工作本身已完成。
- 尚未做的可选项：`cargo check -p ironet-policy-abi --target wasm32-unknown-unknown`（需 wasm32 rust-std，见 1.5 工具链结论）。

### 2.3 拆分 `AutoTunerV2`（6.2）（第三波完成，已验证）

- 新增 `src/protocol/v2/policy/guardrails.rs`（~1050 行）：`GuardrailContextV1`、`GuardrailsV1::{new, from_bounds, limits, apply(candidate, base, ctx) -> (EffectiveActionV1, ClampReportV1), reapply}`，12 测试（9 条 12.3 属性测试：硬界、cwnd floor<=cap、FEC 几何/线上开销、reliable⇒FEC off、CPU/队列紧急优先、emergency 保护不可关、接收内存<=预算、cover 宿主派生且<=预算、apply 幂等/报告诚实）。
- 新增 `src/protocol/v2/policy/transition.rs`（~390 行）：`TransitionControllerV1::{new, reset, smooth, pending_fec, pending_repeats}`（FEC 三次确认 + 1 s 冷却、关闭即时、emergency 旁路；train/send/receive 步长），6 测试。
- `tuning.rs`：新增 `FilteredTelemetryV1`、`TelemetryFilterV1`、`NativePolicyV1::propose(&FilteredTelemetryV1, &HostLimitsV1) -> CandidateActionV1`、`ForcedActionV2::to_candidate`；`AutoTunerV2` 变薄组合（filter → candidate → guardrails → transition → forced override → final guardrail → effective），对外 API 签名不变，新增只读 `current_effective/last_clamp_report/limits`。
- `policy.rs` 加 `pub mod guardrails; pub mod transition;`。
- 验证：tuning 33 / replay 3 / learner 11 / golden 2 / policy 60 全通过，workspace clippy 干净。
- 等价性说明：最终 guardrail pass 在默认 `AutoTuneBoundsV2` 下可证明为恒等；仅极端自定义 bounds（`minimum_train_bytes > 16 KiB`）冷启动爬坡会被提前钳到下界（新增安全网）。`constrain_action` 忽略 bbr_preset（与原行为一致）。

### 2.5 `crates/ironet-policy-core`（第三波完成，已验证；对应 §3.1）

- 文件：`Cargo.toml`（依赖仅 `ironet-policy-abi`、`serde`、`postcard 1.1.3`）、`src/{lib,spec,context,rng,learner,state,policy}.rs`。
- `PolicySpecV1`（contexts/presets/actions/posteriors/utility weights/exploration）+ `builtin()`（与 `config/autotune-policy-v1.json` 逐字段相等，宿主测试 `builtin_spec_matches_the_embedded_host_artifact`）；`ContextKeyV1`；`LearnerStateV1`（step/warm_start/export_memory/reset_for_policy_change）；`CorePolicy { new(spec, mode), builtin(mode), decide_traced(&input) -> (PolicyOutputV1, LearnerTraceV1) }` + `impl PolicyBackend`。
- state 编码 schema 1：`"IPLS"` + u32 schema + u32 len + postcard(LearnerStateV1)，小端；decode 超过 `POLICY_STATE_MAX_BYTES` → `StateTooLarge`，其他损坏 → `Internal`；encode 超 cap 时按"总观测数最少、key 最小"逐出 context。空 blob = 冷启动（rng = seed.max(1)）。
- `src/protocol/v2/learner.rs` 变薄适配层：公开 API（`BanditLearnerV2::{new,with_policy,replace_policy,export_memory,warm_start,step}`、`ContextKeyV2`、`LearnerTraceV2`、`LearnerMemoryV2` 等）签名与 serde 形状不变；新增 `policy_spec_from_artifact(&PolicyArtifactV2) -> PolicySpecV1`；`TickClock`：首个 Instant 为 tick 0，`floor(secs)`；dwell 判定改按 tick（生产中与旧 Instant 比较最多差 <1 s）。
- **设计妥协（需在 ABI 文档写明）**：宿主 utility 为保持 f64 精度走 TLV 扩展 `EXTENSION_TAG_HOST_UTILITY_F64_V1 = 1`（8 字节 LE f64 bits），`utility_milli` 只作回退；`LearnerTraceV2.predicted_advantage` f64 经 `decide_traced` 旁路取得，`PolicyDiagnosticsV1` 只有 milli 投影。
- 验证：core 26 测试、learner 11、replay 3、memory 1、tuning 30、policy 42、golden 2（bit-exact）；`cargo check --target wasm32-unknown-unknown` 因本机无 wasm32 rust-std 未验证（grep 确认无 std::time/rand/HashMap）。

### 2.4 单文件 package/签名/CLI（4.1–4.3、12.1）（代码已落地，验证通过；fixture 覆盖待核对）

- 目标：`src/protocol/v2/policy/package.rs`（顶层 component section 解析、`PolicyManifestV1` JSON 段、`PolicySignatureV1`、`PolicyPackage::parse/attach_manifest/sign/verify`，签名段必须是最后一个 section，digest = BLAKE3(前缀)）、`policy/signature.rs`（Ed25519 域分离 `"ironet-policy-v1\0"||digest`、`TrustStoreV1::from_config`、错误分类）、`ironet policy keygen/inspect/verify/sign` 子命令、12.1 全部恶意/畸形 fixture 测试。
- 落地状态：`package.rs`（1283 行，10 测试）、`signature.rs`（516 行，4 测试）已存在，`policy.rs` 末尾已有 `pub mod package; pub mod signature;`；main.rs 的 CLI（keygen/inspect/verify/sign + `policy_command` 分发）已接线，全 workspace 编译/clippy/policy 测试通过。agent 在改 main.rs 收尾时中断。
- **12.1 核对已完成（第三波）**：package.rs 18 测试、signature.rs 8 测试，policy 模块共 42 测试通过；覆盖矩阵：manifest 缺失/重复/超长/字段越界/JSON 形状与类型/控制字符/深嵌套；签名段 36 种载荷畸形、移植/伪造/重放/无域分隔/非规范标量/逐位翻转；component 截断穷举、11 种附加、12 种 section 编码故障、custom 预算精确边界、嵌套段永不被识别；ABI major 不匹配。"WIT round-trip / v1 guest / 缺 export / capability 交集"属于 abi/runtime 层，不在 package 范围。未改生产代码。
- 两点留给维护者决定：(a) 计划 4.2 写"嵌套段直接拒绝"，实现是"嵌套载荷不透视、忽略"（安全等价，测试已固定该性质）；(b) `parse_digest` trim 首尾空白而 `parse_signature` 不 trim，未统一。

## 3. 未开始 / 进行中（按依赖顺序）

状态标注（2026-08-21 第四波，codex gpt-5.6-luna max 经 herdr 驱动，kimi 指挥）：1–5 全部完成并验收。Phase 3 已全部完成（主体+shadow warmup+replay 子命令均由 kimi 直接实现并验收，全 workspace lib 测试、golden 2、clippy/fmt 全绿），见第 6 项。Phase 4 已完成（kimi 直接实现并验收，见第 8 项）。Phase 5 已完成（见第 9 项）。Phase 6 已完成（kimi 直接实现并验收，见第 10 项）——**计划全部 Phase 已落地**；唯一遗留是 netns 动态矩阵需 root 环境（第 10 项 6.7）。

1. **`crates/ironet-policy-core`**（10.1，依赖 2.2）：把 `learner.rs`（`BanditLearnerV2`、`ContextKeyV2`、`materialize_policy_action`、`LearnerMemoryV2` 等）与 `policy.rs` 的 JSON artifact 数据结构搬进只依赖 `ironet-policy-abi` 的 crate，输入 `PolicyInputV1`、输出 `PolicyOutputV1`，状态序列化进 `state: Vec<u8>`（需定义 `state_schema=1` 的编码，建议 postcard/自定义定长，不用 JSON）；`Instant` 依赖改为 `logical_tick`；宿主侧 `learner.rs` 只留适配与 golden 测试。门禁：用 `tests/fixtures/autotune-golden-v1.json` 逐样本一致。
2. ~~**`tuner_loop` 接线**~~ **（第四波完成，codex-wire）**：`src/protocol/v2/policy_tick.rs`（62KB）承载 baseline → `PolicyInputV1` → backend → guardrails → `EffectiveActionV1` → 数据面的可单测 tick 管线；logical tick、BLAKE3 peer hash、确定性 seed、utility f64 TLV 扩展、limits/capabilities/egress/state 全部接入；native/builtin/JSON 走 `CorePolicyBackendV1`，`.wasm` 暂清晰报错回退 builtin（待 Phase 3）；Shadow 用独立 backend/state/utility 不写出线；故障状态机 + quarantine + baseline fallback + JSON 5 秒热重载（修掉了 `native` 误触发 warn）；`PolicyStateStoreV1`（`(policy_id, state_schema, peer)` 键、定时/切换/断连 flush、legacy memory warm start）；status 增加 live/shadow backend、ABI、health、fault、clamp 等字段。新增 policy_tick 8 + state store 4 测试。妥协：`previous_utility` 用当前 tick 的 host baseline（保 replay/golden 逐样本一致）；adaptive cwnd floor 仍由宿主侧追加；netns 基线脚本未跑。
3. ~~**guest SDK `crates/ironet-policy-sdk`**~~ **（第四波完成，codex-sdk）**：wit-bindgen 绑定 ↔ ABI 双向转换、故障映射、定点工具、`GuestPolicy`/`run_decide`/`export_policy!` 宏、echo/conservative fixture guest、README。
4. ~~**`crates/ironet-policy-builtin` + 构建脚本 + CI digest**~~ **（第四波完成，codex-sdk）**：`CorePolicy::builtin(mode)` 的 guest 包装（`capabilities.shadow=true` → Shadow，否则 On）；`builtin.wasm`（82,952 B）+ BLAKE3 sidecar 提交仓库；`scripts/build-policy-guest.sh`（`--check` 复现校验，连续构建 digest 一致：`blake3:905fbd9b…f95b0`）；`tests/fixtures/policy/guests/{echo,conservative}.wasm`；`.forgejo`/`.github` CI 加 digest 校验；flake.nix wasm32 段；wasm-tools validate / component wit 均通过；`ironet policy inspect builtin.wasm` 解析通过。
5. ~~**Wasmtime runtime**~~ **（第四波完成，codex-runtime）**：`src/protocol/v2/policy/runtime.rs`——wasmtime 48 Component runtime、Pulley64 Engine（决策的 `cranelift+pulley` features）、组件 digest 缓存、Store/Instance 池、fuel/epoch/StoreLimits、ABI 转换、错误映射、7.4 故障状态机、`PolicyLoader`、`PolicyExecutor` 有界 worker；`policy/status.rs` 状态 DTO；根 Cargo.toml 加 wasmtime 48。恶意 guest fixture 11 个（`tests/fixtures/policy/malicious/`，含构建脚本）：echo/loop/fuel-burn/memory-grow/trap/oversized-state/oversized-output/invalid-enum/overflow-action/all-maximums/non-deterministic-attempt，覆盖自检拒绝、fuel/deadline/memory、输入/输出/state 限制、bit-exact 重复调用、Quarantined、队列满、NaN 确定性；wasm-tools validate 11/11。runtime 专项 10 测试。性能样本：首次调用 961 µs，稳态 p50/p99 = 886/1,028 µs，fuel p50/p99 = 4,400。遗留：tuner_loop 生产路径的 .wasm 切换接入留到 Phase 3。
6. **Phase 3**（主体完成，2026-08-21，kimi 直接实现）：
   - **生产加载 `.wasm`**：`v2_runtime.rs::load_wasm_live_slot`——读私有缓冲 → `TrustStoreV1::from_config` 验签/预算校验 → 编译（digest 缓存）→ 实例化 → 自检；失败回退 builtin 并给出明确 error。`V2RuntimeState` 新增懒初始化共享 `PolicyLoader`（`OnceLock`，非 wasm 部署不付 engine 成本；engine 构造失败降级 builtin 而非 panic）。wasm 策略的 utility 权重取宿主规范 `Objective::weights()`（组件不携带权重袋）。
   - **热切换**：每 5 s 对文件做整体 BLAKE3；变化则 `spawn_blocking` 后台跑完整加载管线（含自检），完成后在 1 s 采样边界 `replace_live` 原子切换；切换前 flush 脏状态；任何失败只记 error（去重 warn）保留 last-known-good；不重建 QUIC、不在 tick 路径编译。加载前记录 hash，坏文件不每 5 s 重试。
   - **8.2 迁移语义**：`PolicySlotV1::replace`/`replace_live`/`ShadowEvaluatorV2::replace_slot` 新增 `state_schema_accepts: &[u32]`——`policy_id` 相同且（schema 不变或新模块 accepts 声明接受旧 schema）时保留状态，guest 自行转换；JSON/native 调用点传 `&[]`（行为不变）。新增测试 `hot_switch_state_schema_accepts_allows_guest_side_migration`。
   - **builtin digest 固定测试**：`package.rs::tests::committed_builtin_wasm_matches_its_digest_sidecar`（`include_bytes!` + sidecar 比对 + package 解析）。
   - 文档：`docs/配置参考.md` 的 `autotune.policy` 三层取值与热切换段落已更新为 wasm 已支持。
   - **8.3 shadow warmup（补齐，2026-08-21，kimi）**：候选组件加载（含自检）成功后不再直接切换，而是挂成独立 `WasmWarmupV1`（`ShadowEvaluatorV2` 包装候选 slot），每拍用 `observe()` 观察实时输入（不写出线），连续 5 拍（`WASM_WARMUP_TICKS`）无故障才在采样边界晋升 `replace_live`；任何一拍 fault 即中止、保留 LKG（文件 hash 已记录，不变不重试）。晋升时把热身 backend 原样移入 live slot（新增 `PolicySlotV1::into_backend`/`ShadowEvaluatorV2::into_slot`），热身状态丢弃，状态去留按 8.2 规则对 live 现状态判定。warmup 期间不发起新的加载。新增测试 `warmup_promotion_moves_the_backend_and_applies_live_state_rules`。启动初次加载仍自检后直接上线（无 LKG 可保护）。
   - **`ironet policy replay` 子命令（补齐，2026-08-21，kimi）**：`replay.rs::replay_ticks` 让 fixture 走生产 `PolicyTickV1`（PolicyBackend/guardrail）管线——`builtin`/`native`/JSON artifact 走 core slot，`.wasm` 走 `PolicyLoader` 验签加载（信任源：默认 sealed config 的 `[autotune.wasm]`，或 `--signer-pubkey`/`--digest-pin` 覆盖）。输出 `TickReplayReportV2`（逐样本 baseline/effective/candidate/clamps/fault/utility bits + trace_digest，全确定性，不含墙钟）；`--golden REPORT` 与先前报告逐样本比对，首个分歧样本即非零退出（deterministic assert）。`--objective/--mode/--seed/--side/--output` 齐备。测试：`tick_replay_matches_the_checked_in_golden`（builtin 逐样本复现已入库 golden 的 baseline/effective/utility bits）、确定性+时间倒流拒绝、wasm backend（echo fixture + digest pin）。CLI 已端到端人工验证：golden 匹配/分歧退出/未签名拒绝。Phase 3 至此全部完成。
7. ~~**Phase 4**~~ **（完成，2026-08-21，kimi 直接实现）**，见第 8 项。Phase 5/6 亦已完成，见第 9/10 项。
8. **Phase 4：完整动作面与统一护栏（完成，2026-08-21，kimi 直接实现并验收）**：
   - **决策**：新增上限全部用 guardrails 宿主常量（`REPAIR_RETENTION_CAP_MILLIS=60_000`、`REASSEMBLY_BUDGET_FLOOR_BYTES=1MiB`、`ACTIVE_TRAIN_BUDGET_CAP=1024`=协商 wire limit），未动 ABI/WIT/`HostLimitsV1`——避免重编 13 个 wasm fixture 和 builtin.wasm digest。
   - **`TuneDecisionV2` 扩展**：新增 `repair_retention_millis`(0=宿主默认 2s，`REPAIR_CACHE_DEFAULT_TTL_V2`)、`repair_wait_policy: RepairWaitPolicyV2`（HostDefault/Eager=宿主等待减半/AfterFecWindow/Patient=加倍，带 metrics u8 编解码）、`reassembly_budget_bytes`(0=跟随 receive buffer)、`active_train_budget: u16`(0=wire 协商值)；`policy/api.rs` 的 `from_tune_decision`/`to_tune_decision` 双向携带，含 `RepairWaitPolicyV1↔V2` 转换。剩余 Unsupported 域收窄为：scheduler admission window+preset hint、TX datagram admission+producer window、repair responsibility（具名 clamp，非 shim）。
   - **guardrails 开放**：`guard_bbr` 逐字段镜像 `Bbr3Params::from_tunables` 的控制器内部区间（pacing/cwnd gain、headroom、beta、loss thresh、guard、probe RTT 各区间 + pacing cap 非零则 ≥64KiB + cwnd cap 非零则 ≥4×1200），effective 即数据面实际执行值，控制器二次 clamp 保留为第二道防线；`guard_fec` 的 preset family 在 enabled 时保留、disabled 清零，候选显式设 family 且未设显式 cells 时映射宿主几何表（Sparse=(16,1)/Balanced=(8,2)/Dense=(8,4)），emergency 恢复 base 几何时连带恢复 base family；`guard_repair` retention 开放+封顶（AboveCap）、wait_policy 透传；`guard_tx_rx` reassembly budget 开放并双向夹取 `[min(1MiB,有效receive buffer), min(receive cap,有效receive buffer)]`（只能缩小不能扩大 RX 内存）、active train budget 夹取 `1..=1024`。
   - **数据面消费**：`apply_bbr3_effective`（v2_runtime）把 20 个 BBR 字段全量写 tunables（含 startup_bw_hint），cwnd floor 与 adaptive floor 取 max；tuner_loop 从 `decision.bbr` 改为 `outcome.effective.bbr`；等价性测试 `bbr_effective_publish_matches_the_legacy_proposal_path`（7 preset × cap/floor 组合，旧 proposal 路径 vs 新 effective 路径逐字段全等）；旧 `apply_bbr3_proposal` 收缩为 `#[cfg(test)]`。`RepairCacheV2::set_ttl` + `V2Tx::apply_tuning` 应用 retention；`EffectiveTuneV2` 加 retention 变更检测。`RuntimeMetrics` 新增 `repair_wait_policy`/`reassembly_budget_bytes`/`active_train_budget` 原子量，tuner_loop 每拍发布；`adaptive_repair_minimum_age` 按 wait policy 映射（Eager 减半、Patient 加倍封顶 2s）；`ReassemblyTableV2::set_maximum_active_trains`（收缩即修剪完成墓碑）；`V2Rx` 新增 reassembly/active-train 预算字段与 `set_reassembly_budget`，per-epoch reassembly 份额 = `min(均分, budget/epochs)`、train 上限 = `min(budget, 协商值)`；`apply_receive_buffer_target` 扩展消费两者。
   - **fuzz**：新 target `v2_policy_guardrails`（postcard 解 `CandidateActionV1` + 尾部 40 字节驱动 `GuardrailContextV1`，断言 BBR 全字段硬界限、reliable/CPU 压 FEC、latency queued 时 bulk quantum=1、CPU emergency 不超 base、RX 预算只缩不扩、retention/active-train 封顶、cover 派生、egress 关系、reapply 幂等+空报告）；`fuzz/Cargo.toml` 加 [[bin]] + postcard 1.1.3（lockfile 已有版本）；`generate_corpus.py` 生成 3 个手工 postcard 种子；ABI crate 加 postcard dev-dep + `fuzz_seed_corpus_decodes_as_postcard` 测试验证种子可解码；`scripts/fuzz-v2.sh` 加入新 target。**注意**：本机无 cargo-fuzz/nightly，fuzz 只做到编译通过+种子解码验证+等价 property 测试覆盖，实际 fuzz 运行留 CI。
   - 验证：guardrails 19 测试（含 4 条 widened property）、policy 77、全 workspace lib 414、golden 2、clippy 全绿。
9. ~~**Phase 5：Node Egress Coordinator**~~ **（完成，2026-08-21，kimi 直接实现并验收）**：
   - **新模块 `src/protocol/v2/policy/egress.rs`**：`NodeEgressCoordinatorV1`（存在 `V2RuntimeState`，各 peer 任务经 `Arc` 共享）+ 纯函数 `arbitrate`（两阶段裁决：minimum guarantee → 非 exploring 的 weighted max-min excess（weight=priority+1，≤n+1 轮收敛，地板除法保证 Σ≤预算）→ exploring 只吃剩余 → 总量封顶）。minima 超预算时按比例缩减且严格不超 cap。
   - **9.2 不等待慢 peer**：无 actor、无等待——每 peer 在自己任务里 `publish`/`view` 共享状态；demand 超过 `EGRESS_DEMAND_DEADLINE`(2.5s) 未刷新的 peer 以其上一轮 assigned 保留预算（保守需求）；30s 未刷新即剪除（断连）；无历史 peer 读动态公平份额（剩余预算/(活跃+1)）；guest trap=不发布，结构上不可能阻塞其他 peer。Control/Repair 走独立 QUIC stream，不在 BBR pacing 数据面内，仲裁天然压不到它们（已在模块文档注明）。
   - **回馈与合并**：`build_policy_input` 加 `egress: &EgressAllocationViewV1` 参数（assigned/node_cap/demand/pressure/active_peers/generation 回馈下一轮 WASM 输入，`capabilities.egress_coordinator` 随 node cap 配置自动置位）；`PolicyTickV1` 新增 `egress_view` 字段 + `set_egress_view`/`egress_view`，默认 `uncoordinated_egress_view`（assigned=node cap，与旧占位完全一致，replay/golden 零变化）；`clamp_pacing_to_assigned` 在 guardrails 之后把 effective pacing cap 夹到 assigned（记 `ClampReasonV1::EgressArbitration`，OK 与 fault 分支都走），assigned 低于 64KiB 控制器地板时不动（保持 effective==数据面实际执行）。
   - **tuner_loop 接线**：run 前 `tick.set_egress_view(coordinator.view(peer_hash, sampled_at))`，run 后 `coordinator.publish(peer_hash, outcome.effective.egress, sampled_at)`。
   - 测试 12（minima 优先、max-min 加权、exploration 只拿剩余、超承诺 minima 缩减、公平等分、4000 例 property（Σ≤可用预算/minima 满足/不超过 desired）、新鲜 peer、stale 保留、慢/故障 peer 不阻塞+无历史公平份额、剪除、未配置透传、子地板封顶）+ tick 管线测试 `coordinator_assigned_rate_binds_the_pacing_cap_with_arbitration_clamp`（clamp entry/幂等/回退 node cap）。全 workspace lib 427、golden 2 全绿。
10. ~~**Phase 6**~~ **（完成，2026-08-21，kimi 直接实现并验收）**：灰度/晋升/删除迁移代码全部落地。
    - **6.1 等价性门禁**：`replay.rs::builtin_wasm_matches_the_in_process_core_bit_exactly`——committed `builtin.wasm` 经 `PolicyLoader`（digest pin 信任）跑 `tests/fixtures/autotune-replay-v1.json`，On/Shadow 双模式与进程内 core slot 全 trace（candidate/clamps/effective/utility bits）逐样本相等。途中修掉三个真 bug：
      - **self_check 语义修正**：`runtime.rs::self_check` 固定 fixture 原来喂垃圾 state（`[1,2,3,5,8,13]`），builtin guest 按设计（计划 12.2）对坏 state 报 `Internal`，导致 builtin.wasm 永远过不了自检；改为空 state（冷启动），坏 state 由 fault 路径测试覆盖。
      - **candidate materialization 下沉 core**：shadow 反事实与 On 模式 action merge 原来在宿主 `CorePolicyBackendV1` wrapper 里做，guest 没有 → builtin.wasm 与进程内 core 不等价。已把两段 merge 移进 `ironet-policy-core/src/policy.rs::decide_traced`（新增私有 `merge_action`，精确复刻宿主 `ForcedActionV2::to_candidate` 语义：fec 0+0=显式关、字段缺省清 None）；`policy_tick.rs` 宿主 wrapper 瘦身为只转发+probe。**builtin.wasm 重建，新 digest `blake3:321efa19d1524cc98232304491371a5f12276e0388f66c92ff184ec6b5c4ba9e`（84,877 B）**，sidecar 已更新。
      - **Shadow/Off 模式 WASM live slot 会上线的生产正确性 bug**：tick 给 live slot 的 `capabilities.shadow` 原来恒为 false，builtin guest 按此位推导模式 → Shadow 配置的 wasm 会把 learner 动作真上线。已改 `PolicyTickV1::run` 按 `mode != LearnerModeV2::On` 传 shadow 位，且非 On 时 effective = `guardrails.reapply(baseline)`（candidate 仅观测）；`learner.rs` 适配层 `BanditLearnerV2::step` 改传 `shadow: false`（它自己做反事实，需要 applied-arm candidate）。
    - **6.2 native 收缩**：`policy_tick.rs` 新增 `NATIVE_RULES_POLICY_ID_V1 = "native-conservative@1"` + `NativeRulesBackendV1`（空 candidate → effective == 宿主 baseline，无状态、永不 fault，decision_kind=Hold）+ `PolicySlotV1::native_rules()`。**有意行为变更**：`native` 不再含 learner。
    - **6.3 builtin 晋升 WASM**：`runtime.rs` 新增 `BUILTIN_WASM_V1`/`BUILTIN_WASM_BLAKE3_V1`（include_bytes/include_str committed 组件+sidecar）+ `PolicyLoader::load_builtin`（parse → sidecar digest 一致性校验 → digest pin 信任，强制 require_signature=false，预算取 config）；core `spec.rs` 加 `BANDIT_POLICY_ID_V1 = "bandit-vivace@1"`。`v2_runtime.rs` 的 `tuner_loop` 选择逻辑：`native`→native_rules；`builtin`→load_builtin（失败→native_rules，policy_source 降级 `native`）；`.wasm` 路径→load_wasm_live_slot（失败→builtin_or_native_slot 回退链）。utility 权重一律 `objective.weights()`（已验证与旧 artifact 权重逐字段相等，golden 不变）。legacy memory warm start 条件放宽为 `state_schema==1 && policy_id==bandit-vivace@1`——builtin.wasm 可继承旧 JSON memory。
    - **6.4 删除 JSON 双路径**：`load_autotune_policy`/`live_policy_reload_path`/JSON 5 秒 reload 块全删；`config.rs` 校验——`policy`/`shadow_policy` 绝对路径必须 `.wasm`，否则报含 "JSON" 的明确迁移错误。`shadow_policy` 支持 `.wasm`：启动同步加载 + 5 秒整文件 hash 检查 + 后台加载 + 采样边界 `set_shadow` 热切换（无 warmup，shadow 本不上线），失败保留 LKG。**shadow 热切换不保留旧 shadow 状态（fresh start，仅观测面无影响）**。
    - **6.5 replay CLI**：`policy replay` 的 `native`→native_rules slot、`builtin`→`load_builtin`、`.wasm` 不变、其他绝对路径 bail 迁移错误。端到端手工验证全过（builtin=wasm/bandit-vivace@1/faults=0；native=native-conservative@1；--golden 自比对；JSON 拒绝；digest pin 放行 echo fixture）。**行为变化**：Shadow 模式 live slot 的 `TickReplaySampleV2.candidate` 现在是反事实候选（仅观测面）。
    - **6.6 可观测性（计划 §13）**：`PolicyBackend` trait 加默认方法 `fuel_consumed()`（WasmPolicyBackend 覆盖）；`BackendHealthV1` 加 `timeouts_total`（fault==Timeout 时计数）；`PolicySlotStatusV1`/`PeerStatus` 补齐 `module_digest`/`signer_id`/`module_generation`/`fuel_consumed`/`timeouts_total`/`quarantines_total`（live+shadow 全套，serde default 兼容旧快照）+ egress requested/assigned（来自 coordinator view 与 effective egress request）；Prometheus 新增 `ironet_v2_autotune_policy_{fuel_consumed,timeouts_total,quarantines_total,module_generation}`、`ironet_v2_peer_egress_{requested,assigned}_bytes_per_second` 和 `ironet_v2_autotune_policy_info`（label 仅 endpoint/name/backend/module_digest/signer_id，无任意 guest 字符串）；TUI peer 详情加 module/egress 两行。打包：builtin.wasm 经 include_bytes 内嵌进 musl 静态二进制，deb/CI（build-policy-guest --check + musl 构建）已覆盖，发布门禁满足。
    - **6.7 遗留（环境受限，非 blocked）**：`scripts/autotune-oracle.sh`/`profile-v2-netns-matrix.sh` 需要 root 建 netns（本机 UID 1000 无权限，`ip netns add` 被拒），且 `target/profiling/` 二进制是 Phase 6 之前的旧构建；native vs WASM 的完整动态矩阵、shadow 整周期观察和 RSS/火焰图基线对比留给有 root 的 CI/机器。脚本本身与新语义兼容（默认 `builtin`，绝对路径交 daemon 校验）。
    - **保留而非 shim**：`policy::load`/`load_or_builtin`/`PolicyArtifactV2`/`core_slot_from_artifact`/`PolicySlotV1::core` 仅被 examples（`autotune_train`/`autotune_replay`/`autotune_promote`）与测试引用——这是 oracle→训练→replay 的命名工具链，生产路径不再引用。
    - `policy_source` 状态字段取值现在是 `native`/`builtin`/具体 `.wasm` 路径。
    - 验证：workspace check/test（432 lib）/golden 2/clippy/fmt/doc-links 全绿（见 §3 末行状态）。

## 4. 注意事项

- `src/protocol/v2/policy.rs` 同时被 2.3（靠前加 `pub mod guardrails; pub mod transition;`）和 2.4（末尾加 package/signature）编辑；合并后确认 4 行 `pub mod` 都在且只出现一次。
- 若 2.2 完成后 api.rs 变成 re-export，2.3 通过 `crate::protocol::v2::policy::api::` 引用的名字应不受影响；若编译报找不到名字，优先检查 api.rs 的 `pub use` 列表。
- golden 文件再生命令写在文件头 `generated_by`；任何改变 learner/tuner 行为的改动都应使 `tests/autotune_golden.rs` 失败——这是有意的护栏，不要为了通过而更新 golden（除非是 Phase 0 明确的行为变更并在 PR 中说明）。
- 所有新增依赖必须能从 `Cargo.lock` 已有版本离线解析（当前网络可用性以 2.1 报告为准）。
