# WASM 策略模块化：单文件交付实施计划

目标：把当前由内置规则、`PolicyArtifactV2` JSON 和 `BanditLearnerV2` 共同完成的慢环策略，演进成可热加载、可签名、可回放、可灰度的单文件 `policy.wasm`；宿主继续独占护栏、协议、实时调度、资源上限和故障回退。

本文是按阶段、按文件和按验收门禁执行的实施计划。符号位置以当前工作区为依据，实施时以符号名重新定位，不依赖固定行号。

## 0. 执行摘要

### 0.1 最终交付形态

策略作者最终只交付一个文件：

```text
/etc/ironet/policy.wasm
```

该文件同时包含：

```text
policy.wasm
├─ WebAssembly Component 策略代码
├─ 策略默认参数、先验和内部状态迁移逻辑
├─ ironet.manifest.v1 自定义段
└─ ironet.signature.v1 自定义段
```

节点信任根、资源硬上限和总出口预算属于宿主配置，不由策略文件携带或扩大。

### 0.2 核心架构

```text
每秒遥测
   ↓
PolicyInputV1
   ↓
policy.wasm::decide(input, state)
   ↓
CandidateActionV1
   ↓
Host Guardrails + Transition Controller
   ↓
节点出口仲裁
   ↓
EffectiveActionV1 + ClampReportV1
   ↓
BBR3 / Scheduler / FEC / Repair / TX / RX / Cover
```

策略模块只提出候选值；宿主裁决有效值；数据面在既有实时边界执行。

### 0.3 决策

1. 使用 **一个 WASM Component**，不部署八个相互调用的 WASM 文件。
2. 使用版本化 WIT Component ABI，不把 Rust 内部结构体布局作为 ABI。
3. WASM 调用保持在每 peer、每秒一次的慢环（与当前 `tuner_loop` 每 connection 一次对齐，一次 `decide` 同时产出 tx/rx 全部域），永不进入 per-packet、per-ACK 或 per-Cell 热路径。
4. 策略状态显式作为受限字节串输入/输出，由宿主持久化；不为每个 peer 常驻大型有状态实例。
5. 策略 backend 固定为三层：`native` 是无 WASM 的确定性保守规则（不含 learner）；`builtin` 是编进二进制的 `policy.wasm`（learner 只在 guest 中存在一份）；外部路径是第三方 `.wasm`。外部 JSON policy 只作为迁移输入，不保留永久双运行时。
6. Utility/reward 由宿主按 `objective` 计算并作为输入喂给 guest；shadow advantage、promotion gate 和自动回滚只认宿主 utility，guest 不能自评分。
7. Node Egress Coordinator 固定在宿主，与 WASM 解耦，可先以 shadow allocation 独立上线；WASM 只提交需求。
8. 生产环境使用无 WASI、无网络、无文件、无环境变量的 Wasmtime Component runtime，并同时限制 fuel、deadline 和内存；Phase 0 同时评估 Pulley 解释器与 Cranelift JIT 两种执行后端。

### 0.4 工期

| 范围 | 单人串行估算 |
| --- | ---: |
| Phase 0–2：契约拆分 + 单文件 WASM MVP | 5.5–8 个工作日 |
| Phase 3–4：签名、热切换、完整动作面、统一护栏 | 6–9 个工作日 |
| Phase 5：Node Egress Coordinator（可与 Phase 2–4 并行） | 4–7 个工作日 |
| Phase 6：灰度、晋升、删除迁移代码 | 3–5 个工作日 |
| 合计（串行） | 18.5–29 个工作日，约 4–6 周 |

Node Egress Coordinator 只依赖 `egress-request` 一个字段，与 native backend 同样可配合，不必排在 WASM 之后。

## 1. 目标、非目标与不可变原则

### 1.1 目标

- 不重新编译 `ironetd` 即可替换策略算法。
- 一个 `policy.wasm` 同时服务所有 peer，并保持 per-peer 独立状态。
- 支持 `off`、`shadow`、`on` 三种模式和 live/shadow 双策略并行。
- 支持下一采样边界热切换，不重建 QUIC 连接。
- 支持离线确定性 replay、策略训练和 promotion gate。
- 完整覆盖 BBR3、Scheduler、FEC、Repair、TX、RX、Cover 和出口需求提案。
- 所有越界、冲突和资源压力裁决都由宿主完成并可观测。
- 模块 trap、超时、OOM、坏签名或状态损坏时不中断转发。

### 1.2 非目标

- 不允许 WASM 直接读写 TUN、QUIC、socket、qdisc、NIC 或内核路由。
- 不允许 WASM 解析、生成或修改 wire packet/control message。
- 不允许 WASM 参与身份、认证、密钥、握手或能力协商。
- 不允许 WASM 决定队列硬上限、总内存硬上限和总出口硬预算。
- 不在 V1 ABI 中支持模块间动态链接或多个策略文件组合。
- 不保证任意语言 SDK；首版只保证 WIT ABI 和 Rust guest SDK。

### 1.3 不可变原则

```text
Policy 只表达意图
Guardrails 拥有最终裁决权
Dataplane 不执行策略推理
所有状态有上限
所有动作可回放
所有切换可回滚
模块失效不影响基础转发
```

## 2. 当前实现与可复用接缝

| 已有能力 | 当前位置 | WASM 改造方式 |
| --- | --- | --- |
| 每 peer 1 s 慢环 | `src/v2_runtime.rs::tuner_loop` | 在 learner 与动作应用之间插入统一 `PolicyBackend` |
| 遥测输入 | `src/protocol/v2/tuning.rs::PathTelemetryV2` | 转换为稳定 `PolicyTelemetryV1` |
| 当前动作契约 | `TuneDecisionV2` | 拆成 Candidate/Effective/ClampReport |
| 规则策略与平滑 | `AutoTunerV2` | 拆成 native policy、transition、guardrails |
| JSON 策略 | `src/protocol/v2/policy.rs` | 迁移为 native backend 数据和 guest 内嵌数据 |
| 在线学习器 | `src/protocol/v2/learner.rs` | 首个 builtin WASM 的参考实现 |
| shadow evaluator | `src/v2_runtime.rs::ShadowEvaluatorV2` | 改成 backend 无关的双执行器 |
| BBR3 运行时句柄 | `Bbr3Tunables` | 接收宿主验证后的完整 BBR 参数 |
| TX 调优通道 | `watch::Sender<Option<TuneDecisionV2>>` | 发布 `EffectiveActionV1` 或兼容适配值 |
| replay/oracle/promotion | `examples/`、`scripts/` | 让 native 与 WASM 走同一 ABI/guardrail |
| policy digest/hot reload | `policy.rs`、`tuner_loop` | 升级为签名 Component 的预验证、预编译和原子激活 |

现有 `/home/bubu/sdwan/crates/ironet-extension-sdk` 是 Unix Socket 控制面 SDK，不复用为数据面策略 ABI，避免把两个生命周期和信任边界混在一起。

## 3. 目标模块边界

### 3.1 宿主固定部分

```text
Host
├─ TelemetryCollector
├─ PolicyLoader / SignatureVerifier
├─ PolicyExecutor
├─ StateStore
├─ GuardrailsV1
├─ TransitionControllerV1
├─ NodeEgressCoordinatorV1
├─ NativeConservativePolicy
├─ HotSwapManager
└─ DataplaneApplier
```

宿主继续固定：

- Control、Repair 请求发送时机和缺失检测；
- Scheduler 的 Control/Repair/latency 硬优先级与 flow fairness；
- FEC geometry、wire overhead、对端 capability 和可靠 underlay 限制；
- TX/RX/reassembly 内存硬上限；
- Cover 在拥塞、CPU、真实业务压力下的削减；
- BBR3 每项内部 clamp 和轮次边界刷新；
- 节点级总出口仲裁；
- 模块加载、签名、故障隔离和回滚。

### 3.2 WASM 可替换部分

一个 Component 内部可自由拆分：

```text
Guest
├─ context classifier
├─ utility estimator
├─ learner
├─ BBR proposal
├─ scheduler proposal
├─ FEC/Repair proposal
├─ TX/RX proposal
├─ cover proposal
└─ egress demand proposal
```

guest 不能导入宿主对象引用；全部输入来自一个版本化快照，全部输出收敛为一个原子候选动作。

### 3.3 Backend 三层语义

| `autotune.policy` 取值 | backend | 内容 | 用途 |
| --- | --- | --- | --- |
| `native` | `NativePolicyBackend` | 仅现有 `AutoTunerV2` 的确定性 propose 规则，不含 learner、不含 JSON artifact | 故障 fallback、Quarantined 状态、禁用 WASM 的构建 |
| `builtin`（默认） | `WasmPolicyBackend` | 编进二进制的 `builtin.wasm`（`include_bytes!`），包含当前 `BanditLearnerV2` 等价逻辑 | 默认生产策略 |
| 绝对路径 `.wasm` | `WasmPolicyBackend` | 第三方签名 Component | 外部策略 |

规则：

- learner 只在 guest 中存在一份；宿主不再维护第二份 learner 实现。
- `native` 必须在任何遥测下都能给出有效动作，且是"当前遥测下的保守 baseline"，不是"上一 tick 的激进动作"。
- Utility/reward 由宿主 `UtilityEstimator` 按 `objective` 计算，作为 `PolicyInputV1.previous_utility` 喂给 guest；guest 内部可另算效用，但 shadow advantage、promotion、回滚只使用宿主值。
- `builtin.wasm` 与参考 guest 来自同一个 `ironet-policy-core` crate（见 10.1），保证 golden 一致性门禁可达。

## 4. 单文件格式

### 4.1 Component 内容

最终文件是合法 WebAssembly Component。策略代码、默认参数和先验编译进数据段；描述和签名写入 custom section。

`ironet.manifest.v1` 至少包含：

```text
format_version
policy_id
policy_version
abi_world = ironet:policy/policy@1.0.0
extensions_supported[]
state_schema
capabilities[]
minimum_host_version
maximum_state_bytes
requested_memory_bytes
requested_fuel
built_at
source_revision
```

Manifest 是能力申请，不是授权。有效能力为：

```text
declared capabilities
∩ host supported capabilities
∩ node configured capabilities
```

### 4.2 单文件签名

签名算法固定为 Ed25519（复用仓库已有 `ed25519-dalek`），不做算法协商；摘要固定为 BLAKE3。`ironet.signature.v1` **必须是顶层 component 的最后一个 section**，因此：

```text
digest = BLAKE3(文件从第 0 字节到 ironet.signature.v1 段起始位置的精确前缀)
signature = Ed25519Sign("ironet-policy-v1\0" || digest)
```

签名段只在末尾出现一次，避免"签名段在中间"产生两种字节编码对应同一语义。

签名段包含：

```text
signature_format = 1
signer_id
digest
signature
```

加载器必须：

1. 只认顶层 component 的 `ironet.manifest.v1` / `ironet.signature.v1`；嵌套 core module 或子 component 中出现同名段直接拒绝；
2. 拒绝重复 manifest/signature section，拒绝签名段不是最后一个 section 的文件；
3. 在实例化前解析并限制 custom section 大小；
4. 对前缀原始字节重新计算 digest；
5. 使用宿主 trust store 验签；
6. 检查 ABI world、capability、版本和资源申请；
7. 检查 `policy_version` 不低于已激活版本（防回滚，可按 signer 配置关闭）；
8. 验证通过后才允许编译和执行。

信任根规则：

- trust store（signer 公钥列表、每个 signer 的 `minimum_policy_version`、可选过期时间）属于 sealed config 的一部分，不是独立可写文件；否则签名只防"改策略文件"不防"改信任根"。
- 支持多 signer 并存以完成 key rotation；撤销 = 从 sealed config 删除并重新 seal。
- 开发模式可以通过显式配置使用 digest pin；生产默认要求可信签名。模块自报公钥不构成信任。

### 4.3 构建与检查命令

在现有 `ironet` CLI 增加：

```bash
ironet policy keygen --output signer.key            # 生成 Ed25519 签名密钥，打印 signer_id 和公钥
ironet policy inspect policy.wasm                  # manifest、signer、digest、ABI、资源申请
ironet policy verify policy.wasm                   # 按本机 trust store 或 --signer-pubkey 验签
ironet policy sign --key signer.key unsigned.wasm --output policy.wasm
ironet policy replay policy.wasm FIXTURE [--golden GOLDEN]   # 离线确定性回放，不启动 daemon
```

`replay` 子命令与 `examples/autotune_replay.rs` 共用同一 `PolicyBackend`/guardrail 代码路径，使运维能在不启动 daemon 的情况下跑同一 fixture 对比 candidate/clamp/effective。

不新增第二个生产二进制，遵守当前 V2-only 可执行文件约束。构建时可以使用源码、WIT 和临时 manifest；部署产物始终只有最终 `policy.wasm`。

## 5. WIT ABI V1

### 5.1 版本策略

- 包名固定为 `ironet:policy@1.0.0`，world 为 `ironet:policy/policy@1.0.0`。
- WIT record 不能向后兼容地增删字段：任何对 `PolicyInputV1`/`CandidateActionV1` 的字段改动对已编译 guest 都是 breaking。因此 V1 从一开始就内置扩展点，而不是依赖"以后加字段"：
  - `PolicyInputV1.extensions: list<tuple<u16, list<u8>>>`：宿主新增遥测以 TLV 追加，tag 在 SDK 中注册；guest 忽略不认识的 tag。
  - `HostCapabilitiesV1.extension-tags: list<u16>`：宿主声明本次提供了哪些扩展 tag，guest 可按需降级。
  - `CandidateActionV1.extensions: list<tuple<u16, list<u8>>>`：guest 提出新域候选；宿主忽略不认识的 tag 并计入 `ClampReportV1`。
  - 每个 TLV 有长度上限，总量计入 64 KiB 输入/输出预算。
- 只有当扩展袋承载不了（如语义变化、必填字段）时才发布新的 major world；宿主在迁移期并行支持有限数量（≤2）major world，各自独立 `bindgen!`。
- 不依赖 Rust `repr`、Serde JSON、`usize`、`Instant` 或平台字节序。
- 数值使用 `u8/u16/u32/u64/s32/s64` 和明确单位。
- 比率使用 per-mille/ppm；持续时间使用 microseconds/milliseconds；速率使用 bytes/s。
- 所有 guest 数值仍需宿主检查溢出、枚举、NaN 和跨字段约束。

### 5.2 输入

```text
PolicyInputV1
├─ logical_tick: u64
├─ deterministic_seed: u64
├─ peer_hash: list<u8>[32]
├─ path_epoch: u64
├─ reliability
├─ telemetry: PolicyTelemetryV1
├─ previous: EffectiveActionViewV1
├─ previous_utility: HostUtilityV1      (宿主按 objective 计算的上一 tick reward、分项、objective 枚举)
├─ limits: HostLimitsV1
├─ capabilities: HostCapabilitiesV1
├─ egress: EgressAllocationViewV1
├─ extensions: list<tuple<u16, list<u8>>>
└─ state: list<u8>
```

输入不提供真实 EndpointId、墙钟、文件路径或密钥。`peer_hash` 只用于确定性分桶；`deterministic_seed` 由宿主按 `policy_id`、`state_schema`、peer 和 path epoch 派生（不用 digest，避免每次 rebuild 重置探索序列）。`previous_utility` 是 guest 的 reward 信号，也是 promotion/shadow 唯一认可的效用来源。

`PolicyTelemetryV1` 覆盖现有 `PathTelemetryV2`，并按方向明确命名：

```text
path/rtt/min-rtt/queue-delay/reliability
local-tx wire-rate/goodput/queue/loss/controller snapshot
local-rx wire-rate/goodput/reassembly pressure
remote feedback/FEC/Repair/residual loss/reorder
latency sojourn p50/p95/p99
CPU/packet rate/train build rate
current node egress pressure
```

### 5.3 输出

```text
PolicyOutputV1
├─ candidate: CandidateActionV1
├─ next_state: list<u8>
└─ diagnostics: PolicyDiagnosticsV1
```

`CandidateActionV1` 的所有子域均为 optional：

```text
CandidateActionV1
├─ bbr
├─ scheduler
├─ fec
├─ repair
├─ tx
├─ rx
├─ cover
├─ egress-request
└─ extensions: list<tuple<u16, list<u8>>>
```

`diagnostics` 仅允许有限枚举、有限长度标签和定点分数，禁止任意大字符串。

### 5.4 BBR 候选

V1 一次覆盖当前 `Bbr3Tunables` 已支持的完整策略面：

```text
probe_bw_up_pacing_gain_milli
probe_bw_down_pacing_gain_milli
cruise_pacing_gain_milli
default_cwnd_gain_milli
probe_bw_up_cwnd_gain_milli
headroom_milli
beta_milli
loss_threshold_milli
loss_is_congestion
queue_guard_inflation_milli
queue_guard_slack_micros
probe_rtt_interval_millis
probe_rtt_duration_millis
probe_rtt_cwnd_gain_milli
min_probe_wait_millis
max_added_probe_wait_millis
pacing_cap_bytes_per_second
cwnd_floor_bytes
cwnd_cap_bytes
startup_bw_hint_bytes_per_second
```

宿主将其转换成 `ValidatedBbrActionV1` 后写入 `Arc<Bbr3Tunables>`；控制器内部现有 clamp 保留为最后一道限制。

### 5.5 其他候选

| 域 | V1 字段 |
| --- | --- |
| Scheduler | train target、bulk quantum、bulk admission window、preset hint |
| FEC | enabled、data cells、parity cells、preset family |
| Repair | cache bytes、retention target、wait policy、FEC/Repair responsibility hint |
| TX | send buffer、datagram admission、producer window |
| RX | receive buffer、batch、reassembly budget、active train budget |
| Cover | profile、overhead per mille、padding bytes/s |
| Egress | desired rate、minimum rate、priority、exploring |

Repair 请求的逐个发送时机、reassembly eviction 和 scheduler 选包顺序不进入 ABI。

## 6. 宿主内部重构

### 6.1 动作三分

新增：

```rust
pub struct CandidateActionV1 { /* guest/native policy proposal */ }
pub struct EffectiveActionV1 { /* host-authoritative values */ }
pub struct ClampReportV1 { /* field, requested, effective, reason */ }
```

`TuneDecisionV2` 在迁移期成为 `EffectiveActionV1` 到现有数据面的内部适配器，最终删除其“既是候选又是有效值”的语义。

### 6.2 拆分 `AutoTunerV2`

从 `/home/bubu/sdwan/src/protocol/v2/tuning.rs` 拆出：

```text
TelemetryFilterV1
  EWMA、min RTT、repair evidence、pressure hold

NativePolicyV1
  现有 propose/learner 行为，输出 CandidateActionV1

GuardrailsV1
  可靠 underlay、CPU、队列、capability、memory、wire overhead、总出口约束

TransitionControllerV1
  FEC hysteresis、buffer step、dwell、path change reset
```

执行次序固定为：

```text
raw telemetry
→ filtered telemetry
→ policy candidate
→ guardrails
→ transition controller
→ node arbitration
→ final guardrail pass
→ effective action
```

最后一次 guardrail pass 防止节点分配与 peer 动作合并后出现跨字段越界。

### 6.3 通用 `PolicyBackend`

```rust
trait PolicyBackend {
    fn identity(&self) -> &PolicyIdentityV1;
    fn decide(
        &self,
        input: PolicyInputV1,
        state: &[u8],
    ) -> Result<PolicyOutputV1, PolicyFaultV1>;
}
```

实现：

```text
NativePolicyBackend
WasmPolicyBackend
```

shadow/live、replay、oracle 和 promotion 只依赖 `PolicyBackend`，不再识别具体 learner 或 JSON artifact。

## 7. WASM Runtime

### 7.1 Runtime 选择

使用 Wasmtime Component Model，主因是：

- WIT 生成宿主和 guest 的类型安全绑定；
- 支持 fuel 和 epoch interruption；
- 支持 `StoreLimits`/resource limiter；
- Component 可作为独立单文件分发；
- 适合当前低频、非热路径调用。

依赖采用最小 feature 集；在引入前记录 release binary、增量编译和完整构建体积变化。若 stripped release binary 增长超过验收预算，先优化 feature/AOT/cache，不降级 ABI 为裸指针协议。

执行后端在 Phase 0 同时评估两种配置并用数据决定：

| 配置 | 优点 | 代价 |
| --- | --- | --- |
| Pulley 解释器（`cranelift` feature 关闭） | 二进制增量小数 MB 级；无 JIT、无 W^X 可执行页；hot reload 无编译 CPU 峰值；行为更易确定 | 单次调用慢一到两个数量级，但慢环每 peer 每秒一次，预期仍在百微秒量级 |
| Cranelift JIT | 调用最快 | 二进制增量约 15–20 MB；编译需后台线程；建议按 digest 的编译缓存目录跨重启复用 |

默认倾向 Pulley；只有当目标 peer 数下 Pulley 的 p99 调用延迟超过 7.3 预算时才启用 Cranelift。两种配置共用同一 WIT 和 `PolicyBackend`，切换只影响 Cargo feature。

> **Phase 0 spike 更正（2026-08-21，详见 `docs/WASM策略Phase0-runtime-spike.md`）**：Pulley 字节码由 Cranelift 编译，关闭 `cranelift` feature 后只能加载预编译 `.cwasm`，上表"小数 MB 增量"只对 AOT-only 成立。实测（wasmtime 43.0.2，Rust 1.91）：`pulley` 无编译器 +1.10 MiB，`cranelift,pulley` +11.29 MiB；Pulley 调用 p99 72–164 µs，Cranelift 3.5–4.1 µs，fuel 7,379/次。结论：默认 `features = ["runtime","component-model","std","cranelift","pulley"]` + `Config::target("pulley64")`（保留无 JIT 页、确定性、热路径无编译器，接受 +~11 MiB）；AOT-only 作为体积优化备选。另需决策 toolchain：wasmtime 48 LTS 需 Rust ≥1.95。

### 7.2 执行器

新增有界 `PolicyExecutor`：

```text
tuner_loop
→ bounded request channel
→ policy worker pool
→ reusable Store/Instance pool
→ typed result
```

规则：

- 编译和实例化不在 Tokio core worker 上进行；
- Engine 和已编译 Component 按 digest 共享；
- Store/Instance 不跨并发调用共享；
- 每次调用显式装载 fuel、epoch deadline、memory limit；
- guest 状态由输入/输出传递，实例池不保存业务状态；
- worker 队列满时立即使用当前采样的宿主 baseline，不无限等待。

### 7.3 默认资源预算

初始预算在基准测试后允许收紧：

```text
最大 component 文件：8 MiB
最大 custom section 总量：256 KiB
最大 linear memory：8 MiB
最大输入：64 KiB
最大输出：64 KiB
最大 per-peer state：64 KiB
单次 wall deadline：10 ms
单次 fuel：由 builtin guest 实测 p99 的 10 倍初始化
```

fuel 计数与 Wasmtime 版本和执行后端（Pulley/Cranelift）相关，不是稳定常量：每次升级 Wasmtime 或切换后端都必须重新标定 builtin guest 的 fuel p99 并更新默认值，升级 PR 带标定数据。

不得只依赖 wall timeout；fuel 防止确定性无限循环，epoch deadline 处理异常长调用，memory limiter 处理 OOM。

### 7.3.1 Engine 确定性配置

12.4 的"同输入同输出"需要 Engine 层落实，否则 replay 门禁不可达：

```text
relaxed_simd        = off   （非确定性语义）
threads / shared_memory = off
nan_canonicalization = on   （NaN 位模式在 native/wasm/不同 CPU 间一致）
wasm_simd           = off（V1 不需要）
memory64 / multi_memory / gc = off
```

guest SDK 侧：目标 `wasm32-unknown-unknown`（无 WASI），`panic = "abort"`，不提供时钟、随机、环境变量；所有随机性只能来自 `deterministic_seed`。

### 7.4 故障状态机

```text
Healthy
  ├─ 单次 trap/timeout/invalid output → Degraded
  └─ 正常调用 → Healthy

Degraded
  ├─ 后续成功 → Healthy
  └─ 连续 3 次失败 → Quarantined

Quarantined
  ├─ 文件 digest 不变 → 不再执行，使用 native baseline
  └─ 新 digest 验证成功 → ShadowWarmup
```

故障采样不沿用未重新验证的激进动作，而是使用当前遥测下的宿主保守 baseline。数据面不退出，QUIC 连接不重建。

## 8. 状态、热切换与单文件语义

### 8.1 状态模型

```text
decide(input, previous_state) → candidate, next_state
```

宿主按以下键持久化（一次 `decide` 覆盖全部方向，状态不按方向拆分）：

```text
(policy_id, state_schema, peer_id)
```

路径建议：

```text
<identity-parent>/autotune-wasm/<policy-id>/<state-schema>/<peer>.state
```

主键不使用 module digest：digest 每次 rebuild 都变，若按 digest 分目录，同 schema 的小版本升级会把学习历史全部丢掉。digest 只写进文件头作审计和 8.2 的兼容性判断。

文件包含版本、`policy_id`、`state_schema`、写入时的 module digest、CRC/digest、长度和 payload。继续复用 `deployment::atomic_write`。

落盘频率：内存中每 tick 更新，磁盘只在以下时机写——固定间隔（默认 60 s，可配置）、模块切换前、peer 断开、daemon 退出。禁止每秒写盘：64 KiB × peer 数 × 1 Hz 在路由器类闪存设备上是磨损问题。

### 8.2 升级规则

| 条件 | 状态处理 |
| --- | --- |
| `policy_id` + `state_schema` 相同 | 继续使用（digest 是否变化不影响） |
| `policy_id` 相同、`state_schema` 不同 | 从空状态启动；manifest 可声明 `state_schema_accepts[]` 以允许从列出的旧 schema 迁移（guest 自行在 `decide` 中识别并转换） |
| `policy_id` 不同 | 从空状态启动 |
| 状态超限、损坏或 guest 拒绝 | 隔离旧状态，从空状态启动并记录原因 |

V1 不允许 guest 任意读取其他模块、其他 peer 或反方向状态。

### 8.3 热切换

```text
发现文件变化
→ 读取到私有内存缓冲
→ 解析/验签/ABI 校验
→ 后台编译
→ 空输入自检和固定 fixture 自检
→ shadow warmup
→ 下一个 1 s sample boundary 原子切换
```

加载过程始终保留 active 的已验证 Component。坏文件只更新错误状态，不替换 last-known-good。

## 9. Node Egress Coordinator

### 9.1 两阶段裁决

每个 peer 的 WASM 首先输出：

```text
desired_bytes_per_second
minimum_bytes_per_second
priority
exploring
```

节点 actor 在同一 tick 汇总：

```text
peer candidates
→ minimum guarantee allocation
→ weighted excess allocation
→ exploration budget
→ total cap enforcement
→ per-peer assigned rate
```

随后合并：

```text
effective pacing cap = min(
    peer candidate cap,
    node assigned rate,
    configured node/peer cap,
    controller safety cap
)
```

### 9.2 不等待慢 peer

协调器采用 tick snapshot 和截止时间：

- 截止时间前返回的 candidate 进入本轮；
- 超时 peer 使用保守需求或上一轮受限需求；
- 不因为一个 guest 超时阻塞其他 peer；
- 新连接和无历史 peer 使用配置的最小公平份额；
- Control/Repair 硬优先级不由出口权重覆盖。

## 10. 文件与模块改造清单

### 10.1 新增 guest SDK、策略核心与 builtin guest crate

```text
crates/ironet-policy-sdk/          # WIT world + Rust guest 便利类型/定点运算
├─ Cargo.toml
├─ wit/ironet-policy.wit
└─ src/lib.rs

crates/ironet-policy-core/         # 单源两目标：learner/context/utility 纯逻辑
├─ Cargo.toml                      # no_std 友好、无 Tokio/QUIC/宿主类型
└─ src/lib.rs

crates/ironet-policy-builtin/      # 把 policy-core 包成 Component 的 guest crate
├─ Cargo.toml                      # crate-type = cdylib, target wasm32-unknown-unknown
├─ src/lib.rs
└─ builtin.wasm                    # 提交进仓库的构建产物（见下）

fixtures/policy/                   # 恶意/故障 guest 与签名 fixture
```

职责：

- SDK 提供 WIT world、Rust guest 便利类型和定点运算函数，不依赖 `ironet`、Tokio、QUIC 或宿主内部类型，自带最小 echo/conservative guest 测试 fixture。
- `ironet-policy-core` 是现有 `learner.rs`/`ContextKeyV2` 逻辑的搬迁目标，同一份源码既编译进 builtin guest，也在 Phase 0–1 以 native 形式运行用于生成 golden。`learner.rs` 大量使用 f64；单源两目标加 NaN canonicalization 是"逐样本 bit-exact 一致"门禁可达的前提，否则该门禁几乎不可能过。
- `builtin.wasm` 通过 `include_bytes!` 进入 `ironetd`。

构建链路（不能靠 `cargo build` 顺手交叉编译）：

- `scripts/build-policy-guest.sh`：固定 toolchain + `wasm32-unknown-unknown` target + `wasm-tools component new` + 嵌入 manifest，输出可复现的 `builtin.wasm`；
- 构建产物提交进仓库，CI 重新构建并断言 digest 与提交一致，不一致即失败；
- `flake.nix` devShell 加入 wasm32 target 和 `wasm-tools`；
- `build.rs` 不做交叉编译，只做 `include_bytes!` 与 manifest 校验；
- `scripts/check-v2-only.sh` 放行 `crates/ironet-policy-*` 和 `builtin.wasm`，继续禁止额外生产二进制。

### 10.2 重组策略模块

```text
src/protocol/v2/policy/
├─ mod.rs
├─ api.rs
├─ native.rs
├─ guardrails.rs
├─ transition.rs
├─ package.rs
├─ signature.rs
├─ runtime.rs
├─ state.rs
└─ status.rs
```

当前 `src/protocol/v2/policy.rs` 在迁移完成后删除。

### 10.3 其他改动

| 文件 | 改动 |
| --- | --- |
| `Cargo.toml` | 加入 policy SDK/core/builtin、Wasmtime（默认 Pulley，`cranelift` 可选 feature）、WASM parser 依赖和最小 features；签名复用已有 `ed25519-dalek`/`blake3` |
| `src/config.rs` | `policy`/`shadow_policy` 接受 `native`、`builtin` 或绝对 `.wasm` 路径；增加 `[autotune.wasm]` trust store、资源预算、state 落盘间隔配置并纳入 seal |
| `src/main.rs` | 增加 `ironet policy keygen/inspect/verify/sign/replay` |
| `src/protocol/v2/learner.rs` | 逻辑迁移到 `crates/ironet-policy-core`，宿主侧仅保留适配与 golden 测试 |
| `scripts/build-policy-guest.sh`、`flake.nix` | 可复现构建 `builtin.wasm`；devShell 提供 wasm32 target 与 `wasm-tools` |
| CI | 重建 `builtin.wasm` 并断言 digest 与仓库提交一致 |
| `src/v2_runtime.rs` | `tuner_loop` 接入 backend/executor/guardrails/egress，泛化 shadow evaluator |
| `src/protocol/v2/tuning.rs` | 拆分 telemetry filter、candidate、effective、transition |
| `src/protocol/v2/dataplane.rs` | 接收有效动作，拒绝候选动作直接进入数据面 |
| `src/status.rs` | 暴露 module、signer、digest、ABI、fault、fuel、clamp、state 指标 |
| `src/tui.rs` | 展示 live/shadow module 和最近 fault/clamp |
| `examples/autotune_replay.rs` | 加载 `.wasm` backend，支持 deterministic assert |
| `examples/autotune_train.rs` | 输出 guest 可嵌入的训练数据或生成 builtin guest 源数据 |
| `examples/autotune_promote.rs` | promotion 输入改为 module digest/signature/ABI |
| `scripts/check-v2-only.sh` | 允许新 policy 目录和 SDK crate，继续禁止额外生产二进制 |
| `config/example.toml`、`docs/配置参考.md` | 更新单文件策略配置和 trust 模型 |

## 11. 分阶段实施

### Phase 0：冻结 ABI 决策和测量基线（0.5–1 天）

#### 工作

- 记录当前 release binary 大小、冷启动时间、常驻内存和完整构建时间。
- 用 Pulley 与 Cranelift 两种 Wasmtime 配置各做一次 spike：记录二进制增量、空 Component 调用 p99、hot reload 编译时间；据此定 7.1 的默认后端。
- 用现有 replay fixture 记录当前 learner 策略逐样本输入/输出 golden（这是 Phase 2 参考 guest 的比对基线）。
- 冻结 `PolicyInputV1`、`CandidateActionV1`、`EffectiveActionV1` 单位、optional 语义和 TLV 扩展点。
- 冻结单文件 manifest/signature 规范（Ed25519、末尾签名段、顶层 only、防回滚）。
- 验证 `flake.nix`/CI 能以固定 toolchain 复现构建 `wasm32-unknown-unknown` Component。

#### 产物

- WIT 草案（含扩展袋）；
- ABI 字段表；
- 当前行为 golden；
- Pulley/Cranelift 体积与性能对比和选型结论；
- runtime 体积/性能基线。

#### 门禁

- 每个字段只有一个单位和方向语义；
- 明确哪些字段属于 policy、guardrail、transition 和 coordinator；
- 不存在 guest 可直接设置的硬上限字段；
- 扩展袋的 tag 注册、长度上限和忽略语义已写入 SDK 文档；
- 执行后端已选定并有数据支撑。

### Phase 1：动作契约与 native adapter（2–3 天）

#### 工作

- 引入 Candidate/Effective/ClampReport。
- 把 `learner.rs`/`ContextKeyV2` 纯逻辑搬进 `crates/ironet-policy-core`，以 native 形式接到 `PolicyBackend`（这一步的 native backend 仍含 learner，仅作过渡，用于生成与比对 golden；Phase 6 后 `native` 只保留保守规则）。
- 宿主 `UtilityEstimator` 输出纳入 `PolicyInputV1.previous_utility`。
- 拆分 `AutoTunerV2`，但不改变线上行为。
- 让 TX/RX/BBR 只接收有效动作。

#### 门禁

- native golden 逐样本一致；
- 现有 tuning/learner/runtime 单测全部通过；
- netns 基线无吞吐、延迟、FEC geometry 行为变化；
- 候选类型在编译层面不能直接传入 dataplane applier。

### Phase 2：WASM Component MVP（3–4 天）

#### 工作

- 新增 WIT 和 guest SDK；
- 接入 Wasmtime Component runtime；
- 编写与当前 builtin policy 等价的参考 guest；
- 首批开放 BBR preset、FEC、train、quantum、cover overhead；
- 实现显式 per-peer state。

#### 门禁

- 同一 fixture、同一 seed 下，`ironet-policy-core` 的 native 编译与 wasm32 编译逐样本 candidate/state 一致（单源两目标 + NaN canonicalization）；
- 1000 次调用结果完全确定；
- `builtin.wasm` 可由 `scripts/build-policy-guest.sh` 复现且 digest 与仓库一致；
- WASM shadow 不写任何 live action；
- 单次调用 p99、fuel 和 memory 在预算内；
- runtime worker 不出现在 BBR/QUIC 热路径火焰图中。

### Phase 3：单文件 package、签名和热切换（2–3 天）

#### 工作

- 实现 manifest/signature custom section；
- 增加 inspect/verify/sign CLI；
- 后台预编译和实例池；
- active/shadow last-known-good；
- 状态 schema、持久化和隔离。

#### 门禁

- 最终部署只复制一个 `.wasm`；
- 修改任意非签名字节会导致验证失败；
- 重复、超大、畸形 custom section 被拒绝；
- 坏文件、部分写入和签名错误不替换 active；
- 热切换不重建 QUIC，不产生一秒以上调优空洞。

### Phase 4：完整动作面与统一护栏（4–6 天）

#### 工作

- 开放完整 BBR 参数；
- 开放 Repair、TX、RX、reassembly 和 Cover profile；
- 集中实现所有跨字段 guardrail；
- 输出字段级 ClampReport；
- 保留 BBR3 控制器内部二次 clamp。

#### 门禁

- fuzz 任意 Candidate 都不能突破硬上限；
- 可靠 underlay 不能被 guest 强开 FEC；
- CPU/队列压力能关闭 parity/cover；
- RX 预算不受远端策略或 TX rate 强制扩大；
- latency queued 时 Bulk quantum 不能削弱严格通道；
- BBR 参数只在下一 packet-timed round 生效。

### Phase 5：Node Egress Coordinator（4–7 天）

#### 工作

- 增加节点 tick actor 和 peer demand snapshot；
- 实现 minimum guarantee、priority、weighted excess、exploration budget；
- 把 assigned rate 回馈给下一轮 WASM 输入；
- 覆盖 peer 加入、退出、超时和路径迁移。

#### 门禁

- 所有 peer assigned rate 总和不超过节点硬预算；
- 单 guest trap 不阻塞其他 peer；
- Control/Repair 优先级保持；
- 竞争流场景达到预设公平性门槛；
- 探索 peer 不得挤占其他 peer 的最低保障。

### Phase 6：灰度、晋升和删除迁移代码（3–5 天）

#### 工作

- 用现有 oracle/replay/netns matrix 运行 native vs WASM；
- shadow 观察至少一个完整动态矩阵周期；
- 按 promotion gate 晋升 builtin WASM；
- 更新配置、运维、开发和交接文档；
- 删除外部 JSON policy live loader 和永久双路径代码；
- 把 `native` backend 收缩为不含 learner 的保守规则，learner 只保留在 `ironet-policy-core` 并经 `builtin.wasm` 运行。

#### 门禁

- WASM-on 不低于当前 promotion 标准；
- trap/OOM/timeout/坏状态场景都有自动回退证据；
- 发布包包含 runtime、CLI、`native` fallback 和 `builtin.wasm`；
- 外部策略部署只要求 `.wasm`；
- 无未命名兼容 shim。

## 12. 测试计划

### 12.1 ABI 与 package

- WIT round-trip；
- v1 guest 对 v1 host；
- 不支持 major、缺少 export、错误类型签名；
- manifest 缺失、重复、超长、字段越界；
- signature 缺失、错误 signer、digest 不匹配；
- component 截断、附加垃圾、异常 section 顺序；
- capability 申请超出宿主能力。

### 12.2 恶意/故障 guest fixture

仓库至少保留：

```text
loop.wasm
fuel-burn.wasm
memory-grow.wasm
trap.wasm
oversized-state.wasm
invalid-enum.wasm
overflow-action.wasm
all-maximums.wasm
non-deterministic-attempt.wasm
```

断言：有界失败、宿主存活、转发继续、baseline 生效、fault 指标增加。

### 12.3 Guardrail 属性测试

对任意候选动作断言：

```text
effective within hard bounds
floor <= cap when cap != 0
FEC geometry valid
wire overhead within maximum
reliable underlay => FEC off
CPU/queue emergency dominates guest
receive memory <= local budget
cover <= remaining budget
node assigned sum <= node cap
```

### 12.4 Replay

- native 与参考 guest golden；
- 同输入、seed、state 得到同输出和 next_state；
- path epoch 变化清理正确状态；
- active/shadow 状态完全隔离；
- module upgrade 的 state schema 行为；
- recorder 可重放 candidate、clamp 和 effective 三层。

### 12.5 性能

至少记录：

```text
module validation time
compile time
first-call latency
steady-state p50/p95/p99 call latency
fuel per call
instance-pool hit rate
worker queue depth/drop
per-peer state bytes
daemon RSS delta
release binary size delta
build time delta
```

数据面验收继续使用现有 WAN、动态时间线、非对称链路、竞争流、FEC/Repair 和 perf 火焰图设施。

## 13. 可观测性

每个 peer 状态新增：

```text
policy_backend = native|wasm
policy_id
policy_version
module_digest
signer_id
abi_version
module_generation
state_schema/state_bytes
last_call_micros
fuel_consumed
faults_total
timeouts_total
quarantines_total
clamped_fields_total
last_clamp_reasons
candidate/effective action summary
shadow candidate/advantage
egress requested/assigned rate
```

Prometheus 指标避免以 peer/module digest 之外的任意 guest 字符串作为 label，防止高基数。详细诊断进入结构化日志和状态快照。

## 14. 配置迁移

目标配置：

```toml
[autotune]
mode = "shadow"
objective = "balanced"
memory = true
policy = "/etc/ironet/policy.wasm"        # native | builtin | 绝对 .wasm 路径
shadow_policy = "/etc/ironet/policy.next.wasm"

[autotune.wasm]
require_signature = true                   # 生产默认；为 false 时必须给出 digest_pins
maximum_module_bytes = 8388608
maximum_memory_bytes = 8388608
maximum_state_bytes = 65536
deadline_millis = 10
state_flush_interval_secs = 60

[[autotune.wasm.signers]]
signer_id = "ops-2026"
public_key = "ed25519:BASE32..."
minimum_policy_version = 3                 # 防回滚下限
# expires_at = "2027-01-01T00:00:00Z"      # 可选

# 开发模式替代方案（require_signature = false 时生效）
# digest_pins = ["blake3:..."]
```

迁移规则：

1. `native` 永久保留，表示宿主无 WASM 的保守 fallback；`builtin` 为默认值，表示编进二进制的 `policy.wasm`。
2. Phase 1–5 期间现有 JSON policy 可继续运行，用于对照和回滚。
3. 提供一次性 JSON → `ironet-policy-core` 内嵌数据生成工具，不在 runtime 永久维护 JSON-to-WASM 转译器。
4. Phase 6 后外部 `policy`/`shadow_policy` 只接受 `.wasm`；旧 JSON 配置给出明确迁移错误。
5. 配置仍需重新 seal；`[autotune.wasm.signers]`、`digest_pins`、策略路径都在 seal 范围内，不由 guest 修改。

## 15. 发布与回滚

### 15.1 发布顺序

```text
off/native baseline
→ WASM shadow
→ 小比例 peer on
→ 单节点全 peer on
→ 多节点灰度
→ 默认 WASM on（仅在 promotion 通过后）
```

### 15.2 自动回滚触发

- 连续 policy fault；
- p99 调用超过 deadline 门槛；
- candidate invalid/clamp 比率异常上升；
- utility、goodput、latency 或 residual loss 超过现有 promotion regression 门槛；
- controller generation 长时间 pending；
- node egress 分配违反公平性或最低保障；
- CPU/RSS 超过运行预算。

回滚只切换策略 backend/action，不重启 daemon、不重建 connection、不修改 wire capability。

## 16. 风险登记

| 风险 | 影响 | 控制措施 | 证伪/退出条件 |
| --- | --- | --- | --- |
| Wasmtime 增大二进制/RSS | 发布和小设备成本 | 最小 features、共享 Engine/Component、实例池、体积门禁 | 优化后仍超过产品预算，改为可选构建特性，但保持同一 WIT |
| ABI 过早冻结 | 后续字段难演进 | V1 仅慢环、明确单位、major version world | 首个完整 guest 无法表达现有动作即停止冻结 |
| guardrail 与 policy 再次混合 | 权限边界失效 | Candidate/Effective 类型隔离、集中 guardrail、属性测试 | 任意 candidate 能直接到数据面即阻止合并 |
| per-peer 调用扩展性 | peer 多时 worker 排队 | 无状态实例池、显式 state、有界队列、批量指标 | 目标 peer 数下 p99 超过 tick 预算则增加池或批处理 ABI V2 |
| 单文件签名规范自定义 | 验签歧义 | 排除单一签名段、拒绝重复、哈希精确原字节、fixture | 出现两种字节编码得到同一签名语义则重设格式版本 |
| 策略状态升级失败 | 学习历史丢失 | state schema、空状态可用、原子写、隔离旧状态 | guest 依赖不可恢复隐式状态则拒绝该 guest |
| 出口协调影响现有公平性 | 多 peer 退化 | 独立 phase、shadow allocation、竞争流 gate | 总吞吐或最低保障持续退化则保持 coordinator off |
| WIT record 不可扩展 | 每加一个遥测字段就 breaking | V1 内置 TLV 扩展袋 + 扩展 tag 声明 | 扩展袋承载不了语义变化时才发 major world |
| guest 自评 utility 污染 promotion | 晋升错误策略 | utility 只由宿主计算并喂给 guest | — |
| 两份 learner 长期并存 | 维护成本、行为漂移 | 单源 `ironet-policy-core`、Phase 6 收缩 native | Phase 6 门禁未过则 builtin 不晋升，但 native 仍不得扩张 |
| wasm32 交叉构建在 Nix/CI 失败 | 无法产出 builtin | 提交构建产物 + 脚本复现 + CI digest 校验 | 复现失败即阻止合并 |
| Pulley 调用延迟超预算 | 慢环超时 | Phase 0 spike 数据、`cranelift` feature 可切 | p99 超 7.3 预算则启用 Cranelift |
| 状态每秒写盘磨损闪存 | 小设备寿命 | 内存态 + 定时/事件落盘 | — |

## 17. 交付物

### 代码

- `ironet-policy-sdk` 和 WIT V1；
- native/WASM `PolicyBackend`；
- Wasmtime executor、resource limiter 和 instance pool；
- manifest/signature loader；
- guest 状态存储；
- centralized guardrails 和 transition controller；
- Node Egress Coordinator；
- CLI inspect/verify/sign；
- builtin/reference `policy.wasm` 构建目标。

### 测试资产

- native/WASM golden fixture；
- 恶意 guest fixture；
- signature/package fixture；
- guardrail property/fuzz target；
- replay、netns matrix、competition 和 asymmetric 结果；
- runtime/RSS/binary size 基线对比。

### 文档

- WIT ABI 参考；
- guest SDK 快速开始；
- 策略签名与 trust store 运维；
- 配置迁移；
- shadow、promotion、rollback 操作手册；
- 当前实现交接记录。

## 18. Definition of Done

全部满足才算完成：

1. 第三方策略只交付一个签名 `policy.wasm` 即可部署。
2. 策略文件不需要伴随 JSON、manifest、动态库或辅助进程。
3. live/shadow 都通过统一 WIT ABI 和 `PolicyBackend`。
4. WASM 无法直接访问网络、文件、TUN、QUIC、时钟、密钥或路由。
5. 任意 guest 输出都必须经过统一 guardrail，并生成 ClampReport。
6. trap、超时、OOM、坏签名、坏状态都不会中断基础转发。
7. BBR3 参数只在轮次边界刷新，Scheduler 的硬优先级保持不变。
8. 对端能力、本机内存和节点出口预算永远优先于 guest。
9. replay 在相同输入、seed、state 下完全确定。
10. shadow、热切换、last-known-good、quarantine 和自动回滚均有测试证据。
11. 完整性能矩阵达到现有 promotion gate，热路径火焰图无 WASM 调用。
12. 外部 JSON policy live loader 被删除；`native` 保守 fallback 保留且不含 learner；learner 只存在于 `ironet-policy-core` 一份。
13. promotion、shadow advantage、自动回滚使用的 utility 全部由宿主计算，guest 无法影响评分。
14. `builtin.wasm` 可由脚本复现构建，CI 校验 digest。

## 19. 第一批实施任务

按以下顺序开工，不先接 Wasmtime：

1. Phase 0 spike：Pulley vs Cranelift 体积/延迟数据；Nix/CI 复现构建一个空 `wasm32-unknown-unknown` Component。
2. 定义 `PolicyInputV1`（含 `previous_utility` 与 TLV 扩展袋）、`CandidateActionV1`、`EffectiveActionV1`、`ClampReportV1`。
3. 把 `learner.rs`/`ContextKeyV2` 搬进 `ironet-policy-core`，用这些类型包装并以 native 形式运行，证明行为不变。
4. 把 `AutoTunerV2` 的 policy、transition、guardrail 职责拆开；宿主 utility 纳入输入。
5. 让 dataplane API 只接受 `EffectiveActionV1`。
6. 冻结 WIT V1 并生成 `ironet-policy-core` native/wasm32 golden。
7. 再引入 Wasmtime 和单文件 package。

第一不可逆决策是 WIT V1 的字段语义与扩展袋约定；第一证明点不是"成功加载 WASM"，而是：

```text
同一段真实 telemetry replay
→ ironet-policy-core 的 native 编译 与 wasm32 Component 编译
→ 逐样本得到相同 candidate、state、clamp 和 effective action
```

该证明点通过后，剩余工作主要是扩大动作面、加固加载器和完成灰度门禁。
