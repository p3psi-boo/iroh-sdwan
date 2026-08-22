# ironet-policy-sdk

`ironet-policy-sdk` 是 `ironet:policy/policy@1.0.0` guest 的 Rust 便利层。
WIT 唯一来源是 `../ironet-policy-abi/wit/ironet-policy.wit`，SDK 的
`wit_bindgen::generate!` 用 `path` 引用它，不复制接口文件。

## 写一个 guest

guest 只实现 ABI 类型上的 `GuestPolicy`，状态通过 `input.state` 和
`PolicyOutputV1::next_state` 往返：

```rust
#![deny(unsafe_code)]

use ironet_policy_abi::{CandidateActionV1, PolicyFaultV1, PolicyInputV1, PolicyOutputV1};
use ironet_policy_sdk::GuestPolicy;

struct Conservative;

impl GuestPolicy for Conservative {
    fn decide(input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        Ok(PolicyOutputV1 {
            candidate: CandidateActionV1::default(),
            next_state: input.state.clone(),
            ..PolicyOutputV1::default()
        })
    }
}

ironet_policy_sdk::export_policy!(Conservative);
```

`export_policy!` 把 SDK 的 `GuestPolicy` 适配到生成的 WIT `Guest` trait，
并将输入长度错误映射为 `AbiMismatch`、guest 输出形状/状态错误映射为
`InvalidOutput` 或 `StateTooLarge`。需要直接使用 canonical ABI 类型时可用
`ironet_policy_sdk::bindings::ironet::policy::types`；ABI 类型与生成类型的
双向 `From`/`TryFrom` 实现在 `convert` 模块中，诊断 label 因 WIT 是
`list<u8>` 别名，使用公开的 `label_to_wit`/`label_from_wit` 辅助函数。

## 构建与打包

guest 使用无 WASI 的 `wasm32-unknown-unknown`：

```bash
nix develop -c cargo check -p ironet-policy-sdk --target wasm32-unknown-unknown
nix develop -c cargo build -p my-policy --release --target wasm32-unknown-unknown
nix develop -c wasm-tools component new \
    target/wasm32-unknown-unknown/release/my_policy.wasm \
    -o my-policy.component.wasm
```

仓库 builtin、echo 和 conservative guest 的完整可复现构建使用：

```bash
nix develop -c scripts/build-policy-guest.sh
nix develop -c scripts/build-policy-guest.sh --check
```

脚本将 `ironet.manifest.v1` custom section 嵌入 component，生成未签名的
`crates/ironet-policy-builtin/builtin.wasm` 以及
`builtin.wasm.blake3`。该 builtin 文件是与 daemon in-process core bit-exact
的 guest fixture，也是可分发外部组件模板；daemon 默认不加载它。需要显式部署
为外部 `.wasm` 时，用宿主 CLI 把 manifest 保留在包中并签名：

```bash
ironet policy sign --key SIGNING_KEY \
    crates/ironet-policy-builtin/builtin.wasm --output policy.wasm
```

签名段必须是最后一个 section；签名、信任根和 digest pin 由宿主部署配置
管理，guest SDK 不读取文件、环境变量、时钟或随机源。

## 定点工具

`ironet_policy_sdk::fixed` 提供 `ratio_to_milli`、`ratio_to_ppm`、
`milli_to_ppm`、`ppm_to_milli_round`、`mul_div_u64` 以及 `i32/u64`
饱和加减。所有换算使用整数和明确的四舍五入/截断规则，不引入浮点。

工作区 release profile 已设置 LTO、单 codegen unit 和 strip；guest 构建
脚本额外固定 `opt-level=s`、`panic=abort`、非增量编译和
`SOURCE_DATE_EPOCH`。guest 实现不得依赖 `std::time`、环境变量、I/O 或
宿主随机数；需要探索时使用 `PolicyInputV1::deterministic_seed`。
