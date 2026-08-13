# Ironet Protocol V1

V1 是 Ironet 的首个正式协议代际。数据面 ALPN 派生自 `ironet/ip/1`；
所有在 Ironet 品牌确立前产生的实验协议使用不同 ALPN，不能被误认为兼容节点。
当前实现的协议版本是 **1.0**（major `1`、minor `0`）。

## 分层

1. **传输层**：QUIC/TLS 认证 iroh `EndpointId`。
2. **会话层**：客户端发送 `Hello`，服务端返回 `HelloAck`，客户端在可靠流上以 `Ready` 提交完整 transcript。
3. **特性层**：每项特性具有稳定数字 ID 和独立版本范围。必要特性不兼容时关闭连接；未知可选特性不进入协商结果。
4. **数据层**：每个应用数据报以统一 `IRN1` envelope 开头，并携带稳定消息类型。头长度保留有限扩展空间；未知消息类型在解析载荷前丢弃。
5. **目录和路由层**：`NodeRecord`、`RouteOrigin` 与 `RoutePath` 是独立模型；数字属性表可以保留核心路由器尚未理解的扩展字节。

## 会话认证

握手除 TLS 端点身份外，还证明双方持有共享的网络成员密钥。证明覆盖双方身份和新鲜 nonce。
配置 pairwise private link 时，会话还要使用其 `auth_key` 和 link ID 生成第二份证明。
数据报和控制消息限制取双方声明值的较小者。

## 与接入方式无关的中转

`attachment = "none"` 跳过 TUN 创建、Linux 路由配置及清理。数据包仍经 QUIC 进入，
通过源/目的策略检查、递减 IP hop limit、由同一个用户态 FlowRouter 选路，再发往下一 peer。
纯中转节点不拥有 overlay 前缀，并要求 `routing.transit_enabled = true`。

## Pairwise private link

`[[links]]` 将节点身份与传输路径分开：

- `remote_addresses` 与 `local_bind` 是本地 pairwise 状态，不进入 NodeRecord/Presence gossip；
- `active`、`passive` 和 `auto` 定义连接发起权；
- private link 是排他的，不使用 discovery、relay、DERP、观察候选或公网地址回退；
- 选中的 QUIC 路径必须匹配配置的远端 locator、属于 IP 路径，并同时落在本地与远端正向前缀 allowlist 中；迁移出约束范围会关闭连接；
- V1 会话必须证明持有 32 字节 pairwise secret。

## 稳定性规则

- 只有不兼容的 framing 或安全模型变化才提升协议 major 并更换 ALPN；
- 新行为优先通过可选 feature 或新 envelope message type 引入，不静默改变既有消息语义；
- 限制通过会话协商，不从程序构建版本推断；
- 保留字段必须为零；未协商对应 feature 的 peer 将扩展字段视为有限长度的 opaque bytes；
- V2 出现前，捕获的 V1 fixtures 和 mixed-minor 协商测试都是发布门禁。
