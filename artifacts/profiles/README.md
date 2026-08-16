# p2 → wuwei-ws 运营商 IPv6 / 自适应 FEC 实测

测试日期：2026-08-16 UTC。方向均为 p2 上行、wuwei-ws 下行。

## 选路约束

- p2 源地址：`2409:8a00:24a0:7820:fd85:9ed0:3fde:d0ff`
- wuwei-ws 目的前缀：`2408:8207:18d3:2890::/64`
- 两端均配置 `excluded_underlay_prefixes = ["200::/7", ...]`
- ironet 状态显示 `selected_path_transport = direct`
- 实测远端均为 `ip:[2408:8207:18d3:2890:...]:4000`，没有经过 Yggdrasil

## 结果

| 网络状态 / 模式 | 接收吞吐 | 说明 |
| --- | ---: | --- |
| 严重丢包期 underlay TCP | 1.40 Mbit/s | 公网 IPv6 直连，601 retransmits |
| 严重丢包期 overlay，固定 `8+4@100ms` | 1.08 Mbit/s | 旧的固定 FEC 基线 |
| 严重丢包期 overlay，自动 FEC | 20.0 Mbit/s | 自动在 3.50% QUIC loss 时启动；从 `16+3@19ms` 收敛到 `16+2` |
| 健康期 underlay TCP | 85.0 Mbit/s | 同一运营商 IPv6，1168 retransmits |
| 健康期 overlay，自动 FEC | 46.2 Mbit/s | 路径 loss 约 0.21%，FEC 正确保持关闭 |

严重丢包期链路具有明显时变性；自动策略按每个发送方向独立决策，因此同一配置可在链路恶化时启用并选型，在健康路径上保持零 FEC 开销。

## Profile

`p2-wuwei-auto-tuned-v2.svg` 对应健康期 30 秒 overlay iperf3，二进制带 debuginfo，`perf record -F 199 -g` 采集，无 lost samples。

主要 CPU 符号：

- ChaCha20-Poly1305 AVX2 seal：6.60%
- `memcpy`：4.42%
- QUIC `Connection::poll_transmit`：1.81%
- QUIC `Connection::populate_packet`：1.32%
- 内核 IOMMU/cache flush：1.30%

该 profile 没有显示锁或状态机成为主热点；当前健康链路的主要数据面成本是加密、内存复制和 QUIC 发包。
