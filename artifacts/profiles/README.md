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
| 统一自动调优 underlay TCP | 102 Mbit/s | 与 overlay 匹配到同一 `2408:...:6bf2...` 目的地址，3077 retransmits |
| 统一自动调优 overlay | 73.3 Mbit/s | adaptive pacing/在途窗口/quantum + 自动 `16+4@15ms` FEC，841 retransmits |

严重丢包期链路具有明显时变性；自动策略按每个发送方向独立决策，因此同一配置可在链路恶化时启用并选型，在健康路径上保持零 FEC 开销。

统一自动调优轮次在配置中移除了手工 congestion controller、adaptive 速率、passthrough 窗口/速率和 pacing quantum 参数。运行时从下限开始探测，根据 ACK delivery rate 与 RTT inflation 动态计算 pacing，并从 BDP 生成在途窗口和发送 quantum。最终路径遥测为 RTT 7.06 ms、jitter 0.34 ms、loss 3.59%、在途窗口 740000 bytes，overlay/underlay 效率为 **71.9%**。

## Profile

`p2-wuwei-auto-tuned-v2.svg` 对应健康期 30 秒 overlay iperf3，二进制带 debuginfo，`perf record -F 199 -g` 采集，无 lost samples。

主要 CPU 符号：

- ChaCha20-Poly1305 AVX2 seal：6.60%
- `memcpy`：4.42%
- QUIC `Connection::poll_transmit`：1.81%
- QUIC `Connection::populate_packet`：1.32%
- 内核 IOMMU/cache flush：1.30%

该 profile 没有显示锁或状态机成为主热点；当前健康链路的主要数据面成本是加密、内存复制和 QUIC 发包。

`p2-wuwei-unified-tune-v2.svg` 对应统一自动调优后的 30 秒 overlay iperf3，`perf record -F 99 -g` 采集 2429 个 samples、无 lost samples。该轮为精简生产二进制，用来验证热点类型与采样完整性；内核侧最大的可见热点是 `clflush_cache_range` 2.11%，未出现锁竞争热点。

## p2 → p6 自动控制器验证

同一方向、同一时段、4 并发 TCP 的 20 秒对照：

| 路径 | 接收吞吐 | TCP retransmits |
| --- | ---: | ---: |
| 运营商 IPv6 underlay | 97.3 Mbit/s | 5267 |
| ironet overlay | 61.3 Mbit/s | 860 |

overlay/underlay 效率为 **63.0%**。该时段 QUIC 短时丢包峰值从 6.05% 上升到 17.56%，发送端自动从 `16+3` 升到 `16+7@15ms` FEC。按 `16/23` 的有效载荷比估算，该 profile 的线速上限约为 67.7 Mbit/s，实测 61.3 Mbit/s 达到该上限的约 90.5%。因此这轮的首要限制是真实广域网丢包所需的冗余，不是 adaptive pacing 窗口不足。

带符号的双端 profile 均为 `perf record -e task-clock -F 99 --call-graph dwarf,8192`，无 lost samples：

- `p2-p6-auto-controller-symbols-p2.svg`：ChaCha20-Poly1305 AVX2 seal 10.89%，`memcpy` 5.21%，IOMMU cache flush 2.55%。
- `p2-p6-auto-controller-symbols-p6.svg`：内核 wakeup spin unlock 5.53%，ChaCha open SSE4.1 4.67%，`memcpy` 3.69%，virtio `iowrite16` 3.32%。

应用层没有出现状态机或互斥锁主热点；下一阶段的性能优先级是加密批处理/减少复制、降低接收端 wakeup 频率，以及在保持恢复率的前提下继续收紧 FEC parity。
