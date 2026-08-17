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

## p2 → wuwei-ws 批处理、零复制与低冗余 FEC 验收

测试日期：2026-08-17 UTC。发送端为 p2，接收端为 wuwei-ws；underlay 与
overlay 均使用 4 条 TCP 流、30 秒。状态快照确认 overlay 的 QUIC underlay 为
`[2408:8207:18d3:2890:6bf2:7c7c:82bb:227a]:4000`，transport 为 `direct`，没有
使用 `200::/7` Yggdrasil 地址。

| 路径 | 接收吞吐 | TCP retransmits | 说明 |
| --- | ---: | ---: | --- |
| 运营商 IPv6 underlay | 101.9 Mbit/s | 7,991 | `p2-wuwei-batch-zero-copy-underlay.json` |
| ironet overlay（生产二进制） | 67.5 Mbit/s | 1,519 | `p2-wuwei-batch-zero-copy-overlay.json` |
| ironet overlay（带符号 profile） | 66.5 Mbit/s | 1,533 | `p2-wuwei-batch-zero-copy-symbols-overlay.json` |

生产二进制的 overlay/underlay 效率为 **66.2%**。该轮不是健康链路：p2 的
QUIC 发送计数在测试区间增加 391,623 个 datagram，其中 71,885 个被标记丢失；
结束时 loss EWMA 为 15.26%、RTT 7.01 ms、jitter 4.10 ms。自动 FEC 收敛到
`16+5@15ms`；旧的 1.8 倍固定余量在相同损失附近会选择 6–7 个恢复分片。
`16/21` 的编码有效载荷上限对应约 77.6 Mbit/s，实测达到该上限的约 87%。

本轮实现同时验证了：

- 小包按实时 frame ceiling 在 QUIC 加密前聚合，一个 AEAD packet 可承载多个内层包；
- FEC systematic wire frame 与 Reed-Solomon 原始 shard 共享同一 `Bytes` backing，发送端只复制一次；
- 接收端保存 QUIC datagram slice，正常 systematic delivery 不扩容、不补零；只有实际恢复丢失块时才构造 padded shard；
- 每次 QUIC 唤醒最多同步排空 64 个已缓冲 datagram，并按 flow owner 使用 `reserve_many` 合并 ingress 通知；
- FEC 冗余使用 1.2–1.4 倍实时预期损失，并只在 loss ≥ 3% 时增加 safety shard。

双端 profile 均使用 `perf record -e task-clock -F 99 --call-graph dwarf,8192`，
lost samples 为 0：

- `p2-wuwei-batch-zero-copy-symbols-p2.svg`：ChaCha20-Poly1305 AVX2 seal 9.00%，`memcpy` 5.83%，QUIC `populate_packet` 1.06%；
- `p2-wuwei-batch-zero-copy-symbols-wuwei.svg`：`memcpy` 6.69%，ChaCha20-Poly1305 AVX2 open 6.41%，`RecvState::poll_socket` 1.67%；
- 接收端旧 profile 中 5.53% 的 wakeup spin unlock 已不再是主要热点；调用栈中没有 routine `expand_original`，按需补零路径只在真实 FEC 恢复时执行。

因此当前主要剩余成本已经收敛到 QUIC 每包 AEAD、内核 UDP/TUN copy 与通用
`memcpy`，而不是应用状态机、锁或逐 datagram 接收唤醒。

## p2 → wuwei-ws 密码套件自动择优、FEC v2 feedback 与复制归因

测试日期：2026-08-17 UTC。两端均通过运营商 IPv6 直连；验收状态中的远端地址
位于 `2408:8207:18d3:2890::/64`，没有使用 `200::/7` Yggdrasil overlay。
`udp_segmentation_offload = "auto"` 的真实双 segment 出口探测在两端通过并自动
启用 GSO。启动基准在 p2 测得 ChaCha/AES-256 为 11.91/3.72 ms，在 wuwei-ws
测得 4.74/1.72 ms，因此双方自动优先 AES-256-GCM；同一版本部署到 p6 后则根据
该主机实测保留 ChaCha，证明选择是逐主机完成而非编译时固定。

| 路径 | 接收吞吐 | TCP retransmits | 说明 |
| --- | ---: | ---: | --- |
| 运营商 IPv6 underlay | 101.888 Mbit/s | 7,719 | `p2-wuwei-crypto-auto-fec-feedback-underlay.json` |
| ironet overlay（带符号、双端 profile） | 68.172 Mbit/s | 2,165 | `p2-wuwei-crypto-auto-fec-feedback-profile-overlay.json` |
| ironet overlay（精简生产二进制） | 69.750 Mbit/s | 1,828 | `p2-wuwei-crypto-auto-fec-feedback-overlay.json` |

生产二进制的 overlay/underlay 效率为 **68.46%**；相对上一轮相同 underlay
约 101.9 Mbit/s 时的 67.5 Mbit/s / 66.2%，overlay 吞吐提高 **3.3%**，效率
提高 **2.3 个百分点**。最终生产测试结束时 p2 的 loss EWMA 为 7.89%，FEC
收敛到 `16+3@15ms`。该轮发送 62,248 个 recovery shard，接收端观察到 51,128
个，实际恢复 144 个数据 shard；累计有效收益仅为已发送 parity 的 0.23%。FEC
v2 feedback 因而移除低收益的安全余量，同时仍受 EWMA 平均丢包下限约束；测试
全程两端 `frame_drops` 保持 0。

双端火焰图使用 `perf record -e task-clock -F 99 --call-graph dwarf,8192`，lost
samples 均为 0：

- `p2-wuwei-crypto-auto-fec-feedback-p2.svg`：AES-GCM VAES/AVX2 seal 2.44%，上一轮 ChaCha seal 为 9.00%；`memcpy` 8.41%，没有状态机或锁竞争主热点；
- `p2-wuwei-crypto-auto-fec-feedback-wuwei.svg`：AES-GCM VAES/AVX2 open 0.95%，上一轮 ChaCha open 为 6.41%；`memcpy` 5.34%；
- p2 采集期 task-clock 为 14.90 秒/47 秒（约 31.7% 单核），上一轮为 11.44 秒/35 秒（约 32.7% 单核）；加密成本下降后并未把热点转移到锁或状态机。

新增计数把 profile 中的 `memcpy` 还原到数据面阶段。40 秒 profile 区间内，p2
的 jumbo 分片一次复制 483.53 MB、FEC systematic/recovery 构造复制 532.99 MB；
wuwei-ws 仅在真实恢复时产生 1.79 MB FEC decode copy，必需的 jumbo 重组复制
394.45 MB，TUN fallback copy 仅 1.66 MB。下一步若继续降低 `memcpy`，边界已经
明确为 jumbo 重组和内核 UDP/TUN 交付，而不是再删除应用层锁或状态机。
