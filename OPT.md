# 数据面性能与资源优化清单

功能必须保持不变：Priority 挤 Bulk、Bulk 分片可抢占、单健康直连不打 delivery tag、流租约、FEC 不进 DERP、有界队列与现有丢弃语义。

真零拷贝（TUN 页直达网卡）做不到：内核读、QUIC AEAD、`tun-rs` GSO 拆段、分片/FEC/重组都必然移动字节。目标是把用户态多余拷贝收到物理下限，并去掉结构性和资源浪费。

验收仍用 [docs/性能验证.md](docs/性能验证.md)。微基准覆盖解析 / 队列 / 选路 / 重组；下列 P0–P2 还要看 iperf 与多 peer 入站。

---

## P0 — 入站漏斗

全网 peer 共用一条深度 64 的 `inbound_packets`，一个 `inbound_to_router` 同时做策略、本机判断、TUN GRO、transit 分发。TUN 写入一堵，所有邻接的 QUIC `read_datagram` 一起停。

- [ ] 本机交付按 `flow_shard` 直接写对应 TUN 队列，不经全局 inbound 任务
- [ ] inbound 通道按 TUN 队列或 Router shard 切开，深度可仍浅
- [ ] 拆分后确认：策略拒绝、TTL 减一、delivery 聚合、trace 探针对账行为不变

## P1 — 用户态少拷贝

出站现在大约是 `to_vec` → 分片 `Vec` → `Envelope::encode` 再拷；入站镜像再加 virtio 头 `Vec`。单 datagram 包可以把用户态 payload memcpy 压到 0；分片/FEC/重组压到「只拷该拷的一次」。

- [ ] TUN 读：`recv_multiple` 使用 `BytesMut`，`offset` 预留 envelope + fragment + 可选 tag（约 28–40 字节）
- [ ] 单 datagram 出站：回头写头，`freeze()` 成 `Bytes` 交给 `send_datagram`，payload 不再 `to_vec`
- [ ] `Envelope::encode` 一次写出 magic + 头 + payload，禁止「先组 payload 再整包拷进 envelope」
- [ ] TUN 写：缓冲预留 `VIRTIO_NET_HDR_LEN`，GRO 原地写头，去掉 `send_batch` 里按包 `Vec` + `extend_from_slice`
- [ ] 入站单片：`decode` 的 `Bytes::slice` 传到 TUN，重组完整包不再 `to_vec`
- [ ] 分片超包：整包 `freeze` 一次；每片只组短头。不改变 64 KiB 超包在单写者调度器里可抢占的语义
- [ ] 读侧缓冲池：用完的 `BytesMut` 回收，避免每包堆分配
- [ ] 微基准增加「TUN→encode 整路径拷贝次数」；iperf 单流 / 64 KiB GSO 对比重构前后

## P2 — 内存预算

`MESH_BUFFER_POOL_BUDGET_BYTES`（64 MiB）被四套缓冲各自当进程上限，再按 `max_peers` 均分。mesh 关闭时每邻接理论上限约 96 MiB（队列 8 + repair 16 + 重组 32 + FEC 32 + QUIC 收 8）。TUN 读槽按 `128 × 65535 × 最多 8 队列` 常驻，约 67 MiB。

- [ ] 发送队列、重组、repair、FEC 解码共用一份进程级字节计数，而不是四套各 64 MiB
- [ ] mesh 关闭时也不按「每 peer 88 MiB payload」堆；两节点静态拓扑以单份 8 MiB 队列为默认 BDP 上限
- [ ] TUN 读槽按真实 GSO 需要分配，或「大量 2–4 KiB 槽 + 少量 64 KiB 槽」，不要每槽 64 KiB
- [ ] 评估把 `QUIC_RECEIVE_BUFFER_BYTES`（8 MiB/连接）收到与 RTT×容量相当；发送侧保持 8 KiB
- [ ] 用多邻接 soak 核对 RSS / 队列丢弃 / 重组驱逐，确认不是靠堆内存换吞吐

## P3 — 每包空转

不改变调度结果，只去掉不该按包付的税。

- [ ] 队列 `notify_one` 改为空→非空边沿触发；消费者在跑时不要每包唤醒
- [ ] `update_depth` 不要每包写 7 个观测原子；热路径只维护 packed `total`，观测降频展开
- [ ] 去掉 `sleep(50µs)` 聚合等待（Tokio 时间轮实际约 0–1 ms）；只 `try_pop` 已在队列里的小包
- [ ] FEC 是否走 DERP：读已有 `selected_path_transport` 原子，不要每个包 `connection.paths()`
- [ ] `connection()` 在 `connection_updates` 变更前缓存 `Connection`，避免每轮 `load_full` + clone
- [ ] `inbound_to_router` 用 `snapshot.local_prefixes.contains`，不要每包扫 `config.all_advertised_prefixes()`
- [ ] 同一 `recv_many` / 发送批次共用一个 `Instant`，不要每包 `Instant::now()`
- [ ] 分片包的 repair 插入改 `std::sync::Mutex`（或等价短临界区）；`RepairCache::get` 在 insert 时存 offset，查找时不要对每帧 `Envelope::decode`
- [ ] 小包延迟（ping p95、空队列突发首包）不得劣于改前

## P4 — Flow 表与选路热路径

每包一次 `HashMap` + SipHash；满 65 536 时 `make_room` 扫最老项。非直连路径每包拿 `route_estimates` 读锁。

- [ ] Flow 表改更快哈希（如 hashbrown + rustc-hash），或定长槽；查找/插入语义不变
- [ ] 满表驱逐改为时钟或环形扫描，避免偶发 O(n) 暂停
- [ ] 将 `(destination, first_hop)` 容量快照进 100 ms generation，transit 选路不再每包抢 `RwLock`
- [ ] `RouteDispatcher::send_batch` 复用按 shard 的 `Vec`，不要每批新分配
- [ ] 高并发流（1k / 65k）微基准与租约、idle TTL 单测保持绿

## P5 — FEC 与重组

编码正确，但按块重建编码器、按片填零、过期时全表重算字节。

- [ ] 连接期内复用 `ReedSolomonEncoder` / `ReedSolomonDecoder`，不要每个 block `new`
- [ ] 系统码 original 只包头；需要偶数 shard 时在预留尾空间 `resize`，不要 `vec![0; shard_bytes]` 再拷
- [ ] `original_payload` 对已有 `Bytes` 做 slice，不要 `copy_from_slice`
- [ ] `record_fragment`：已覆盖区间跳过拷贝；冲突只比重叠部分
- [ ] `Reassembler::expire` / `FecDecoder::expire` 用增减计数维护 `buffered_bytes`，不要全表 `sum`
- [ ] FEC 开关、DERP 禁用 FEC、乱序重组、repair 次数上限的现有测试保持绿

## P6 — 小项

收益小，顺手或与上面同一补丁一起做。

- [ ] `flow_shard` 对 IPv6 按 `u64` 块混合，减少逐字节 FNV
- [ ] `DeliverySource::allocate_session_id` 去掉每会话 blake3（冷路径；可用计数器 xor 节点 id）
- [ ] `run_flow_router` 热路径避免无谓的 `Arc<Peer>` clone，能借 snapshot 引用就借
- [ ] 微基准增加「N 个 peer 同时 inbound」的通道等待时间

---

## 明确不做

- [ ] ~~AF_XDP / DPDK / 绕过 iroh~~ 等于另一条数据面
- [ ] ~~TUN `splice` 进 UDP~~ 会丢掉 QUIC 与 overlay 头
- [ ] ~~为少拷贝关掉分片、FEC、batch、GRO~~ 功能与恢复能力会变
- [ ] ~~改 iroh/noq 让 datagram 收 `Buf` 链~~ 才能让分片头与 payload 完全免拼；不在本仓库范围
