//! Phase 0 runtime spike host.
//!
//! Modes:
//!   run <component.wasm> [--target pulley64] [--iters N] [--input-bytes N]   (needs `cranelift`)
//!   precompile <component.wasm> <out.cwasm> [--target pulley64]             (needs `cranelift`)
//!   load <file.cwasm> [--target pulley64] [--iters N] [--input-bytes N]      (any build)
use std::time::{Duration, Instant};

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

wasmtime::component::bindgen!({
    path: "../wit",
    world: "policy",
});

struct HostState {
    limits: StoreLimits,
}

fn build_config(target: Option<&str>) -> Config {
    let mut config = Config::new();
    // --- determinism (plan 7.3.1) ---
    config.wasm_relaxed_simd(false);
    config.wasm_simd(false);
    // NOTE: `wasm_threads`, `wasm_gc`, `wasm_function_references`, `wasm_exceptions`,
    // `wasm_reference_types` only exist when the `threads` / `gc` cargo features are
    // enabled; with them off those proposals are statically disabled (WasmFeatures::THREADS /
    // GC_TYPES are set from cfg!(feature = ...)).
    config.wasm_memory64(false);
    config.wasm_multi_memory(false);
    config.wasm_tail_call(false);
    config.wasm_stack_switching(false);
    config.wasm_custom_page_sizes(false);
    config.wasm_wide_arithmetic(false);
    config.wasm_component_model(true);
    #[cfg(feature = "cranelift")]
    {
        config.cranelift_nan_canonicalization(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
    }
    // --- resource control (plan 7.3) ---
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.max_wasm_stack(512 * 1024);
    // Linear memory: hard cap 8 MiB; reserve 8 MiB of address space, no guard pages
    // beyond what's needed (keeps virtual footprint small per Store).
    config.memory_reservation(8 << 20);
    config.memory_reservation_for_growth(0);
    config.memory_guard_size(64 << 10);
    config.memory_may_move(false);
    config.memory_init_cow(true);
    config.wasm_backtrace_max_frames(None); // `backtrace` feature is off anyway
    config.native_unwind_info(false);
    config.generate_address_map(false);
    if let Some(t) = target {
        config.target(t).expect("unsupported target");
    }
    config
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn make_input(bytes: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes);
    let mut i = 0u64;
    while v.len() + 16 <= bytes {
        let rtt = 20.0 + (i % 17) as f64 * 3.5;
        let loss = ((i * 7) % 100) as f64 / 1000.0;
        v.extend_from_slice(&rtt.to_le_bytes());
        v.extend_from_slice(&loss.to_le_bytes());
        i += 1;
    }
    v.resize(bytes, 0);
    v
}

fn rss_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn new_store(engine: &Engine) -> Store<HostState> {
    let limits = StoreLimitsBuilder::new()
        .memory_size(8 << 20)
        .instances(1)
        .memories(1)
        .tables(1)
        .table_elements(10_000)
        .trap_on_grow_failure(false)
        .build();
    let mut store = Store::new(engine, HostState { limits });
    store.limiter(|s| &mut s.limits);
    store
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: see source");
        std::process::exit(2);
    }
    let mode = args[1].as_str();
    let file = args[2].as_str();
    let mut target: Option<&str> = None;
    let mut iters = 1000usize;
    let mut input_bytes = 1024usize;
    let mut out: Option<&str> = None;
    let mut i = 3;
    if mode == "precompile" {
        out = Some(args[3].as_str());
        i = 4;
    }
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                target = Some(args[i + 1].as_str());
                i += 2;
            }
            "--iters" => {
                iters = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--input-bytes" => {
                input_bytes = args[i + 1].parse().unwrap();
                i += 2;
            }
            other => panic!("unknown arg {other}"),
        }
    }

    let build = format!(
        "features: cranelift={} pulley={}",
        cfg!(feature = "cranelift"),
        cfg!(feature = "pulley")
    );
    let rss0 = rss_kib();
    let t0 = Instant::now();
    let config = build_config(target);
    let engine = Engine::new(&config).expect("engine");
    let t_engine = t0.elapsed();
    println!("build: {build}");
    println!("mode: {mode} file: {file} target: {} ", target.unwrap_or("host"));
    println!("engine_new: {:?}", t_engine);

    let bytes = std::fs::read(file).expect("read file");
    println!("input_file_bytes: {}", bytes.len());

    if mode == "precompile" {
        #[cfg(feature = "cranelift")]
        {
            let t = Instant::now();
            let cw = engine.precompile_component(&bytes).expect("precompile");
            let dt = t.elapsed();
            std::fs::write(out.unwrap(), &cw).unwrap();
            println!("precompile_time: {:?}", dt);
            println!("cwasm_bytes: {}", cw.len());
            return;
        }
        #[cfg(not(feature = "cranelift"))]
        {
            let _ = out;
            panic!("precompile requires the cranelift feature");
        }
    }

    // --- compile / load ---
    let t = Instant::now();
    let component = match mode {
        "run" => {
            #[cfg(feature = "cranelift")]
            {
                Component::new(&engine, &bytes).expect("compile component")
            }
            #[cfg(not(feature = "cranelift"))]
            {
                panic!("run (runtime compile) requires the cranelift feature; use load with a .cwasm")
            }
        }
        "load" => unsafe { Component::deserialize(&engine, &bytes).expect("deserialize") },
        _ => panic!("unknown mode"),
    };
    let t_compile = t.elapsed();
    println!("compile_or_load_time: {:?}", t_compile);
    let rss1 = rss_kib();

    // Epoch ticker: 10 ms ticks; each call gets deadline = 2 ticks (10–20 ms wall).
    {
        let engine = engine.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(10));
            engine.increment_epoch();
        });
    }

    let linker: Linker<HostState> = Linker::new(&engine);

    // --- instantiate timing (fresh Store each time) ---
    let mut inst_times = Vec::with_capacity(100);
    for _ in 0..100 {
        let mut store = new_store(&engine);
        store.set_fuel(1_000_000_000).unwrap();
        store.set_epoch_deadline(2);
        let t = Instant::now();
        let _p = Policy::instantiate(&mut store, &component, &linker).expect("instantiate");
        inst_times.push(t.elapsed());
    }
    inst_times.sort();
    println!(
        "instantiate: p50={:?} p99={:?} max={:?}",
        percentile(&inst_times, 0.5),
        percentile(&inst_times, 0.99),
        percentile(&inst_times, 1.0)
    );

    // --- call timing on a reused Store/instance ---
    let mut store = new_store(&engine);
    store.set_fuel(1_000_000_000).unwrap();
    store.set_epoch_deadline(2);
    let policy = Policy::instantiate(&mut store, &component, &linker).expect("instantiate");
    let input = make_input(input_bytes);

    // first call (includes lazy init, e.g. table/func init)
    let t = Instant::now();
    let out0 = policy.call_decide(&mut store, &input).expect("call");
    let t_first = t.elapsed();
    println!("first_call: {:?} out_len={}", t_first, out0.len());

    // warmup
    for _ in 0..100 {
        store.set_epoch_deadline(2);
        policy.call_decide(&mut store, &input).unwrap();
    }

    let mut lat = Vec::with_capacity(iters);
    let mut fuels = Vec::with_capacity(iters);
    let mut checksum = 0u64;
    for _ in 0..iters {
        store.set_fuel(1_000_000_000).unwrap();
        store.set_epoch_deadline(2);
        let f0 = store.get_fuel().unwrap();
        let t = Instant::now();
        let out = policy.call_decide(&mut store, &input).expect("call");
        let dt = t.elapsed();
        let f1 = store.get_fuel().unwrap();
        lat.push(dt);
        fuels.push(f0 - f1);
        checksum = checksum.wrapping_add(out.iter().map(|b| *b as u64).sum::<u64>());
    }
    lat.sort();
    fuels.sort();
    println!(
        "call({} iters, input {} B): p50={:?} p90={:?} p99={:?} max={:?}",
        iters,
        input_bytes,
        percentile(&lat, 0.5),
        percentile(&lat, 0.9),
        percentile(&lat, 0.99),
        percentile(&lat, 1.0)
    );
    println!(
        "fuel_per_call: min={} p50={} p99={} max={}",
        fuels[0],
        fuels[fuels.len() / 2],
        fuels[((fuels.len() - 1) as f64 * 0.99) as usize],
        fuels[fuels.len() - 1]
    );
    println!("checksum: {checksum}");
    let rss2 = rss_kib();
    println!("rss_kib: start={rss0} after_load={rss1} end={rss2}");
    // Print the deterministic output for cross-backend comparison.
    println!("out0_hex: {}", out0.iter().map(|b| format!("{b:02x}")).collect::<String>());
}
