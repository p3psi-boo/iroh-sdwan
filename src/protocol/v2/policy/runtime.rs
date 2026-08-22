//! Wasmtime Component runtime for policy ABI V1.
//!
//! The runtime deliberately keeps all guest state in the ABI records.  A
//! compiled component is shareable, while a store and its instance belong to
//! one call at a time and are discarded after a Wasmtime trap or resource
//! failure.  No WASI imports are linked into the policy world.

use std::{
    collections::HashMap,
    fmt,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use super::{
    api::{
        Bbr3PresetV1, BbrCandidateV1, BbrEffectiveV1, CandidateActionV1, CoverCandidateV1,
        CoverEffectiveV1, CoverProfileV1, EffectiveActionViewV1, EgressAllocationViewV1,
        EgressRequestV1, FecCandidateV1, FecEffectiveV1, FecPresetFamilyV1, HostCapabilitiesV1,
        HostLimitsV1, HostUtilityV1, PathReliabilityV1, PolicyBackend, PolicyBackendKindV1,
        PolicyDecisionKindV1, PolicyDiagnosticsV1, PolicyExtensionV1, PolicyFaultV1,
        PolicyIdentityV1, PolicyInputV1, PolicyLabelV1, PolicyOutputV1, PolicyTelemetryV1,
        ProtectionResponsibilityV1, RepairCandidateV1, RepairEffectiveV1, RepairWaitPolicyV1,
        RxCandidateV1, RxEffectiveV1, SchedulerCandidateV1, SchedulerEffectiveV1,
        SchedulerPresetHintV1, TxCandidateV1, TxEffectiveV1,
    },
    package::{POLICY_ABI_WORLD_V1, PackageLimits, PolicyManifestV1, PolicyPackage},
    signature::TrustStoreV1,
    status::PolicyRuntimeStatusV1,
};
use crate::config::AutotuneWasmConfig;

wasmtime::component::bindgen!({
    path: "crates/ironet-policy-abi/wit",
    world: "policy",
});

use self::ironet::policy::types as wit;

/// Initial fuel budget used by fixtures and by manifests that request the
/// normal builtin budget.  The manifest is still a request: the host caps it
/// at [`MAXIMUM_FUEL_BUDGET`].
pub const DEFAULT_FUEL_BUDGET: u64 = 1_000_000;
/// Prevent a manifest from turning one slow policy tick into an unbounded
/// deterministic computation.
pub const MAXIMUM_FUEL_BUDGET: u64 = 10_000_000;
/// The ticker granularity.  A deadline is expressed in these epoch ticks.
pub const EPOCH_TICK: Duration = Duration::from_millis(1);
/// Maximum number of compiled components retained by one engine.
pub const DEFAULT_COMPONENT_CACHE_CAPACITY: usize = 32;
/// Number of stores retained by a pool when the caller does not specify one.
pub const DEFAULT_STORE_POOL_CAPACITY: usize = 1;
/// Component-model records have a fixed canonical area; this headroom covers
/// scalar fields and list descriptors before variable payloads are counted.
const INPUT_FIXED_OVERHEAD_BYTES: usize = 2 * 1024;
const OUTPUT_FIXED_OVERHEAD_BYTES: usize = 2 * 1024;

/// The committed builtin policy component and its BLAKE3 sidecar, embedded
/// at compile time. Rebuild both with `scripts/build-policy-guest.sh` when
/// the guest or `ironet-policy-core` changes; the package tests pin the pair.
const BUILTIN_WASM_V1: &[u8] =
    include_bytes!("../../../../crates/ironet-policy-builtin/builtin.wasm");
const BUILTIN_WASM_BLAKE3_V1: &str =
    include_str!("../../../../crates/ironet-policy-builtin/builtin.wasm.blake3");

/// Shared Wasmtime engine, component cache and epoch ticker.
#[derive(Clone)]
pub struct PolicyEngine {
    inner: Arc<PolicyEngineInner>,
}

struct PolicyEngineInner {
    engine: Engine,
    components: Mutex<HashMap<[u8; 32], Arc<Component>>>,
    component_cache_capacity: usize,
    ticker_stop: Arc<AtomicBool>,
    ticker: Mutex<Option<JoinHandle<()>>>,
}

impl PolicyEngine {
    /// Builds the deterministic Pulley-targeted engine selected by the Phase 0
    /// spike.
    pub fn new() -> Self {
        Self::try_new().expect("building the policy Wasmtime engine")
    }

    /// Fallible constructor useful to callers that do not want engine setup to
    /// panic during daemon startup.
    pub fn try_new() -> Result<Self> {
        let mut config = Config::new();
        configure_engine(&mut config)?;
        let engine = Engine::new(&config)
            .map_err(|error| anyhow!("creating policy Wasmtime engine: {error}"))?;
        Ok(Self::from_engine(engine, DEFAULT_COMPONENT_CACHE_CAPACITY))
    }

    /// Creates an engine wrapper from an already configured Wasmtime engine.
    /// This is primarily useful for embedding and deterministic runtime tests.
    pub fn from_engine(engine: Engine, component_cache_capacity: usize) -> Self {
        let component_cache_capacity = component_cache_capacity.max(1);
        let ticker_stop = Arc::new(AtomicBool::new(false));
        let ticker_engine = engine.clone();
        let ticker_stop_for_thread = Arc::clone(&ticker_stop);
        let ticker = thread::Builder::new()
            .name("ironet-policy-epoch".to_owned())
            .spawn(move || {
                while !ticker_stop_for_thread.load(Ordering::Acquire) {
                    thread::sleep(EPOCH_TICK);
                    if !ticker_stop_for_thread.load(Ordering::Acquire) {
                        ticker_engine.increment_epoch();
                    }
                }
            })
            .expect("spawning the policy epoch ticker");
        Self {
            inner: Arc::new(PolicyEngineInner {
                engine,
                components: Mutex::new(HashMap::new()),
                component_cache_capacity,
                ticker_stop,
                ticker: Mutex::new(Some(ticker)),
            }),
        }
    }

    /// The shared Wasmtime engine.
    pub fn engine(&self) -> &Engine {
        &self.inner.engine
    }

    /// Compiles and caches a component by the package digest.
    pub fn compile(&self, digest: [u8; 32], bytes: &[u8]) -> Result<CompiledPolicy> {
        if let Some(component) = self
            .inner
            .components
            .lock()
            .expect("policy component cache poisoned")
            .get(&digest)
            .cloned()
        {
            return Ok(CompiledPolicy { digest, component });
        }

        let component = Arc::new(
            Component::new(self.engine(), bytes)
                .map_err(|error| anyhow!("compiling policy component: {error}"))?,
        );
        let mut cache = self
            .inner
            .components
            .lock()
            .expect("policy component cache poisoned");
        if cache.len() >= self.inner.component_cache_capacity
            && let Some(oldest) = cache.keys().next().copied()
        {
            cache.remove(&oldest);
        }
        let component = cache
            .entry(digest)
            .or_insert_with(|| Arc::clone(&component));
        Ok(CompiledPolicy {
            digest,
            component: Arc::clone(component),
        })
    }

    /// Number of compiled components currently retained.
    pub fn component_cache_len(&self) -> usize {
        self.inner
            .components
            .lock()
            .expect("policy component cache poisoned")
            .len()
    }

    /// Configured cache bound.
    pub fn component_cache_capacity(&self) -> usize {
        self.inner.component_cache_capacity
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PolicyEngineInner {
    fn drop(&mut self) {
        self.ticker_stop.store(true, Ordering::Release);
        if let Some(ticker) = self
            .ticker
            .get_mut()
            .expect("policy ticker mutex poisoned")
            .take()
        {
            let _ = ticker.join();
        }
    }
}

fn configure_engine(config: &mut Config) -> Result<()> {
    config
        .target("pulley64")
        .map_err(|error| anyhow!("configuring Wasmtime target pulley64: {error}"))?;
    config.wasm_relaxed_simd(false);
    config.wasm_simd(false);
    config.wasm_memory64(false);
    config.wasm_multi_memory(false);
    config.wasm_component_model(true);
    config.cranelift_nan_canonicalization(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.memory_reservation(8 << 20);
    config.memory_reservation_for_growth(0);
    config.memory_guard_size(64 << 10);
    config.memory_may_move(false);
    config.memory_init_cow(true);
    config.max_wasm_stack(512 << 10);
    config.wasm_backtrace_max_frames(None);
    config.native_unwind_info(false);
    config.generate_address_map(false);
    Ok(())
}

/// A compiled component retained by the shared engine cache.
#[derive(Clone)]
pub struct CompiledPolicy {
    digest: [u8; 32],
    component: Arc<Component>,
}

impl CompiledPolicy {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn component(&self) -> &Component {
        &self.component
    }
}

struct HostState {
    limits: StoreLimits,
}

struct StoreSlot {
    store: Store<HostState>,
    policy: Policy,
}

/// Reusable store/instance pool for one compiled policy.
#[derive(Clone)]
pub struct StorePool {
    inner: Arc<StorePoolInner>,
}

struct StorePoolInner {
    engine: PolicyEngine,
    component: CompiledPolicy,
    maximum_memory_bytes: usize,
    capacity: usize,
    slots: Mutex<Vec<StoreSlot>>,
}

impl StorePool {
    pub fn new(
        engine: PolicyEngine,
        component: CompiledPolicy,
        maximum_memory_bytes: u64,
        capacity: usize,
    ) -> Result<Self> {
        let pool = Self {
            inner: Arc::new(StorePoolInner {
                engine,
                component,
                maximum_memory_bytes: usize::try_from(maximum_memory_bytes)
                    .context("maximum policy memory does not fit usize")?,
                capacity: capacity.max(1),
                slots: Mutex::new(Vec::new()),
            }),
        };
        // Instantiate one store eagerly.  This makes missing exports and ABI
        // mismatches loader errors rather than first-tick errors.
        let slot = pool.new_slot()?;
        pool.put(slot);
        Ok(pool)
    }

    fn linker(&self) -> Linker<HostState> {
        Linker::new(self.inner.engine.engine())
    }

    fn new_slot(&self) -> Result<StoreSlot> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.inner.maximum_memory_bytes)
            .instances(1)
            .memories(1)
            .tables(1)
            .table_elements(10_000)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(self.inner.engine.engine(), HostState { limits });
        store.limiter(|state| &mut state.limits);
        // Instantiation itself should not be stopped by the call deadline.
        store.set_epoch_deadline(u64::MAX / 2);
        let policy =
            Policy::instantiate(&mut store, self.inner.component.component(), &self.linker())
                .map_err(|error| anyhow!("instantiating policy component: {error}"))?;
        Ok(StoreSlot { store, policy })
    }

    fn take(&self) -> Result<StoreSlot> {
        if let Some(slot) = self
            .inner
            .slots
            .lock()
            .expect("policy store pool poisoned")
            .pop()
        {
            return Ok(slot);
        }
        self.new_slot()
    }

    fn put(&self, slot: StoreSlot) {
        let mut slots = self.inner.slots.lock().expect("policy store pool poisoned");
        if slots.len() < self.inner.capacity {
            slots.push(slot);
        }
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    pub fn available(&self) -> usize {
        self.inner
            .slots
            .lock()
            .expect("policy store pool poisoned")
            .len()
    }
}

/// A package loader which verifies, compiles and self-checks policy components.
#[derive(Clone)]
pub struct PolicyLoader {
    engine: PolicyEngine,
    store_pool_capacity: usize,
}

impl fmt::Debug for PolicyLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyLoader")
            .field("store_pool_capacity", &self.store_pool_capacity)
            .finish_non_exhaustive()
    }
}

impl PolicyLoader {
    pub fn new(engine: PolicyEngine) -> Self {
        Self {
            engine,
            store_pool_capacity: DEFAULT_STORE_POOL_CAPACITY,
        }
    }

    pub fn with_store_pool_capacity(mut self, capacity: usize) -> Self {
        self.store_pool_capacity = capacity.max(1);
        self
    }

    pub fn engine(&self) -> &PolicyEngine {
        &self.engine
    }

    /// Verifies and loads a policy from a private byte buffer.
    pub fn load_from_bytes(
        &self,
        bytes: &[u8],
        config: &AutotuneWasmConfig,
        trust: &TrustStoreV1,
        now: DateTime<Utc>,
    ) -> Result<WasmPolicyBackend> {
        self.load_from_bytes_inner(bytes, config, trust, now, true)
    }

    fn load_from_bytes_inner(
        &self,
        bytes: &[u8],
        config: &AutotuneWasmConfig,
        trust: &TrustStoreV1,
        now: DateTime<Utc>,
        self_check: bool,
    ) -> Result<WasmPolicyBackend> {
        let limits = PackageLimits::from_config(config);
        let package = PolicyPackage::parse(bytes, limits).map_err(|error| anyhow!(error))?;
        let verified = package.verify(trust, now).map_err(|error| anyhow!(error))?;
        validate_manifest(&verified.manifest, config)?;
        let component = self.engine.compile(package.digest, bytes)?;
        let mut backend = WasmPolicyBackend::from_verified(
            self.engine.clone(),
            component,
            verified.manifest,
            verified.digest,
            verified.signer_id,
            config,
            self.store_pool_capacity,
        )?;
        if self_check {
            backend.self_check()?;
        }
        Ok(backend)
    }

    /// Reads a policy into a private `Vec<u8>` before invoking
    /// [`Self::load_from_bytes`].
    pub fn load_from_path(
        &self,
        path: &Path,
        config: &AutotuneWasmConfig,
        trust: &TrustStoreV1,
        now: DateTime<Utc>,
    ) -> Result<WasmPolicyBackend> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        self.load_from_bytes(&bytes, config, trust, now)
    }

    /// Loads the builtin policy component embedded in this binary.
    ///
    /// Trust comes from the checked-in BLAKE3 sidecar (the committed
    /// component is unsigned; the sidecar digest is pinned), so the
    /// operator's `require_signature`/signer settings do not apply. The
    /// resource budgets of `config` still bound the component.
    pub fn load_builtin(&self, config: &AutotuneWasmConfig) -> Result<WasmPolicyBackend> {
        let mut config = config.clone();
        config.require_signature = false;
        let package = PolicyPackage::parse(BUILTIN_WASM_V1, PackageLimits::from_config(&config))
            .map_err(|error| anyhow!(error))?;
        let expected = super::signature::parse_digest(BUILTIN_WASM_BLAKE3_V1.trim())
            .context("parsing the checked-in builtin.wasm digest sidecar")?;
        ensure!(
            package.digest == expected,
            "embedded builtin.wasm does not match its digest sidecar"
        );
        let trust = TrustStoreV1::with_digest_pins([expected]);
        self.load_from_bytes(BUILTIN_WASM_V1, &config, &trust, Utc::now())
    }
}

fn validate_manifest(manifest: &PolicyManifestV1, config: &AutotuneWasmConfig) -> Result<()> {
    ensure!(
        manifest.abi_world == POLICY_ABI_WORLD_V1,
        "policy ABI world {:?} is not {:?}",
        manifest.abi_world,
        POLICY_ABI_WORLD_V1
    );
    ensure!(
        manifest.maximum_state_bytes as u64 <= config.maximum_state_bytes,
        "policy maximum_state_bytes {} exceeds host maximum {}",
        manifest.maximum_state_bytes,
        config.maximum_state_bytes
    );
    ensure!(
        manifest.requested_memory_bytes as u64 <= config.maximum_memory_bytes,
        "policy requested_memory_bytes {} exceeds host maximum {}",
        manifest.requested_memory_bytes,
        config.maximum_memory_bytes
    );
    if !manifest.state_schema_accepts.is_empty() {
        ensure!(
            manifest
                .state_schema_accepts
                .contains(&manifest.state_schema),
            "policy state_schema {} is not listed in state_schema_accepts",
            manifest.state_schema
        );
    }
    Ok(())
}

/// Wasmtime-backed implementation of [`PolicyBackend`].
pub struct WasmPolicyBackend {
    identity: PolicyIdentityV1,
    manifest: PolicyManifestV1,
    pool: StorePool,
    maximum_state_bytes: usize,
    fuel_budget: u64,
    epoch_deadline_ticks: u64,
    health: PolicyHealthState,
}

#[derive(Debug, Clone, Copy, Default)]
struct PolicyHealthState {
    health: ironet_policy_abi::PolicyHealthV1,
    consecutive_faults: u32,
    faults_total: u64,
    timeouts_total: u64,
    quarantines_total: u64,
    last_call_micros: u64,
    fuel_consumed: u64,
    last_fault: Option<PolicyFaultV1>,
}

impl WasmPolicyBackend {
    #[allow(clippy::too_many_arguments)]
    fn from_verified(
        engine: PolicyEngine,
        component: CompiledPolicy,
        manifest: PolicyManifestV1,
        digest: [u8; 32],
        signer_id: Option<String>,
        config: &AutotuneWasmConfig,
        store_pool_capacity: usize,
    ) -> Result<Self> {
        let pool = StorePool::new(
            engine,
            component,
            config.maximum_memory_bytes,
            store_pool_capacity,
        )?;
        let maximum_state_bytes = usize::try_from(
            config
                .maximum_state_bytes
                .min(u64::from(manifest.maximum_state_bytes))
                .min(u64::from(ironet_policy_abi::POLICY_STATE_MAX_BYTES)),
        )
        .context("maximum policy state does not fit usize")?;
        let fuel_budget = manifest.requested_fuel.clamp(1, MAXIMUM_FUEL_BUDGET);
        let epoch_deadline_ticks = config.deadline_millis.max(1);
        let identity = PolicyIdentityV1 {
            backend: PolicyBackendKindV1::Wasm,
            policy_id: manifest.policy_id.clone(),
            policy_version: manifest.policy_version.to_string(),
            digest: Some(digest),
            signer_id,
            abi_world: manifest.abi_world.clone(),
            state_schema: manifest.state_schema,
            module_generation: 0,
        };
        Ok(Self {
            identity,
            manifest,
            pool,
            maximum_state_bytes,
            fuel_budget,
            epoch_deadline_ticks,
            health: PolicyHealthState {
                health: ironet_policy_abi::PolicyHealthV1::Healthy,
                ..PolicyHealthState::default()
            },
        })
    }

    fn self_check(&mut self) -> Result<()> {
        let empty = PolicyInputV1::default();
        self.decide(&empty)
            .map_err(|fault| anyhow!("empty policy self-check failed: {fault}"))?;
        // The state blob must be a *valid* encoding (empty = cold start):
        // guests that keep typed state — the builtin among them — report
        // corrupt state as a fault by design (plan section 12.2), so feeding
        // garbage here would reject every stateful policy at load time.
        // Corrupt-state handling is exercised by the fault-path tests instead.
        let fixture = PolicyInputV1 {
            logical_tick: 1,
            deterministic_seed: 0x0123_4567_89ab_cdef,
            peer_hash: [0xa5; 32],
            path_epoch: 7,
            ..PolicyInputV1::default()
        };
        self.decide(&fixture)
            .map_err(|fault| anyhow!("fixed policy self-check failed: {fault}"))?;
        Ok(())
    }

    pub fn manifest(&self) -> &PolicyManifestV1 {
        &self.manifest
    }

    pub fn health(&self) -> ironet_policy_abi::PolicyHealthV1 {
        self.health.health
    }

    pub fn consecutive_faults(&self) -> u32 {
        self.health.consecutive_faults
    }

    pub fn faults_total(&self) -> u64 {
        self.health.faults_total
    }

    pub fn timeouts_total(&self) -> u64 {
        self.health.timeouts_total
    }

    pub fn quarantines_total(&self) -> u64 {
        self.health.quarantines_total
    }

    pub fn last_call_micros(&self) -> u64 {
        self.health.last_call_micros
    }

    pub fn fuel_consumed(&self) -> u64 {
        self.health.fuel_consumed
    }

    pub fn last_fault(&self) -> Option<PolicyFaultV1> {
        self.health.last_fault
    }

    pub fn status(&self) -> PolicyRuntimeStatusV1 {
        PolicyRuntimeStatusV1::from_backend(
            &self.identity,
            self.health.health,
            self.health.faults_total,
            self.health.timeouts_total,
            self.health.quarantines_total,
            self.health.last_call_micros,
            self.health.fuel_consumed,
            self.health.last_fault,
        )
    }

    pub fn fuel_budget(&self) -> u64 {
        self.fuel_budget
    }

    pub fn epoch_deadline_ticks(&self) -> u64 {
        self.epoch_deadline_ticks
    }

    pub fn store_pool(&self) -> &StorePool {
        &self.pool
    }

    fn record_success(&mut self, elapsed: Duration, fuel_consumed: u64) {
        self.health.health = ironet_policy_abi::PolicyHealthV1::Healthy;
        self.health.consecutive_faults = 0;
        self.health.last_fault = None;
        self.health.last_call_micros = micros(elapsed);
        self.health.fuel_consumed = fuel_consumed;
    }

    fn record_failure(&mut self, fault: PolicyFaultV1, elapsed: Duration, fuel_consumed: u64) {
        self.health.faults_total = self.health.faults_total.saturating_add(1);
        if fault == PolicyFaultV1::Timeout {
            self.health.timeouts_total = self.health.timeouts_total.saturating_add(1);
        }
        self.health.consecutive_faults = self.health.consecutive_faults.saturating_add(1);
        self.health.last_call_micros = micros(elapsed);
        self.health.fuel_consumed = fuel_consumed;
        self.health.last_fault = Some(fault);
        if self.health.consecutive_faults >= 3 {
            if self.health.health != ironet_policy_abi::PolicyHealthV1::Quarantined {
                self.health.quarantines_total = self.health.quarantines_total.saturating_add(1);
            }
            self.health.health = ironet_policy_abi::PolicyHealthV1::Quarantined;
        } else {
            self.health.health = ironet_policy_abi::PolicyHealthV1::Degraded;
        }
    }
}

impl PolicyBackend for WasmPolicyBackend {
    fn identity(&self) -> &PolicyIdentityV1 {
        &self.identity
    }

    fn decide(&mut self, input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        if self.health.health == ironet_policy_abi::PolicyHealthV1::Quarantined {
            return Err(PolicyFaultV1::Unavailable);
        }
        let started = Instant::now();
        if input.state.len() > self.maximum_state_bytes {
            let fault = PolicyFaultV1::StateTooLarge;
            self.record_failure(fault, started.elapsed(), 0);
            return Err(fault);
        }
        if encoded_input_size(input)
            > usize::try_from(ironet_policy_abi::POLICY_INPUT_BUDGET_BYTES).unwrap_or(usize::MAX)
        {
            let fault = PolicyFaultV1::InputTooLarge;
            self.record_failure(fault, started.elapsed(), 0);
            return Err(fault);
        }

        let wit_input = wit_input(input);
        let mut slot = match self.pool.take() {
            Ok(slot) => slot,
            Err(_) => {
                let fault = PolicyFaultV1::Internal;
                self.record_failure(fault, started.elapsed(), 0);
                return Err(fault);
            }
        };
        let mut reusable = true;
        let set_fuel = slot.store.set_fuel(self.fuel_budget);
        if set_fuel.is_err() {
            let fault = PolicyFaultV1::Internal;
            self.record_failure(fault, started.elapsed(), 0);
            return Err(fault);
        }
        slot.store.set_epoch_deadline(self.epoch_deadline_ticks);
        let result = slot.policy.call_decide(&mut slot.store, &wit_input);
        let fuel_consumed = fuel_consumed(&slot.store, self.fuel_budget);
        let mapped = match result {
            Ok(Ok(output)) => {
                if output.next_state.len() > self.maximum_state_bytes {
                    Some(Err(PolicyFaultV1::StateTooLarge))
                } else if encoded_output_size(&output)
                    > usize::try_from(ironet_policy_abi::POLICY_OUTPUT_BUDGET_BYTES)
                        .unwrap_or(usize::MAX)
                {
                    Some(Err(PolicyFaultV1::OutputTooLarge))
                } else {
                    match output_from_wit(output, input) {
                        Ok(output) => {
                            if let Err(entries) = output.candidate.validate(&input.limits) {
                                let _ = entries;
                                Some(Err(PolicyFaultV1::InvalidOutput))
                            } else if output.diagnostics.state_schema != 0
                                && output.diagnostics.state_schema != self.manifest.state_schema
                            {
                                Some(Err(PolicyFaultV1::InvalidOutput))
                            } else {
                                Some(Ok(output))
                            }
                        }
                        Err(_) => Some(Err(PolicyFaultV1::InvalidOutput)),
                    }
                }
            }
            Ok(Err(fault)) => Some(Err(policy_fault_from_wit(fault))),
            Err(error) => {
                reusable = false;
                Some(Err(map_wasmtime_error(&error)))
            }
        };

        if reusable {
            self.pool.put(slot);
        }
        match mapped.expect("policy call always produces a result") {
            Ok(output) => {
                self.record_success(started.elapsed(), fuel_consumed);
                Ok(output)
            }
            Err(fault) => {
                self.record_failure(fault, started.elapsed(), fuel_consumed);
                Err(fault)
            }
        }
    }

    fn fuel_consumed(&self) -> u64 {
        self.health.fuel_consumed
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn fuel_consumed(store: &Store<HostState>, budget: u64) -> u64 {
    store
        .get_fuel()
        .map(|remaining| budget.saturating_sub(remaining))
        .unwrap_or(budget)
}

fn map_wasmtime_error(error: &wasmtime::Error) -> PolicyFaultV1 {
    if let Some(trap) = error.downcast_ref::<wasmtime::Trap>() {
        return match trap {
            wasmtime::Trap::OutOfFuel => PolicyFaultV1::FuelExhausted,
            wasmtime::Trap::Interrupt => PolicyFaultV1::Timeout,
            wasmtime::Trap::MemoryOutOfBounds => PolicyFaultV1::OutOfMemory,
            _ => PolicyFaultV1::Trap,
        };
    }
    let text = format!("{error:#}").to_ascii_lowercase();
    if text.contains("fuel") {
        PolicyFaultV1::FuelExhausted
    } else if text.contains("epoch") || text.contains("interrupt") || text.contains("deadline") {
        PolicyFaultV1::Timeout
    } else if text.contains("memory")
        || text.contains("resource limit")
        || text.contains("resource limiter")
        || text.contains("grow")
    {
        PolicyFaultV1::OutOfMemory
    } else {
        PolicyFaultV1::Trap
    }
}

/// A request sent to the fixed worker pool.
struct ExecutorRequest {
    peer_key: String,
    input: PolicyInputV1,
    deadline: Instant,
    response: SyncSender<Result<PolicyOutputV1, PolicyFaultV1>>,
}

/// Executor configuration. Workers are ordinary OS threads, never Tokio core
/// workers, and requests are bounded by `queue_capacity`.
#[derive(Debug, Clone)]
pub struct PolicyExecutorConfig {
    pub workers: usize,
    pub queue_capacity: usize,
    pub deadline: Duration,
}

impl Default for PolicyExecutorConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            queue_capacity: 64,
            deadline: Duration::from_millis(10),
        }
    }
}

/// A one-shot result returned by [`PolicyExecutor::submit`].
pub type PolicyResponse = Receiver<Result<PolicyOutputV1, PolicyFaultV1>>;

/// Bounded, fixed-size policy worker pool.
pub struct PolicyExecutor {
    requests: Option<crossbeam_channel::Sender<ExecutorRequest>>,
    workers: Vec<JoinHandle<()>>,
    config: PolicyExecutorConfig,
}

impl PolicyExecutor {
    pub fn new<B>(backend: B, config: PolicyExecutorConfig) -> Self
    where
        B: PolicyBackend + 'static,
    {
        let config = PolicyExecutorConfig {
            workers: config.workers.max(1),
            queue_capacity: config.queue_capacity.max(1),
            deadline: config.deadline.max(Duration::from_millis(1)),
        };
        let backend: Arc<Mutex<Box<dyn PolicyBackend>>> = Arc::new(Mutex::new(Box::new(backend)));
        let (sender, receiver) = crossbeam_channel::bounded(config.queue_capacity);
        let mut workers = Vec::with_capacity(config.workers);
        for index in 0..config.workers {
            let receiver = receiver.clone();
            let backend = Arc::clone(&backend);
            workers.push(
                thread::Builder::new()
                    .name(format!("ironet-policy-worker-{index}"))
                    .spawn(move || worker_loop(receiver, backend))
                    .expect("spawning policy worker"),
            );
        }
        Self {
            requests: Some(sender),
            workers,
            config,
        }
    }

    pub fn with_defaults<B>(backend: B) -> Self
    where
        B: PolicyBackend + 'static,
    {
        Self::new(backend, PolicyExecutorConfig::default())
    }

    pub fn submit(&self, peer_key: impl Into<String>, input: PolicyInputV1) -> PolicyResponse {
        let Some(requests) = &self.requests else {
            let (sender, response) = mpsc::sync_channel(1);
            let _ = sender.send(Err(PolicyFaultV1::Unavailable));
            return response;
        };
        let (sender, response) = mpsc::sync_channel(1);
        let request = ExecutorRequest {
            peer_key: peer_key.into(),
            input,
            deadline: Instant::now() + self.config.deadline,
            response: sender,
        };
        if requests.try_send(request).is_err() {
            // The queue is full or the executor is shutting down.  Return a
            // ready oneshot so the caller can immediately use its baseline.
            let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
            let _ = ready_sender.send(Err(PolicyFaultV1::Unavailable));
            return ready_receiver;
        }
        response
    }

    pub fn config(&self) -> &PolicyExecutorConfig {
        &self.config
    }

    pub fn queue_capacity(&self) -> usize {
        self.config.queue_capacity
    }

    pub fn queue_depth(&self) -> usize {
        self.requests
            .as_ref()
            .map_or(0, crossbeam_channel::Sender::len)
    }
}

impl Drop for PolicyExecutor {
    fn drop(&mut self) {
        // Closing the sender lets every worker leave its blocking receive
        // loop.  Joining keeps the executor's fixed thread pool bounded over
        // repeated policy reloads.
        self.requests.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn worker_loop(
    receiver: crossbeam_channel::Receiver<ExecutorRequest>,
    backend: Arc<Mutex<Box<dyn PolicyBackend>>>,
) {
    while let Ok(request) = receiver.recv() {
        let _peer_key = request.peer_key;
        if Instant::now() >= request.deadline {
            let _ = request.response.send(Err(PolicyFaultV1::Unavailable));
            continue;
        }
        let result = match backend.lock() {
            Ok(mut backend) if Instant::now() < request.deadline => backend.decide(&request.input),
            Ok(_) => Err(PolicyFaultV1::Unavailable),
            Err(_) => Err(PolicyFaultV1::Internal),
        };
        let result = if Instant::now() >= request.deadline {
            Err(PolicyFaultV1::Unavailable)
        } else {
            result
        };
        let _ = request.response.send(result);
    }
}

fn encoded_input_size(input: &PolicyInputV1) -> usize {
    INPUT_FIXED_OVERHEAD_BYTES
        .saturating_add(input.state.len())
        .saturating_add(
            input
                .extensions
                .iter()
                .map(|entry| entry.payload.len().saturating_add(8))
                .sum::<usize>(),
        )
}

fn encoded_output_size(output: &wit::PolicyOutput) -> usize {
    OUTPUT_FIXED_OVERHEAD_BYTES
        .saturating_add(output.next_state.len())
        .saturating_add(
            output
                .candidate
                .extensions
                .iter()
                .map(|entry| entry.payload.len().saturating_add(8))
                .sum::<usize>(),
        )
}

fn policy_fault_from_wit(fault: wit::PolicyFault) -> PolicyFaultV1 {
    match fault {
        wit::PolicyFault::Trap => PolicyFaultV1::Trap,
        wit::PolicyFault::Timeout => PolicyFaultV1::Timeout,
        wit::PolicyFault::FuelExhausted => PolicyFaultV1::FuelExhausted,
        wit::PolicyFault::OutOfMemory => PolicyFaultV1::OutOfMemory,
        wit::PolicyFault::InputTooLarge => PolicyFaultV1::InputTooLarge,
        wit::PolicyFault::OutputTooLarge => PolicyFaultV1::OutputTooLarge,
        wit::PolicyFault::InvalidOutput => PolicyFaultV1::InvalidOutput,
        wit::PolicyFault::StateTooLarge => PolicyFaultV1::StateTooLarge,
        wit::PolicyFault::AbiMismatch => PolicyFaultV1::AbiMismatch,
        wit::PolicyFault::Unavailable => PolicyFaultV1::Unavailable,
        wit::PolicyFault::Internal => PolicyFaultV1::Internal,
    }
}

fn path_reliability(value: PathReliabilityV1) -> wit::PathReliability {
    match value {
        PathReliabilityV1::Datagram => wit::PathReliability::Datagram,
        PathReliabilityV1::ReliableRelay => wit::PathReliability::ReliableRelay,
    }
}

fn objective(value: super::api::ObjectiveV1) -> wit::Objective {
    match value {
        super::api::ObjectiveV1::Balanced => wit::Objective::Balanced,
        super::api::ObjectiveV1::Throughput => wit::Objective::Throughput,
        super::api::ObjectiveV1::Latency => wit::Objective::Latency,
    }
}

fn bbr_preset(value: Bbr3PresetV1) -> wit::Bbr3Preset {
    match value {
        Bbr3PresetV1::SharedConservative => wit::Bbr3Preset::SharedConservative,
        Bbr3PresetV1::PrivateAggressive => wit::Bbr3Preset::PrivateAggressive,
        Bbr3PresetV1::LossyRadio => wit::Bbr3Preset::LossyRadio,
        Bbr3PresetV1::Policer => wit::Bbr3Preset::Policer,
        Bbr3PresetV1::LongFat => wit::Bbr3Preset::LongFat,
        Bbr3PresetV1::RelayReliable => wit::Bbr3Preset::RelayReliable,
        Bbr3PresetV1::LowRttHost => wit::Bbr3Preset::LowRttHost,
    }
}

fn bbr_preset_from_wit(value: wit::Bbr3Preset) -> Bbr3PresetV1 {
    match value {
        wit::Bbr3Preset::SharedConservative => Bbr3PresetV1::SharedConservative,
        wit::Bbr3Preset::PrivateAggressive => Bbr3PresetV1::PrivateAggressive,
        wit::Bbr3Preset::LossyRadio => Bbr3PresetV1::LossyRadio,
        wit::Bbr3Preset::Policer => Bbr3PresetV1::Policer,
        wit::Bbr3Preset::LongFat => Bbr3PresetV1::LongFat,
        wit::Bbr3Preset::RelayReliable => Bbr3PresetV1::RelayReliable,
        wit::Bbr3Preset::LowRttHost => Bbr3PresetV1::LowRttHost,
    }
}

fn cover_profile(value: CoverProfileV1) -> wit::CoverProfile {
    match value {
        CoverProfileV1::Idle => wit::CoverProfile::Idle,
        CoverProfileV1::LiveBroadcast => wit::CoverProfile::LiveBroadcast,
        CoverProfileV1::InteractiveVideo => wit::CoverProfile::InteractiveVideo,
        CoverProfileV1::GenericH3Bulk => wit::CoverProfile::GenericH3Bulk,
    }
}

fn cover_profile_from_wit(value: wit::CoverProfile) -> CoverProfileV1 {
    match value {
        wit::CoverProfile::Idle => CoverProfileV1::Idle,
        wit::CoverProfile::LiveBroadcast => CoverProfileV1::LiveBroadcast,
        wit::CoverProfile::InteractiveVideo => CoverProfileV1::InteractiveVideo,
        wit::CoverProfile::GenericH3Bulk => CoverProfileV1::GenericH3Bulk,
    }
}

fn fec_family(value: FecPresetFamilyV1) -> wit::FecPresetFamily {
    match value {
        FecPresetFamilyV1::Unspecified => wit::FecPresetFamily::Unspecified,
        FecPresetFamilyV1::Sparse => wit::FecPresetFamily::Sparse,
        FecPresetFamilyV1::Balanced => wit::FecPresetFamily::Balanced,
        FecPresetFamilyV1::Dense => wit::FecPresetFamily::Dense,
    }
}

fn fec_family_from_wit(value: wit::FecPresetFamily) -> FecPresetFamilyV1 {
    match value {
        wit::FecPresetFamily::Unspecified => FecPresetFamilyV1::Unspecified,
        wit::FecPresetFamily::Sparse => FecPresetFamilyV1::Sparse,
        wit::FecPresetFamily::Balanced => FecPresetFamilyV1::Balanced,
        wit::FecPresetFamily::Dense => FecPresetFamilyV1::Dense,
    }
}

fn wait_policy(value: RepairWaitPolicyV1) -> wit::RepairWaitPolicy {
    match value {
        RepairWaitPolicyV1::HostDefault => wit::RepairWaitPolicy::HostDefault,
        RepairWaitPolicyV1::Eager => wit::RepairWaitPolicy::Eager,
        RepairWaitPolicyV1::AfterFecWindow => wit::RepairWaitPolicy::AfterFecWindow,
        RepairWaitPolicyV1::Patient => wit::RepairWaitPolicy::Patient,
    }
}

fn wait_policy_from_wit(value: wit::RepairWaitPolicy) -> RepairWaitPolicyV1 {
    match value {
        wit::RepairWaitPolicy::HostDefault => RepairWaitPolicyV1::HostDefault,
        wit::RepairWaitPolicy::Eager => RepairWaitPolicyV1::Eager,
        wit::RepairWaitPolicy::AfterFecWindow => RepairWaitPolicyV1::AfterFecWindow,
        wit::RepairWaitPolicy::Patient => RepairWaitPolicyV1::Patient,
    }
}

fn responsibility(value: ProtectionResponsibilityV1) -> wit::ProtectionResponsibility {
    match value {
        ProtectionResponsibilityV1::HostDefault => wit::ProtectionResponsibility::HostDefault,
        ProtectionResponsibilityV1::PreferFec => wit::ProtectionResponsibility::PreferFec,
        ProtectionResponsibilityV1::PreferRepair => wit::ProtectionResponsibility::PreferRepair,
        ProtectionResponsibilityV1::Both => wit::ProtectionResponsibility::Both,
    }
}

fn responsibility_from_wit(value: wit::ProtectionResponsibility) -> ProtectionResponsibilityV1 {
    match value {
        wit::ProtectionResponsibility::HostDefault => ProtectionResponsibilityV1::HostDefault,
        wit::ProtectionResponsibility::PreferFec => ProtectionResponsibilityV1::PreferFec,
        wit::ProtectionResponsibility::PreferRepair => ProtectionResponsibilityV1::PreferRepair,
        wit::ProtectionResponsibility::Both => ProtectionResponsibilityV1::Both,
    }
}

fn scheduler_hint(value: SchedulerPresetHintV1) -> wit::SchedulerPresetHint {
    match value {
        SchedulerPresetHintV1::HostDefault => wit::SchedulerPresetHint::HostDefault,
        SchedulerPresetHintV1::LatencyFirst => wit::SchedulerPresetHint::LatencyFirst,
        SchedulerPresetHintV1::Balanced => wit::SchedulerPresetHint::Balanced,
        SchedulerPresetHintV1::BulkThroughput => wit::SchedulerPresetHint::BulkThroughput,
    }
}

fn scheduler_hint_from_wit(value: wit::SchedulerPresetHint) -> SchedulerPresetHintV1 {
    match value {
        wit::SchedulerPresetHint::HostDefault => SchedulerPresetHintV1::HostDefault,
        wit::SchedulerPresetHint::LatencyFirst => SchedulerPresetHintV1::LatencyFirst,
        wit::SchedulerPresetHint::Balanced => SchedulerPresetHintV1::Balanced,
        wit::SchedulerPresetHint::BulkThroughput => SchedulerPresetHintV1::BulkThroughput,
    }
}

fn decision_kind_from_wit(value: wit::PolicyDecisionKind) -> PolicyDecisionKindV1 {
    match value {
        wit::PolicyDecisionKind::Hold => PolicyDecisionKindV1::Hold,
        wit::PolicyDecisionKind::Exploit => PolicyDecisionKindV1::Exploit,
        wit::PolicyDecisionKind::Explore => PolicyDecisionKindV1::Explore,
        wit::PolicyDecisionKind::Rollback => PolicyDecisionKindV1::Rollback,
        wit::PolicyDecisionKind::ColdStart => PolicyDecisionKindV1::ColdStart,
        wit::PolicyDecisionKind::Fallback => PolicyDecisionKindV1::Fallback,
    }
}

fn wit_extension(value: &PolicyExtensionV1) -> wit::PolicyExtension {
    wit::PolicyExtension {
        tag: value.tag,
        payload: value.payload.clone(),
    }
}

fn wit_telemetry(value: &PolicyTelemetryV1) -> wit::PolicyTelemetry {
    wit::PolicyTelemetry {
        path_rtt_micros: value.path_rtt_micros,
        path_min_rtt_micros: value.path_min_rtt_micros,
        path_queue_delay_micros: value.path_queue_delay_micros,
        local_tx_wire_rate_bytes_per_second: value.local_tx_wire_rate_bytes_per_second,
        local_tx_tun_ingress_bytes_per_second: value.local_tx_tun_ingress_bytes_per_second,
        local_tx_real_traffic_bytes_per_second: value.local_tx_real_traffic_bytes_per_second,
        local_tx_train_build_bytes_per_second: value.local_tx_train_build_bytes_per_second,
        local_tx_packets_per_second: value.local_tx_packets_per_second,
        local_tx_loss_ppm: value.local_tx_loss_ppm,
        local_tx_burst_loss_cells: value.local_tx_burst_loss_cells,
        local_tx_average_record_bytes: value.local_tx_average_record_bytes,
        local_tx_gso_ingress_ratio_ppm: value.local_tx_gso_ingress_ratio_ppm,
        local_tx_packet_train_queue_bytes: value.local_tx_packet_train_queue_bytes,
        local_tx_latency_queue_bytes: value.local_tx_latency_queue_bytes,
        local_tx_bulk_preemption_delay_average_micros: value
            .local_tx_bulk_preemption_delay_average_micros,
        local_tx_controller_pacing_rate_bytes_per_second: value
            .local_tx_controller_pacing_rate_bytes_per_second,
        local_tx_controller_send_quantum_bytes: value.local_tx_controller_send_quantum_bytes,
        local_tx_controller_state: value.local_tx_controller_state,
        local_tx_controller_bw_bytes_per_second: value.local_tx_controller_bw_bytes_per_second,
        local_tx_controller_inflight_longterm_bytes: value
            .local_tx_controller_inflight_longterm_bytes,
        local_tx_controller_guard_transitions_delta: value
            .local_tx_controller_guard_transitions_delta,
        local_tx_controller_app_limited: value.local_tx_controller_app_limited,
        local_tx_controller_tunables_generation: value.local_tx_controller_tunables_generation,
        local_tx_controller_params_generation: value.local_tx_controller_params_generation,
        local_tx_controller_clamped_writes: value.local_tx_controller_clamped_writes,
        local_rx_wire_rate_bytes_per_second: value.local_rx_wire_rate_bytes_per_second,
        local_rx_reassembly_pressure_evictions: value.local_rx_reassembly_pressure_evictions,
        remote_goodput_bytes_per_second: value.remote_goodput_bytes_per_second,
        remote_residual_loss_ppm: value.remote_residual_loss_ppm,
        remote_reorder_ppm: value.remote_reorder_ppm,
        remote_expired_stripes_delta: value.remote_expired_stripes_delta,
        remote_wasted_parity_per_mille: value.remote_wasted_parity_per_mille,
        remote_fec_recovery_per_mille: value.remote_fec_recovery_per_mille,
        remote_repair_hit_per_mille: value.remote_repair_hit_per_mille,
        remote_repair_completed_requests: value.remote_repair_completed_requests,
        remote_repair_response_latency_micros: value.remote_repair_response_latency_micros,
        latency_sojourn_p50_micros: value.latency_sojourn_p50_micros,
        latency_sojourn_p95_micros: value.latency_sojourn_p95_micros,
        latency_sojourn_p99_micros: value.latency_sojourn_p99_micros,
        latency_queue_recently_nonempty: value.latency_queue_recently_nonempty,
        host_cpu_utilization_per_mille: value.host_cpu_utilization_per_mille,
    }
}

fn wit_utility(value: &HostUtilityV1) -> wit::HostUtility {
    wit::HostUtility {
        objective: objective(value.objective),
        valid: value.valid,
        utility_milli: value.utility_milli,
        throughput_milli: value.throughput_milli,
        queue_delay_milli: value.queue_delay_milli,
        latency_sojourn_milli: value.latency_sojourn_milli,
        residual_loss_milli: value.residual_loss_milli,
        jitter_milli: value.jitter_milli,
        cpu_milli: value.cpu_milli,
        wire_overhead_milli: value.wire_overhead_milli,
        memory_milli: value.memory_milli,
        goodput_bytes_per_second: value.goodput_bytes_per_second,
    }
}

fn wit_limits(value: &HostLimitsV1) -> wit::HostLimits {
    wit::HostLimits {
        train_target_floor_bytes: value.train_target_floor_bytes,
        train_target_cap_bytes: value.train_target_cap_bytes,
        bulk_quantum_floor_cells: value.bulk_quantum_floor_cells,
        bulk_quantum_cap_cells: value.bulk_quantum_cap_cells,
        send_buffer_floor_bytes: value.send_buffer_floor_bytes,
        send_buffer_cap_bytes: value.send_buffer_cap_bytes,
        receive_buffer_floor_bytes: value.receive_buffer_floor_bytes,
        receive_buffer_cap_bytes: value.receive_buffer_cap_bytes,
        receive_batch_cap: value.receive_batch_cap,
        repair_cache_cap_bytes: value.repair_cache_cap_bytes,
        fec_data_cells_cap: value.fec_data_cells_cap,
        fec_parity_cells_cap: value.fec_parity_cells_cap,
        fec_parity_per_mille_cap: value.fec_parity_per_mille_cap,
        cover_overhead_cap_per_mille: value.cover_overhead_cap_per_mille,
        cover_padding_cap_bytes_per_second: value.cover_padding_cap_bytes_per_second,
        pacing_cap_bytes_per_second: value.pacing_cap_bytes_per_second,
        egress_priority_cap: value.egress_priority_cap,
        state_cap_bytes: value.state_cap_bytes,
        extension_payload_cap_bytes: value.extension_payload_cap_bytes,
        extension_count_cap: value.extension_count_cap,
    }
}

fn wit_capabilities(value: &HostCapabilitiesV1) -> wit::HostCapabilities {
    wit::HostCapabilities {
        abi_major: value.abi_major,
        abi_minor: value.abi_minor,
        fec_supported: value.fec_supported,
        repair_supported: value.repair_supported,
        cover_supported: value.cover_supported,
        bbr_tunables_writable: value.bbr_tunables_writable,
        egress_coordinator: value.egress_coordinator,
        shadow: value.shadow,
        extension_tags: value.extension_tags.clone(),
    }
}

fn wit_egress_view(value: &EgressAllocationViewV1) -> wit::EgressAllocationView {
    wit::EgressAllocationView {
        assigned_rate_bytes_per_second: value.assigned_rate_bytes_per_second,
        node_cap_bytes_per_second: value.node_cap_bytes_per_second,
        node_demand_bytes_per_second: value.node_demand_bytes_per_second,
        pressure_per_mille: value.pressure_per_mille,
        active_peers: value.active_peers,
        allocation_generation: value.allocation_generation,
    }
}

fn wit_bbr_effective(value: &BbrEffectiveV1) -> wit::BbrEffective {
    wit::BbrEffective {
        preset: bbr_preset(value.preset),
        probe_bw_up_pacing_gain_milli: value.probe_bw_up_pacing_gain_milli,
        probe_bw_down_pacing_gain_milli: value.probe_bw_down_pacing_gain_milli,
        cruise_pacing_gain_milli: value.cruise_pacing_gain_milli,
        default_cwnd_gain_milli: value.default_cwnd_gain_milli,
        probe_bw_up_cwnd_gain_milli: value.probe_bw_up_cwnd_gain_milli,
        headroom_milli: value.headroom_milli,
        beta_milli: value.beta_milli,
        loss_threshold_milli: value.loss_threshold_milli,
        loss_is_congestion: value.loss_is_congestion,
        queue_guard_inflation_milli: value.queue_guard_inflation_milli,
        queue_guard_slack_micros: value.queue_guard_slack_micros,
        probe_rtt_interval_millis: value.probe_rtt_interval_millis,
        probe_rtt_duration_millis: value.probe_rtt_duration_millis,
        probe_rtt_cwnd_gain_milli: value.probe_rtt_cwnd_gain_milli,
        min_probe_wait_millis: value.min_probe_wait_millis,
        max_added_probe_wait_millis: value.max_added_probe_wait_millis,
        pacing_cap_bytes_per_second: value.pacing_cap_bytes_per_second,
        cwnd_floor_bytes: value.cwnd_floor_bytes,
        cwnd_cap_bytes: value.cwnd_cap_bytes,
        startup_bw_hint_bytes_per_second: value.startup_bw_hint_bytes_per_second,
    }
}

fn wit_scheduler_effective(value: &SchedulerEffectiveV1) -> wit::SchedulerEffective {
    wit::SchedulerEffective {
        train_target_bytes: value.train_target_bytes,
        bulk_quantum_cells: value.bulk_quantum_cells,
        bulk_admission_window_bytes: value.bulk_admission_window_bytes,
        preset_hint: scheduler_hint(value.preset_hint),
    }
}

fn wit_fec_effective(value: &FecEffectiveV1) -> wit::FecEffective {
    wit::FecEffective {
        enabled: value.enabled,
        data_cells: value.data_cells,
        parity_cells: value.parity_cells,
        preset_family: fec_family(value.preset_family),
    }
}

fn wit_repair_effective(value: &RepairEffectiveV1) -> wit::RepairEffective {
    wit::RepairEffective {
        cache_bytes: value.cache_bytes,
        retention_target_millis: value.retention_target_millis,
        wait_policy: wait_policy(value.wait_policy),
        responsibility: responsibility(value.responsibility),
    }
}

fn wit_tx_effective(value: &TxEffectiveV1) -> wit::TxEffective {
    wit::TxEffective {
        send_buffer_bytes: value.send_buffer_bytes,
        datagram_admission_bytes: value.datagram_admission_bytes,
        producer_window_bytes: value.producer_window_bytes,
    }
}

fn wit_rx_effective(value: &RxEffectiveV1) -> wit::RxEffective {
    wit::RxEffective {
        receive_buffer_bytes: value.receive_buffer_bytes,
        receive_batch: value.receive_batch,
        reassembly_budget_bytes: value.reassembly_budget_bytes,
        active_train_budget: value.active_train_budget,
    }
}

fn wit_cover_effective(value: &CoverEffectiveV1) -> wit::CoverEffective {
    wit::CoverEffective {
        profile: cover_profile(value.profile),
        overhead_per_mille: value.overhead_per_mille,
        padding_bytes_per_second: value.padding_bytes_per_second,
    }
}

fn wit_egress_request(value: &EgressRequestV1) -> wit::EgressRequest {
    wit::EgressRequest {
        desired_rate_bytes_per_second: value.desired_rate_bytes_per_second,
        minimum_rate_bytes_per_second: value.minimum_rate_bytes_per_second,
        priority: value.priority,
        exploring: value.exploring,
    }
}

fn wit_effective(value: &EffectiveActionViewV1) -> wit::EffectiveAction {
    wit::EffectiveAction {
        reason: match value.reason {
            super::api::ActionReasonV1::ColdStart => wit::ActionReason::ColdStart,
            super::api::ActionReasonV1::TelemetryUnavailable => {
                wit::ActionReason::TelemetryUnavailable
            }
            super::api::ActionReasonV1::PathChanged => wit::ActionReason::PathChanged,
            super::api::ActionReasonV1::HealthyLowLoss => wit::ActionReason::HealthyLowLoss,
            super::api::ActionReasonV1::RandomLoss => wit::ActionReason::RandomLoss,
            super::api::ActionReasonV1::BurstLoss => wit::ActionReason::BurstLoss,
            super::api::ActionReasonV1::Congested => wit::ActionReason::Congested,
            super::api::ActionReasonV1::CpuLimited => wit::ActionReason::CpuLimited,
            super::api::ActionReasonV1::ReliablePath => wit::ActionReason::ReliablePath,
        },
        path_epoch: value.path_epoch,
        sample_count: value.sample_count,
        bbr: wit_bbr_effective(&value.bbr),
        scheduler: wit_scheduler_effective(&value.scheduler),
        fec: wit_fec_effective(&value.fec),
        repair: wit_repair_effective(&value.repair),
        tx: wit_tx_effective(&value.tx),
        rx: wit_rx_effective(&value.rx),
        cover: wit_cover_effective(&value.cover),
        egress: wit_egress_request(&value.egress),
    }
}

fn wit_input(value: &PolicyInputV1) -> wit::PolicyInput {
    wit::PolicyInput {
        logical_tick: value.logical_tick,
        deterministic_seed: value.deterministic_seed,
        peer_hash: value.peer_hash.to_vec(),
        path_epoch: value.path_epoch,
        reliability: path_reliability(value.reliability),
        telemetry: wit_telemetry(&value.telemetry),
        previous: wit_effective(&value.previous),
        previous_utility: wit_utility(&value.previous_utility),
        limits: wit_limits(&value.limits),
        capabilities: wit_capabilities(&value.capabilities),
        egress: wit_egress_view(&value.egress),
        extensions: value.extensions.iter().map(wit_extension).collect(),
        state: value.state.clone(),
    }
}

fn label_from_wit(value: wit::PolicyLabel) -> Result<PolicyLabelV1> {
    ensure!(
        value.len() <= ironet_policy_abi::POLICY_LABEL_BYTES,
        "diagnostic label is too long"
    );
    std::str::from_utf8(&value).context("diagnostic label is not UTF-8")?;
    let mut label = [0u8; ironet_policy_abi::POLICY_LABEL_BYTES];
    label[..value.len()].copy_from_slice(&value);
    Ok(PolicyLabelV1(label))
}

fn output_from_wit(value: wit::PolicyOutput, _input: &PolicyInputV1) -> Result<PolicyOutputV1> {
    let diagnostics = value.diagnostics;
    Ok(PolicyOutputV1 {
        candidate: candidate_from_wit(value.candidate),
        next_state: value.next_state,
        diagnostics: PolicyDiagnosticsV1 {
            decision_kind: decision_kind_from_wit(diagnostics.decision_kind),
            context_label: label_from_wit(diagnostics.context_label)?,
            applied_arm_label: label_from_wit(diagnostics.applied_arm_label)?,
            baseline_arm_label: label_from_wit(diagnostics.baseline_arm_label)?,
            predicted_advantage_milli: diagnostics.predicted_advantage_milli,
            confidence_per_mille: diagnostics.confidence_per_mille,
            exploring: diagnostics.exploring,
            rollback: diagnostics.rollback,
            rollbacks: diagnostics.rollbacks,
            guest_utility_milli: diagnostics.guest_utility_milli,
            state_schema: diagnostics.state_schema,
        },
    })
}

fn candidate_from_wit(value: wit::CandidateAction) -> CandidateActionV1 {
    CandidateActionV1 {
        bbr: value.bbr.map(bbr_candidate_from_wit),
        scheduler: value.scheduler.map(scheduler_candidate_from_wit),
        fec: value.fec.map(fec_candidate_from_wit),
        repair: value.repair.map(repair_candidate_from_wit),
        tx: value.tx.map(tx_candidate_from_wit),
        rx: value.rx.map(rx_candidate_from_wit),
        cover: value.cover.map(cover_candidate_from_wit),
        egress_request: value.egress_request.map(egress_request_from_wit),
        extensions: value
            .extensions
            .into_iter()
            .map(extension_from_wit)
            .collect(),
    }
}

fn extension_from_wit(value: wit::PolicyExtension) -> PolicyExtensionV1 {
    PolicyExtensionV1 {
        tag: value.tag,
        payload: value.payload,
    }
}

fn bbr_candidate_from_wit(value: wit::BbrCandidate) -> BbrCandidateV1 {
    BbrCandidateV1 {
        preset: value.preset.map(bbr_preset_from_wit),
        probe_bw_up_pacing_gain_milli: value.probe_bw_up_pacing_gain_milli,
        probe_bw_down_pacing_gain_milli: value.probe_bw_down_pacing_gain_milli,
        cruise_pacing_gain_milli: value.cruise_pacing_gain_milli,
        default_cwnd_gain_milli: value.default_cwnd_gain_milli,
        probe_bw_up_cwnd_gain_milli: value.probe_bw_up_cwnd_gain_milli,
        headroom_milli: value.headroom_milli,
        beta_milli: value.beta_milli,
        loss_threshold_milli: value.loss_threshold_milli,
        loss_is_congestion: value.loss_is_congestion,
        queue_guard_inflation_milli: value.queue_guard_inflation_milli,
        queue_guard_slack_micros: value.queue_guard_slack_micros,
        probe_rtt_interval_millis: value.probe_rtt_interval_millis,
        probe_rtt_duration_millis: value.probe_rtt_duration_millis,
        probe_rtt_cwnd_gain_milli: value.probe_rtt_cwnd_gain_milli,
        min_probe_wait_millis: value.min_probe_wait_millis,
        max_added_probe_wait_millis: value.max_added_probe_wait_millis,
        pacing_cap_bytes_per_second: value.pacing_cap_bytes_per_second,
        cwnd_floor_bytes: value.cwnd_floor_bytes,
        cwnd_cap_bytes: value.cwnd_cap_bytes,
        startup_bw_hint_bytes_per_second: value.startup_bw_hint_bytes_per_second,
    }
}

fn scheduler_candidate_from_wit(value: wit::SchedulerCandidate) -> SchedulerCandidateV1 {
    SchedulerCandidateV1 {
        train_target_bytes: value.train_target_bytes,
        bulk_quantum_cells: value.bulk_quantum_cells,
        bulk_admission_window_bytes: value.bulk_admission_window_bytes,
        preset_hint: value.preset_hint.map(scheduler_hint_from_wit),
    }
}

fn fec_candidate_from_wit(value: wit::FecCandidate) -> FecCandidateV1 {
    FecCandidateV1 {
        enabled: value.enabled,
        data_cells: value.data_cells,
        parity_cells: value.parity_cells,
        preset_family: value.preset_family.map(fec_family_from_wit),
    }
}

fn repair_candidate_from_wit(value: wit::RepairCandidate) -> RepairCandidateV1 {
    RepairCandidateV1 {
        cache_bytes: value.cache_bytes,
        retention_target_millis: value.retention_target_millis,
        wait_policy: value.wait_policy.map(wait_policy_from_wit),
        responsibility: value.responsibility.map(responsibility_from_wit),
    }
}

fn tx_candidate_from_wit(value: wit::TxCandidate) -> TxCandidateV1 {
    TxCandidateV1 {
        send_buffer_bytes: value.send_buffer_bytes,
        datagram_admission_bytes: value.datagram_admission_bytes,
        producer_window_bytes: value.producer_window_bytes,
    }
}

fn rx_candidate_from_wit(value: wit::RxCandidate) -> RxCandidateV1 {
    RxCandidateV1 {
        receive_buffer_bytes: value.receive_buffer_bytes,
        receive_batch: value.receive_batch,
        reassembly_budget_bytes: value.reassembly_budget_bytes,
        active_train_budget: value.active_train_budget,
    }
}

fn cover_candidate_from_wit(value: wit::CoverCandidate) -> CoverCandidateV1 {
    CoverCandidateV1 {
        profile: value.profile.map(cover_profile_from_wit),
        overhead_per_mille: value.overhead_per_mille,
        padding_bytes_per_second: value.padding_bytes_per_second,
    }
}

fn egress_request_from_wit(value: wit::EgressRequest) -> EgressRequestV1 {
    EgressRequestV1 {
        desired_rate_bytes_per_second: value.desired_rate_bytes_per_second,
        minimum_rate_bytes_per_second: value.minimum_rate_bytes_per_second,
        priority: value.priority,
        exploring: value.exploring,
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use ironet_policy_abi::{
        POLICY_INPUT_BUDGET_BYTES, POLICY_OUTPUT_BUDGET_BYTES, PolicyHealthV1,
    };

    const TEST_NOW: &str = "2026-08-21T00:00:00Z";

    fn fixture(name: &str) -> &'static [u8] {
        match name {
            "echo" => include_bytes!("../../../../tests/fixtures/policy/malicious/echo.wasm"),
            "loop" => include_bytes!("../../../../tests/fixtures/policy/malicious/loop.wasm"),
            "fuel-burn" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/fuel-burn.wasm")
            }
            "memory-grow" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/memory-grow.wasm")
            }
            "trap" => include_bytes!("../../../../tests/fixtures/policy/malicious/trap.wasm"),
            "oversized-state" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/oversized-state.wasm")
            }
            "oversized-output" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/oversized-output.wasm")
            }
            "invalid-enum" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/invalid-enum.wasm")
            }
            "overflow-action" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/overflow-action.wasm")
            }
            "all-maximums" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/all-maximums.wasm")
            }
            "non-deterministic-attempt" => include_bytes!(
                "../../../../tests/fixtures/policy/malicious/non-deterministic-attempt.wasm"
            ),
            other => panic!("unknown policy fixture {other}"),
        }
    }

    fn fixture_backend(name: &str, self_check: bool) -> WasmPolicyBackend {
        let bytes = fixture(name);
        let config = AutotuneWasmConfig {
            require_signature: false,
            ..AutotuneWasmConfig::default()
        };
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let trust = TrustStoreV1::with_digest_pins([package.digest]);
        PolicyLoader::new(PolicyEngine::new())
            .load_from_bytes_inner(
                bytes,
                &config,
                &trust,
                TEST_NOW.parse().unwrap(),
                self_check,
            )
            .unwrap()
    }

    #[test]
    fn engine_uses_shared_component_cache_and_echo_is_bit_exact() {
        let engine = PolicyEngine::new();
        let bytes = fixture("echo");
        let digest = PolicyPackage::parse(bytes, PackageLimits::default())
            .unwrap()
            .digest;
        let first = engine.compile(digest, bytes).unwrap();
        let second = engine.compile(digest, bytes).unwrap();
        assert_eq!(first.digest(), second.digest());
        assert_eq!(engine.component_cache_len(), 1);

        let config = AutotuneWasmConfig {
            require_signature: false,
            ..AutotuneWasmConfig::default()
        };
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let trust = TrustStoreV1::with_digest_pins([package.digest]);
        let mut backend = PolicyLoader::new(engine)
            .load_from_bytes(bytes, &config, &trust, TEST_NOW.parse().unwrap())
            .unwrap();
        let input = PolicyInputV1 {
            logical_tick: 11,
            deterministic_seed: 22,
            peer_hash: [3; 32],
            state: vec![1, 2, 3, 4],
            ..PolicyInputV1::default()
        };
        let first_started = Instant::now();
        let first = backend.decide(&input).unwrap();
        let first_call_us = micros(first_started.elapsed());
        let mut steady_latencies_us = Vec::with_capacity(1_000);
        let mut steady_fuel = Vec::with_capacity(1_000);
        for _ in 0..1_000 {
            let started = Instant::now();
            assert_eq!(backend.decide(&input).unwrap(), first);
            steady_latencies_us.push(micros(started.elapsed()));
            steady_fuel.push(backend.fuel_consumed());
        }
        assert_eq!(backend.health(), PolicyHealthV1::Healthy);
        assert!(backend.last_call_micros() > 0);
        steady_latencies_us.sort_unstable();
        steady_fuel.sort_unstable();
        let percentile = |samples: &[u64], percentile: usize| {
            samples[(samples.len() * percentile / 100).min(samples.len() - 1)]
        };
        println!(
            "policy_runtime_perf first_call_us={} steady_p50_us={} steady_p99_us={} \
             fuel_p50={} fuel_p99={} cache_len={}",
            first_call_us,
            percentile(&steady_latencies_us, 50),
            percentile(&steady_latencies_us, 99),
            percentile(&steady_fuel, 50),
            percentile(&steady_fuel, 99),
            backend.store_pool().available()
        );
    }

    #[test]
    fn loader_rejects_unsigned_without_pin_and_accepts_pin() {
        let bytes = fixture("echo");
        let config = AutotuneWasmConfig::default();
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let require_signature =
            TrustStoreV1::with_signers(Vec::<super::super::signature::TrustedSigner>::new())
                .unwrap();
        assert!(
            PolicyLoader::new(PolicyEngine::new())
                .load_from_bytes(
                    bytes,
                    &config,
                    &require_signature,
                    TEST_NOW.parse().unwrap()
                )
                .is_err()
        );

        let pin = TrustStoreV1::with_digest_pins([package.digest]);
        let config = AutotuneWasmConfig {
            require_signature: false,
            ..AutotuneWasmConfig::default()
        };
        let backend = PolicyLoader::new(PolicyEngine::new())
            .load_from_bytes(bytes, &config, &pin, TEST_NOW.parse().unwrap())
            .unwrap();
        assert_eq!(backend.identity().backend, PolicyBackendKindV1::Wasm);
    }

    #[test]
    fn self_check_rejects_faulting_guest() {
        for name in ["loop", "fuel-burn", "memory-grow", "trap"] {
            let bytes = fixture(name);
            let config = AutotuneWasmConfig {
                require_signature: false,
                ..AutotuneWasmConfig::default()
            };
            let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
            let pin = TrustStoreV1::with_digest_pins([package.digest]);
            assert!(
                PolicyLoader::new(PolicyEngine::new())
                    .load_from_bytes(bytes, &config, &pin, TEST_NOW.parse().unwrap())
                    .is_err(),
                "faulting fixture {name} passed self-check"
            );
        }
    }

    #[test]
    fn fault_state_machine_quarantines_after_three_failures() {
        let mut backend = fixture_backend("trap", false);
        for expected_health in [PolicyHealthV1::Degraded, PolicyHealthV1::Degraded] {
            assert_eq!(
                backend.decide(&PolicyInputV1::default()),
                Err(PolicyFaultV1::Trap)
            );
            assert_eq!(backend.health(), expected_health);
        }
        assert_eq!(
            backend.decide(&PolicyInputV1::default()),
            Err(PolicyFaultV1::Trap)
        );
        assert_eq!(backend.health(), PolicyHealthV1::Quarantined);
        assert_eq!(backend.faults_total(), 3);
        assert_eq!(backend.quarantines_total(), 1);
        assert_eq!(
            backend.decide(&PolicyInputV1::default()),
            Err(PolicyFaultV1::Unavailable)
        );
        assert_eq!(backend.faults_total(), 3);
    }

    #[test]
    fn guest_fault_fixture_matrix_is_bounded_and_counted() {
        for (name, expected) in [
            ("fuel-burn", PolicyFaultV1::FuelExhausted),
            ("memory-grow", PolicyFaultV1::OutOfMemory),
            ("oversized-state", PolicyFaultV1::StateTooLarge),
            ("oversized-output", PolicyFaultV1::OutputTooLarge),
            ("invalid-enum", PolicyFaultV1::InvalidOutput),
            ("overflow-action", PolicyFaultV1::InvalidOutput),
            ("all-maximums", PolicyFaultV1::InvalidOutput),
        ] {
            let mut backend = fixture_backend(name, false);
            let result = backend.decide(&PolicyInputV1::default());
            assert_eq!(result, Err(expected), "fixture {name}");
            assert_eq!(backend.faults_total(), 1, "fixture {name}");
            assert_eq!(backend.health(), PolicyHealthV1::Degraded, "fixture {name}");
        }
    }

    #[test]
    fn timeout_and_input_budgets_are_separate_faults() {
        let bytes = fixture("loop");
        let config = AutotuneWasmConfig {
            require_signature: false,
            deadline_millis: 1,
            ..AutotuneWasmConfig::default()
        };
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let pin = TrustStoreV1::with_digest_pins([package.digest]);
        let mut backend = PolicyLoader::new(PolicyEngine::new())
            .load_from_bytes_inner(bytes, &config, &pin, TEST_NOW.parse().unwrap(), false)
            .unwrap();
        assert_eq!(
            backend.decide(&PolicyInputV1::default()),
            Err(PolicyFaultV1::Timeout)
        );
        assert_eq!(backend.timeouts_total(), 1);

        let mut echo = fixture_backend("echo", true);
        let input = PolicyInputV1 {
            extensions: vec![PolicyExtensionV1 {
                tag: 1,
                payload: vec![0; usize::try_from(POLICY_INPUT_BUDGET_BYTES).unwrap()],
            }],
            ..PolicyInputV1::default()
        };
        assert_eq!(echo.decide(&input), Err(PolicyFaultV1::InputTooLarge));
    }

    #[test]
    fn nondeterministic_attempt_stays_bit_exact() {
        let mut backend = fixture_backend("non-deterministic-attempt", true);
        let input = PolicyInputV1::default();
        let expected = backend.decide(&input).unwrap();
        for _ in 0..100 {
            assert_eq!(backend.decide(&input).unwrap(), expected);
        }
    }

    struct SlowBackend;

    impl PolicyBackend for SlowBackend {
        fn identity(&self) -> &PolicyIdentityV1 {
            static IDENTITY: std::sync::OnceLock<PolicyIdentityV1> = std::sync::OnceLock::new();
            IDENTITY.get_or_init(|| PolicyIdentityV1::native("slow", "1"))
        }

        fn decide(&mut self, _: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
            thread::sleep(Duration::from_millis(25));
            Ok(PolicyOutputV1::default())
        }
    }

    #[test]
    fn executor_queue_full_and_deadline_return_unavailable() {
        let executor = PolicyExecutor::new(
            SlowBackend,
            PolicyExecutorConfig {
                workers: 1,
                queue_capacity: 1,
                deadline: Duration::from_millis(5),
            },
        );
        let first = executor.submit("peer-a", PolicyInputV1::default());
        let second = executor.submit("peer-b", PolicyInputV1::default());
        let third = executor.submit("peer-c", PolicyInputV1::default());
        assert_eq!(third.recv().unwrap(), Err(PolicyFaultV1::Unavailable));
        assert_eq!(first.recv().unwrap(), Err(PolicyFaultV1::Unavailable));
        assert_eq!(second.recv().unwrap(), Err(PolicyFaultV1::Unavailable));
        assert_eq!(executor.queue_depth(), 0);
    }

    #[test]
    fn status_exposes_fault_and_execution_counters() {
        let mut backend = fixture_backend("trap", false);
        assert_eq!(
            backend.decide(&PolicyInputV1::default()),
            Err(PolicyFaultV1::Trap)
        );
        let status = backend.status();
        assert_eq!(status.health, PolicyHealthV1::Degraded);
        assert_eq!(status.faults_total, 1);
        assert_eq!(status.last_fault, Some(PolicyFaultV1::Trap));
        assert_eq!(status.backend, PolicyBackendKindV1::Wasm);
    }

    #[test]
    fn output_budget_constant_is_at_least_state_budget() {
        const {
            assert!(POLICY_OUTPUT_BUDGET_BYTES >= ironet_policy_abi::POLICY_STATE_MAX_BYTES);
        }
    }

    /// The embedded builtin component loads through the verified loader with
    /// its trust anchored to the checked-in digest sidecar — independent of
    /// the operator's signature settings (plan Phase 6 promotion).
    #[test]
    fn load_builtin_embedded_component_via_digest_sidecar() {
        let backend = PolicyLoader::new(PolicyEngine::new())
            .load_builtin(&AutotuneWasmConfig::default())
            .unwrap();
        let identity = backend.identity();
        assert_eq!(identity.backend, PolicyBackendKindV1::Wasm);
        assert_eq!(identity.policy_id, "bandit-vivace@1");
        assert_eq!(identity.state_schema, ironet_policy_core::STATE_SCHEMA_V1);
        assert!(identity.digest.is_some());
        // The default config requires signatures; the builtin is trusted by
        // its pinned digest instead.
        assert!(AutotuneWasmConfig::default().require_signature);
    }
}
