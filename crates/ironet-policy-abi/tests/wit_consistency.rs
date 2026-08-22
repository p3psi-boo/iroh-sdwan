//! Keeps `wit/ironet-policy.wit` and the Rust types in lock-step: every Rust
//! record field and enum variant must appear, in order and with the same
//! kebab-case name, in the WIT definition of the corresponding type.

use std::collections::BTreeMap;

use ironet_policy_abi::*;
use serde::Serialize;

const WIT: &str = include_str!("../wit/ironet-policy.wit");

/// Minimal WIT reader: returns `{type-name: [member, ...]}` for every
/// `record`, `enum` and `variant` block.
fn wit_members() -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for raw in WIT.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, members)) = current.as_mut() {
            if line.starts_with('}') {
                out.insert(name.clone(), std::mem::take(members));
                current = None;
                continue;
            }
            let member = line
                .split([':', ',', '('])
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            assert!(!member.is_empty(), "unparsed WIT line: {raw}");
            members.push(member);
            continue;
        }
        let mut tokens = line.split_whitespace();
        if let Some(kind) = tokens.next()
            && matches!(kind, "record" | "enum" | "variant")
        {
            let name = tokens.next().expect("type name").trim_end_matches('{');
            assert!(line.ends_with('{'), "one-line WIT types unsupported: {raw}");
            current = Some((name.to_string(), Vec::new()));
        }
    }
    assert!(current.is_none(), "unterminated WIT block");
    out
}

fn rust_fields<T: Serialize + Default>() -> Vec<String> {
    // serde_json is built with `preserve_order`, so keys come back in
    // declaration order.
    let value = serde_json::to_value(T::default()).unwrap();
    let serde_json::Value::Object(map) = value else {
        panic!("not a struct");
    };
    map.keys().map(|key| key.replace('_', "-")).collect()
}

fn rust_variants<T: Serialize>(all: &[T]) -> Vec<String> {
    all.iter()
        .map(|variant| {
            let serde_json::Value::String(name) = serde_json::to_value(variant).unwrap() else {
                panic!("non-unit variant");
            };
            name
        })
        .collect()
}

#[test]
fn records_match_rust_structs() {
    let wit = wit_members();
    let checks: Vec<(&str, Vec<String>)> = vec![
        ("policy-extension", rust_fields::<PolicyExtensionV1>()),
        ("policy-telemetry", rust_fields::<PolicyTelemetryV1>()),
        ("host-utility", rust_fields::<HostUtilityV1>()),
        ("host-limits", rust_fields::<HostLimitsV1>()),
        ("host-capabilities", rust_fields::<HostCapabilitiesV1>()),
        (
            "egress-allocation-view",
            rust_fields::<EgressAllocationViewV1>(),
        ),
        ("bbr-effective", rust_fields::<BbrEffectiveV1>()),
        ("scheduler-effective", rust_fields::<SchedulerEffectiveV1>()),
        ("fec-effective", rust_fields::<FecEffectiveV1>()),
        ("repair-effective", rust_fields::<RepairEffectiveV1>()),
        ("tx-effective", rust_fields::<TxEffectiveV1>()),
        ("rx-effective", rust_fields::<RxEffectiveV1>()),
        ("cover-effective", rust_fields::<CoverEffectiveV1>()),
        ("egress-request", rust_fields::<EgressRequestV1>()),
        ("effective-action", rust_fields::<EffectiveActionV1>()),
        ("policy-input", rust_fields::<PolicyInputV1>()),
        ("bbr-candidate", rust_fields::<BbrCandidateV1>()),
        ("scheduler-candidate", rust_fields::<SchedulerCandidateV1>()),
        ("fec-candidate", rust_fields::<FecCandidateV1>()),
        ("repair-candidate", rust_fields::<RepairCandidateV1>()),
        ("tx-candidate", rust_fields::<TxCandidateV1>()),
        ("rx-candidate", rust_fields::<RxCandidateV1>()),
        ("cover-candidate", rust_fields::<CoverCandidateV1>()),
        ("candidate-action", rust_fields::<CandidateActionV1>()),
        ("clamp-report", rust_fields::<ClampReportV1>()),
        ("policy-diagnostics", rust_fields::<PolicyDiagnosticsV1>()),
        ("policy-output", rust_fields::<PolicyOutputV1>()),
    ];
    for (name, fields) in checks {
        let wit_fields = wit
            .get(name)
            .unwrap_or_else(|| panic!("WIT record `{name}` missing"));
        assert_eq!(wit_fields, &fields, "record `{name}` differs");
    }
    // ClampEntryV1 has no Default (its enums have none); spell it out.
    assert_eq!(
        wit["clamp-entry"],
        ["field", "requested", "effective", "reason"]
    );
    let _ = ClampEntryV1::new(
        ClampFieldV1::Extension,
        0,
        0,
        ClampReasonV1::UnknownExtension,
    );
}

#[test]
fn enums_match_rust_enums() {
    let wit = wit_members();
    let checks: Vec<(&str, Vec<String>)> = vec![
        ("path-reliability", rust_variants(&PathReliabilityV1::ALL)),
        ("action-reason", rust_variants(&ActionReasonV1::ALL)),
        ("cover-profile", rust_variants(&CoverProfileV1::ALL)),
        ("bbr3-preset", rust_variants(&Bbr3PresetV1::ALL)),
        ("objective", rust_variants(&ObjectiveV1::ALL)),
        ("fec-preset-family", rust_variants(&FecPresetFamilyV1::ALL)),
        (
            "repair-wait-policy",
            rust_variants(&RepairWaitPolicyV1::ALL),
        ),
        (
            "protection-responsibility",
            rust_variants(&ProtectionResponsibilityV1::ALL),
        ),
        (
            "scheduler-preset-hint",
            rust_variants(&SchedulerPresetHintV1::ALL),
        ),
        (
            "policy-decision-kind",
            rust_variants(&PolicyDecisionKindV1::ALL),
        ),
        ("clamp-field", rust_variants(&ClampFieldV1::ALL)),
        ("clamp-reason", rust_variants(&ClampReasonV1::ALL)),
        ("policy-fault", rust_variants(&PolicyFaultV1::ALL)),
    ];
    for (name, variants) in checks {
        let wit_variants = wit
            .get(name)
            .unwrap_or_else(|| panic!("WIT enum `{name}` missing"));
        assert_eq!(wit_variants, &variants, "enum `{name}` differs");
    }
}

#[test]
fn world_exports_decide_with_the_documented_signature() {
    assert!(WIT.contains("package ironet:policy@1.0.0;"));
    assert!(WIT.contains("world policy {"));
    assert!(WIT.contains(
        "export decide: func(input: policy-input) -> result<policy-output, policy-fault>;"
    ));
    assert_eq!(POLICY_ABI_WORLD_V1, "ironet:policy/policy@1.0.0");
}

#[test]
fn serde_round_trips_every_abi_record() {
    let input = PolicyInputV1 {
        peer_hash: [0xab; 32],
        extensions: vec![PolicyExtensionV1 {
            tag: 7,
            payload: vec![1, 2, 3],
        }],
        state: vec![9],
        ..PolicyInputV1::default()
    };
    let json = serde_json::to_string(&input).unwrap();
    assert_eq!(serde_json::from_str::<PolicyInputV1>(&json).unwrap(), input);

    let output = PolicyOutputV1 {
        candidate: CandidateActionV1 {
            bbr: Some(BbrCandidateV1 {
                preset: Some(Bbr3PresetV1::Policer),
                ..BbrCandidateV1::default()
            }),
            egress_request: Some(EgressRequestV1 {
                desired_rate_bytes_per_second: 10,
                minimum_rate_bytes_per_second: 5,
                priority: 3,
                exploring: true,
            }),
            ..CandidateActionV1::default()
        },
        next_state: vec![1; 16],
        diagnostics: PolicyDiagnosticsV1 {
            decision_kind: PolicyDecisionKindV1::Explore,
            context_label: PolicyLabelV1::truncated("r1-b2-l0"),
            ..PolicyDiagnosticsV1::default()
        },
    };
    let json = serde_json::to_string(&output).unwrap();
    assert_eq!(
        serde_json::from_str::<PolicyOutputV1>(&json).unwrap(),
        output
    );

    let report = ClampReportV1 {
        entries: vec![ClampEntryV1::new(
            ClampFieldV1::FecParityCells,
            9,
            4,
            ClampReasonV1::CrossFieldConstraint,
        )],
    };
    let json = serde_json::to_string(&report).unwrap();
    assert_eq!(
        serde_json::from_str::<ClampReportV1>(&json).unwrap(),
        report
    );

    let identity = PolicyIdentityV1 {
        digest: Some([3; 32]),
        signer_id: Some("dev".into()),
        ..PolicyIdentityV1::native("builtin", "1.0.0")
    };
    let json = serde_json::to_string(&identity).unwrap();
    assert_eq!(
        serde_json::from_str::<PolicyIdentityV1>(&json).unwrap(),
        identity
    );
    assert_eq!(
        serde_json::to_string(&PolicyFaultV1::FuelExhausted).unwrap(),
        "\"fuel-exhausted\""
    );
}
