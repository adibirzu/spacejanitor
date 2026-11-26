//! Entry-level (key + value) allowlist for the executable-config gate. Pure function, so it runs on
//! every platform (the repo-level probes live in git_proof_leftovers.rs, unix only).
use sj_core::orphans::{executable_config_entry, executable_config_key};

#[test]
fn entry_vectors_allow_known_benign_forms_and_block_everything_else() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/exec_config_entries.json")).unwrap();
    let split = |e: &serde_json::Value| (e[0].as_str().unwrap().to_string(), e[1].as_str().map(str::to_string));
    for e in v["allow"].as_array().unwrap() {
        let (k, val) = split(e);
        assert!(
            executable_config_entry(&k, val.as_deref()).is_none(),
            "expected allow: {k} = {val:?}"
        );
    }
    for e in v["block"].as_array().unwrap() {
        let (k, val) = split(e);
        assert!(
            executable_config_entry(&k, val.as_deref()).is_some(),
            "expected block: {k} = {val:?}"
        );
    }
}

#[test]
fn the_key_only_gate_is_unchanged_and_still_blocks_the_benign_keys() {
    // the key-level function stays the strict superset: only the entry-level one may waive
    for k in ["filter.lfs.clean", "filter.lfs.smudge", "filter.lfs.process", "credential.helper"] {
        assert!(executable_config_key(k).is_some(), "{k}");
    }
}
