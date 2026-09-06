// SPDX-License-Identifier: MIT OR Apache-2.0

use landlock_observability::collector::CollectorConfig;
use landlock_observability::privilege::{PrivilegeErrorKind, Privileges};
use rustix::io::Errno;
use rustix::thread::{
    capabilities, capability_is_in_ambient_set, capability_is_in_bounding_set, no_new_privs,
    CapabilitySet, CapabilitySets,
};

const SETUP_CAPABILITIES: CapabilitySet = CapabilitySet::BPF.union(CapabilitySet::PERFMON);

fn capability(index: u32) -> CapabilitySet {
    CapabilitySet::from_bits_retain(1_u64 << index)
}

fn external_sets() -> Vec<(bool, bool)> {
    let mut sets = Vec::new();
    for index in 0..64 {
        let capability = capability(index);
        let bounding = match capability_is_in_bounding_set(capability) {
            Ok(value) => value,
            Err(Errno::INVAL) => break,
            Err(error) => panic!("failed to read capability bounding set: {error}"),
        };
        let ambient = capability_is_in_ambient_set(capability)
            .unwrap_or_else(|error| panic!("failed to read ambient capability set: {error}"));
        sets.push((ambient, bounding));
    }
    sets
}

fn empty_capabilities() -> CapabilitySets {
    CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    }
}

fn main() {
    let before_capabilities = capabilities(None).expect("failed to read initial capabilities");
    let before_no_new_privs = no_new_privs().expect("failed to read initial no_new_privs");
    let before_external = external_sets();

    let mut privileges = match Privileges::minimize() {
        Ok(privileges) => privileges,
        Err(error) if error.kind() == PrivilegeErrorKind::MissingSetupCapability => {
            assert_eq!(
                capabilities(None).expect("failed to reread capabilities"),
                before_capabilities
            );
            assert_eq!(
                no_new_privs().expect("failed to reread no_new_privs"),
                before_no_new_privs
            );
            assert_eq!(external_sets(), before_external);
            return;
        }
        Err(error) => panic!("unexpected privilege minimization failure: {error}"),
    };

    assert!(no_new_privs().expect("failed to read minimized no_new_privs"));
    assert_eq!(
        capabilities(None).expect("failed to read minimized capabilities"),
        CapabilitySets {
            effective: SETUP_CAPABILITIES,
            permitted: SETUP_CAPABILITIES,
            inheritable: CapabilitySet::empty(),
        }
    );
    assert!(external_sets()
        .into_iter()
        .all(|(ambient, bounding)| !ambient && !bounding));

    let config = CollectorConfig::default();
    let (collector, worker) = config
        .prepare(&mut privileges)
        .expect("failed to prepare collector with minimized privileges");

    assert!(no_new_privs().expect("failed to read final no_new_privs"));
    assert_eq!(
        capabilities(None).expect("failed to read final capabilities"),
        empty_capabilities()
    );
    assert!(external_sets()
        .into_iter()
        .all(|(ambient, bounding)| !ambient && !bounding));

    let worker_thread = std::thread::spawn(move || {
        assert!(no_new_privs().expect("failed to read worker no_new_privs"));
        assert_eq!(
            capabilities(None).expect("failed to read worker capabilities"),
            empty_capabilities()
        );
        worker.run();
    });
    drop(collector);
    worker_thread.join().expect("collector worker panicked");
}
