// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::env;

fn main() {
    let has_mutually_exclusive_features = cfg!(feature = "non-fips") && cfg!(feature = "fips");
    assert!(
        !has_mutually_exclusive_features,
        "`fips` and `non-fips` are mutually exclusive crate features."
    );

    println!("cargo:rustc-check-cfg=cfg(disable_slow_tests)");
    if let Ok(disable) = env::var("AWS_LC_RS_DISABLE_SLOW_TESTS") {
        if disable == "1" {
            println!("cargo:warning=### Slow tests will be disabled! ###");
            println!("cargo:rustc-cfg=disable_slow_tests");
        } else {
            println!("cargo:warning=### Slow tests are enabled: {disable}! ###");
        }
    }
    println!("cargo:rerun-if-env-changed=AWS_LC_RS_DISABLE_SLOW_TESTS");

    // This appears asymmetric, but it reflects the `cfg` statements in lib.rs that
    // require `aws-lc-sys` to be present when "fips" is not enabled.
    // if `fips` is enabled, then use that
    let sys_crate = if cfg!(feature = "fips") {
        "aws-lc-fips-sys"
    } else if cfg!(feature = "aws-lc-sys") {
        "aws-lc-sys"
    } else {
        panic!(
            "one of the following features must be specified: `aws-lc-sys`, `non-fips`, or `fips`."
        );
    };

    export_sys_vars(sys_crate);
}

fn export_sys_vars(sys_crate: &str) {
    let prefix = if sys_crate == "aws-lc-fips-sys" {
        "DEP_AWS_LC_FIPS_"
    } else {
        "DEP_AWS_LC_"
    };

    let mut selected = String::default();
    let mut candidates = vec![];

    // search through the DEP vars and find the selected sys crate version
    for (name, value) in std::env::vars() {
        // if we've selected a prefix then we can go straight to exporting it
        if !selected.is_empty() {
            try_export_var(&selected, &name, &value);
            continue;
        }

        // we're still looking for a selected prefix
        if let Some(version) = name.strip_prefix(prefix) {
            if let Some(version) = version.strip_suffix("_INCLUDE") {
                // we've found the selected version so update it and export it
                selected = format!("{prefix}{version}_");
                try_export_var(&selected, &name, &value);
            } else {
                // it started with the expected prefix, but we don't know what the version is yet
                // so save it for later
                candidates.push((name, value));
            }
        }
    }

    assert!(!selected.is_empty(), "missing {prefix} include");

    // process all of the remaining candidates
    for (name, value) in candidates {
        try_export_var(&selected, &name, &value);
    }
}

fn try_export_var(selected: &str, name: &str, value: &str) {
    assert!(!selected.is_empty(), "missing selected prefix");

    if let Some(var) = name.strip_prefix(selected) {
        eprintln!("cargo:rerun-if-env-changed={name}");
        let var = var.to_lowercase();
        println!("cargo:{var}={value}");
    }
}
