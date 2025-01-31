// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// NOTE: This module is intended to produce an equivalent "libcrypto" static library to the one
// produced by the CMake. Changes to CMake relating to compiler checks and/or special build flags
// may require modifications to the logic in this module.

mod aarch64_apple_darwin;
mod aarch64_unknown_linux_gnu;
mod aarch64_unknown_linux_musl;
mod i686_unknown_linux_gnu;
mod x86_64_apple_darwin;
mod x86_64_unknown_linux_gnu;
mod x86_64_unknown_linux_musl;

use crate::{
    cargo_env, emit_warning, env_var_to_bool, execute_command, get_crate_cflags, is_no_asm,
    option_env, out_dir, requested_c_std, target, target_arch, target_env, target_os,
    target_vendor, CStdRequested, OutputLibType,
};
use std::path::PathBuf;

pub(crate) struct CcBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

use std::{env, fs};

pub(crate) struct Library {
    name: &'static str,
    flags: &'static [&'static str],
    sources: &'static [&'static str],
}

#[allow(non_camel_case_types)]
enum PlatformConfig {
    aarch64_apple_darwin,
    aarch64_unknown_linux_gnu,
    aarch64_unknown_linux_musl,
    x86_64_apple_darwin,
    x86_64_unknown_linux_gnu,
    x86_64_unknown_linux_musl,
    i686_unknown_linux_gnu,
}

impl PlatformConfig {
    fn libcrypto(&self) -> Library {
        match self {
            PlatformConfig::aarch64_apple_darwin => aarch64_apple_darwin::CRYPTO_LIBRARY,
            PlatformConfig::aarch64_unknown_linux_gnu => aarch64_unknown_linux_gnu::CRYPTO_LIBRARY,
            PlatformConfig::aarch64_unknown_linux_musl => {
                aarch64_unknown_linux_musl::CRYPTO_LIBRARY
            }
            PlatformConfig::x86_64_apple_darwin => x86_64_apple_darwin::CRYPTO_LIBRARY,
            PlatformConfig::x86_64_unknown_linux_gnu => x86_64_unknown_linux_gnu::CRYPTO_LIBRARY,
            PlatformConfig::x86_64_unknown_linux_musl => x86_64_unknown_linux_musl::CRYPTO_LIBRARY,
            PlatformConfig::i686_unknown_linux_gnu => i686_unknown_linux_gnu::CRYPTO_LIBRARY,
        }
    }

    fn default_for(target: &str) -> Option<Self> {
        println!("default_for Target: '{target}'");
        match target {
            "aarch64-apple-darwin" => Some(PlatformConfig::aarch64_apple_darwin),
            "aarch64-unknown-linux-gnu" => Some(PlatformConfig::aarch64_unknown_linux_gnu),
            "aarch64-unknown-linux-musl" => Some(PlatformConfig::aarch64_unknown_linux_musl),
            "x86_64-apple-darwin" => Some(PlatformConfig::x86_64_apple_darwin),
            "x86_64-unknown-linux-gnu" => Some(PlatformConfig::x86_64_unknown_linux_gnu),
            "x86_64-unknown-linux-musl" => Some(PlatformConfig::x86_64_unknown_linux_musl),
            "i686-unknown-linux-gnu" => Some(PlatformConfig::i686_unknown_linux_gnu),
            _ => None,
        }
    }
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self::default_for(&target()).unwrap()
    }
}

impl CcBuilder {
    pub(crate) fn new(
        manifest_dir: PathBuf,
        out_dir: PathBuf,
        build_prefix: Option<String>,
        output_lib_type: OutputLibType,
    ) -> Self {
        Self {
            manifest_dir,
            out_dir,
            build_prefix,
            output_lib_type,
        }
    }

    pub(crate) fn create_builder(&self) -> cc::Build {
        let mut cc_build = cc::Build::default();
        cc_build.out_dir(&self.out_dir).cpp(false);

        let compiler = cc_build.get_compiler();
        if compiler.is_like_gnu() || compiler.is_like_clang() {
            cc_build.flag("-Wno-unused-parameter");
            if target_os() == "linux"
                || target_os().ends_with("bsd")
                || target_env() == "gnu"
                || target_env() == "musl"
            {
                cc_build.define("_XOPEN_SOURCE", "700").flag("-pthread");
            }
        }

        self.add_includes(&mut cc_build);

        cc_build
    }

    pub(crate) fn prepare_builder(&self) -> cc::Build {
        let mut cc_build = self.create_builder();
        match requested_c_std() {
            CStdRequested::C99 => {
                cc_build.std("c99");
            }
            CStdRequested::C11 => {
                cc_build.std("c11");
            }
            CStdRequested::None => {
                if target_env() == "msvc" && target_arch() == "aarch64" {
                    // clang-cl (not "clang") will be used.
                } else if self.compiler_check("c11", "") {
                    cc_build.std("c11");
                } else {
                    cc_build.std("c99");
                }
            }
        };

        if let Some(cc) = option_env("CC") {
            emit_warning(&format!("CC environment variable set: {}", cc.clone()));
        }
        if let Some(cxx) = option_env("CXX") {
            emit_warning(&format!("CXX environment variable set: {}", cxx.clone()));
        }

        let compiler = cc_build.get_compiler();
        if target_arch() == "x86" && (compiler.is_like_clang() || compiler.is_like_gnu()) {
            cc_build.flag_if_supported("-msse2");
        }

        let opt_level = cargo_env("OPT_LEVEL");
        match opt_level.as_str() {
            "0" | "1" | "2" => {
                if is_no_asm() {
                    emit_warning("AWS_LC_SYS_NO_ASM found. Disabling assembly code usage.");
                    cc_build.define("OPENSSL_NO_ASM", "1");
                }
            }
            _ => {
                assert!(
                    !is_no_asm(),
                    "AWS_LC_SYS_NO_ASM only allowed for debug builds!"
                );
                if compiler.is_like_gnu() || compiler.is_like_clang() {
                    let flag = format!("-ffile-prefix-map={}=", self.manifest_dir.display());
                    if let Ok(true) = cc_build.is_flag_supported(&flag) {
                        emit_warning(&format!("Using flag: {}", &flag));
                        cc_build.flag(flag);
                    } else {
                        emit_warning("NOTICE: Build environment source paths might be visible in release binary.");
                        let flag = format!("-fdebug-prefix-map={}=", self.manifest_dir.display());
                        if let Ok(true) = cc_build.is_flag_supported(&flag) {
                            emit_warning(&format!("Using flag: {}", &flag));
                            cc_build.flag(flag);
                        }
                    }
                }
            }
        }

        if !get_crate_cflags().is_empty() {
            let cflags = get_crate_cflags();
            emit_warning(&format!(
                "AWS_LC_SYS_CFLAGS found. Setting CFLAGS: '{cflags}'"
            ));
            env::set_var("CFLAGS", cflags);
        }

        if target_os() == "macos" {
            // This compiler error has only been seen on MacOS x86_64:
            // ```
            // clang: error: overriding '-mmacosx-version-min=13.7' option with '--target=x86_64-apple-macosx14.2' [-Werror,-Woverriding-t-option]
            // ```
            cc_build.flag_if_supported("-Wno-overriding-t-option");
            cc_build.flag_if_supported("-Wno-overriding-option");
        }

        cc_build
    }

    fn add_includes(&self, cc_build: &mut cc::Build) {
        // The order of includes matters
        if let Some(prefix) = &self.build_prefix {
            cc_build
                .define("BORINGSSL_IMPLEMENTATION", "1")
                .define("BORINGSSL_PREFIX", prefix.as_str());
            cc_build.include(self.manifest_dir.join("generated-include"));
        }
        cc_build
            .include(self.manifest_dir.join("include"))
            .include(self.manifest_dir.join("aws-lc").join("include"))
            .include(
                self.manifest_dir
                    .join("aws-lc")
                    .join("third_party")
                    .join("s2n-bignum")
                    .join("include"),
            );
    }

    fn add_all_files(&self, lib: &Library, cc_build: &mut cc::Build) {
        use core::str::FromStr;
        cc_build.file(PathBuf::from_str("rust_wrapper.c").unwrap());

        for source in lib.sources {
            let source_path = self.manifest_dir.join("aws-lc").join(source);
            let is_asm = std::path::Path::new(source)
                .extension()
                .map_or(false, |ext| ext.eq("S"));
            if is_asm && target_vendor() == "apple" && target_arch() == "aarch64" {
                let mut cc_preprocessor = self.create_builder();
                cc_preprocessor.file(source_path);
                let preprocessed_asm = String::from_utf8(cc_preprocessor.expand()).unwrap();
                let preprocessed_asm = preprocessed_asm.replace(';', "\n\t");
                let asm_output_path = self.out_dir.join(source);
                fs::create_dir_all(asm_output_path.parent().unwrap()).unwrap();
                fs::write(asm_output_path.clone(), preprocessed_asm).unwrap();
                cc_build.file(asm_output_path);
            } else {
                cc_build.file(source_path);
            }
        }
    }

    fn build_library(&self, lib: &Library) {
        let mut cc_build = self.prepare_builder();

        self.add_all_files(lib, &mut cc_build);

        for flag in lib.flags {
            cc_build.flag(flag);
        }
        self.run_compiler_checks();

        if let Some(prefix) = &self.build_prefix {
            cc_build.compile(format!("{}_crypto", prefix.as_str()).as_str());
        } else {
            cc_build.compile(lib.name);
        }
    }

    // This performs basic checks of compiler capabilities and sets an appropriate flag on success.
    // This should be kept in alignment with the checks performed by AWS-LC's CMake build.
    // See: https://github.com/search?q=repo%3Aaws%2Faws-lc%20check_compiler&type=code
    fn compiler_check(&self, basename: &str, flag: &str) -> bool {
        let mut ret_val = false;
        let output_dir = self.out_dir.join(format!("out-{basename}"));
        let mut cc_build = self.create_builder();
        let source_file = self
            .manifest_dir
            .join("aws-lc")
            .join("tests")
            .join("compiler_features_tests")
            .join(format!("{basename}.c"));
        if !source_file.exists() {
            emit_warning("######");
            emit_warning("###### WARNING: MISSING GIT SUBMODULE ######");
            emit_warning(&format!(
                "  -- Did you initialize the repo's git submodules? Unable to find source file: {:?}.",
                &source_file
            ));
            emit_warning("  -- run 'git submodule update --init --recursive' to initialize.");
            emit_warning("######");
            emit_warning("######");
        }
        cc_build
            .file(source_file)
            .warnings_into_errors(true)
            .out_dir(&output_dir);

        let compiler = cc_build.get_compiler();
        if compiler.is_like_gnu() || compiler.is_like_clang() {
            cc_build.flag("-Wno-unused-parameter");
        }
        let result = cc_build.try_compile_intermediates();

        if result.is_ok() {
            if !flag.is_empty() {
                cc_build.define(flag, "1");
            }
            ret_val = true;
        }
        if fs::remove_dir_all(&output_dir).is_err() {
            emit_warning(&format!("Failed to remove {:?}", &output_dir));
        }
        emit_warning(&format!(
            "Compilation of '{basename}.c' {} - {:?}.",
            if ret_val { "succeeded" } else { "failed" },
            &result
        ));
        ret_val
    }

    // This checks whether the compiler contains a critical bug that causes `memcmp` to erroneously
    // consider two regions of memory to be equal when they're not.
    // See GCC bug report: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189
    // This should be kept in alignment with the same check performed by the CMake build.
    // See: https://github.com/search?q=repo%3Aaws%2Faws-lc%20check_run&type=code
    fn memcmp_check(&self) {
        let basename = "memcmp_invalid_stripped_check";
        let exec_path = out_dir().join(basename);
        let memcmp_build = cc::Build::default();
        let memcmp_compiler = memcmp_build.get_compiler();
        if !memcmp_compiler.is_like_clang() && !memcmp_compiler.is_like_gnu() {
            // The logic below assumes a Clang or GCC compiler is in use
            return;
        }
        let mut memcmp_compile_args = Vec::from(memcmp_compiler.args());
        memcmp_compile_args.push(
            self.manifest_dir
                .join("aws-lc")
                .join("tests")
                .join("compiler_features_tests")
                .join(format!("{basename}.c"))
                .into_os_string(),
        );
        memcmp_compile_args.push("-Wno-unused-parameter".into());
        memcmp_compile_args.push("-o".into());
        memcmp_compile_args.push(exec_path.clone().into_os_string());
        let memcmp_args: Vec<_> = memcmp_compile_args
            .iter()
            .map(std::ffi::OsString::as_os_str)
            .collect();
        let memcmp_compile_result =
            execute_command(memcmp_compiler.path().as_os_str(), memcmp_args.as_slice());
        assert!(
            memcmp_compile_result.status,
            "COMPILER: {:?}\
            ARGS: {:?}\
            EXECUTED: {}\
            ERROR: {}\
            OUTPUT: {}\
            Failed to compile {basename}
            ",
            memcmp_compiler.path(),
            memcmp_args.as_slice(),
            memcmp_compile_result.executed,
            memcmp_compile_result.stderr,
            memcmp_compile_result.stdout
        );

        // We can only execute the binary when the host and target platforms match.
        if cargo_env("HOST") == target() {
            let result = execute_command(exec_path.as_os_str(), &[]);
            assert!(
                result.status,
                "### COMPILER BUG DETECTED ###\nYour compiler ({}) is not supported due to a memcmp related bug reported in \
                https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189. \
                We strongly recommend against using this compiler. \n\
                EXECUTED: {}\n\
                ERROR: {}\n\
                OUTPUT: {}\n\
                ",
                memcmp_compiler.path().display(),
                memcmp_compile_result.executed,
                memcmp_compile_result.stderr,
                memcmp_compile_result.stdout
            );
        }
        let _ = fs::remove_file(exec_path);
    }
    fn run_compiler_checks(&self) {
        self.compiler_check("stdalign_check", "AWS_LC_STDALIGN_AVAILABLE");
        self.compiler_check("builtin_swap_check", "AWS_LC_BUILTIN_SWAP_SUPPORTED");
        self.memcmp_check();
    }
}

impl crate::Builder for CcBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        if OutputLibType::Dynamic == self.output_lib_type {
            // https://github.com/rust-lang/cc-rs/issues/594
            return Err("CcBuilder only supports static builds".to_string());
        }

        if PlatformConfig::default_for(&target()).is_none() {
            return Err(format!("Platform not supported: {}", target()));
        }

        if Some(true) == env_var_to_bool("CARGO_FEATURE_SSL") {
            return Err(format!("libssl not supported: {}", target()));
        }

        Ok(())
    }

    fn build(&self) -> Result<(), String> {
        println!("cargo:root={}", self.out_dir.display());
        let platform_config = PlatformConfig::default();
        let libcrypto = platform_config.libcrypto();
        self.build_library(&libcrypto);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CC"
    }
}
