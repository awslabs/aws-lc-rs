// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::OutputLib::{Crypto, RustWrapper, Ssl};
use crate::{
    cargo_env, emit_rustc_cfg, emit_warning, execute_command, is_cpu_jitter_entropy, is_no_asm,
    option_env, target, target_arch, target_env, target_family, target_os, target_underscored,
    target_vendor, OutputLibType, TestCommandResult,
};
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

pub(crate) struct CmakeBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

fn test_perl_command() -> bool {
    execute_command("perl".as_ref(), &["--version".as_ref()]).status
}

fn test_go_command() -> bool {
    let result = execute_command("go".as_ref(), &["version".as_ref()]);
    if !result.status && result.executed {
        eprintln!("Go stderr:\n--------\n{}\n--------", result.stderr);
    }
    result.status
}

fn test_ninja_command() -> bool {
    execute_command("ninja".as_ref(), &["--version".as_ref()]).status
        || execute_command("ninja-build".as_ref(), &["--version".as_ref()]).status
}

fn test_nasm_command() -> bool {
    execute_command("nasm".as_ref(), &["-version".as_ref()]).status
}

fn find_cmake_command() -> Option<OsString> {
    if let Some(cmake) = option_env("CMAKE") {
        emit_warning(&format!(
            "CMAKE environment variable set: {}",
            cmake.clone()
        ));
        if execute_command(cmake.as_ref(), &["--version".as_ref()]).status {
            Some(cmake.into())
        } else {
            None
        }
    } else if execute_command("cmake3".as_ref(), &["--version".as_ref()]).status {
        Some("cmake3".into())
    } else if execute_command("cmake".as_ref(), &["--version".as_ref()]).status {
        Some("cmake".into())
    } else {
        None
    }
}

fn has_target_cpu_optimization() -> bool {
    matches!(
        target_arch().as_str(),
        "x86_64" | "x86" | "aarch64" | "arm" | "powerpc64"
    )
}

impl CmakeBuilder {
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

    fn artifact_output_dir(&self) -> PathBuf {
        self.out_dir.join("build").join("artifacts")
    }

    fn get_cmake_config(&self) -> cmake::Config {
        cmake::Config::new(&self.manifest_dir)
    }

    const GOCACHE_DIR_NAME: &'static str = "go-cache";
    #[allow(clippy::too_many_lines)]
    fn prepare_cmake_build(&self) -> cmake::Config {
        env::set_var(
            "GOCACHE",
            self.out_dir.join(Self::GOCACHE_DIR_NAME).as_os_str(),
        );

        let mut cmake_cfg = self.get_cmake_config();

        if OutputLibType::default() == OutputLibType::Dynamic {
            cmake_cfg.define("BUILD_SHARED_LIBS", "1");
        } else {
            cmake_cfg.define("BUILD_SHARED_LIBS", "0");
        }

        if is_cpu_jitter_entropy() {
            cmake_cfg.define("ENABLE_FIPS_ENTROPY_CPU_JITTER", "ON");
            emit_rustc_cfg("cpu_jitter_entropy");
        }

        let cc_build = cc::Build::new();
        let opt_level = cargo_env("OPT_LEVEL");
        if opt_level.ne("0") {
            if opt_level.eq("1") || opt_level.eq("2") {
                cmake_cfg.define("CMAKE_BUILD_TYPE", "relwithdebinfo");
            } else {
                cmake_cfg.define("CMAKE_BUILD_TYPE", "release");
                // TODO: Due to the nature of the FIPS build (e.g., its dynamic generation of
                // assembly files and its custom compilation commands within CMake), not all
                // source paths are stripped from the resulting binary.
                emit_warning(
                    "NOTICE: Build environment source paths might be visible in release binary.",
                );
                let parent_dir = self.manifest_dir.parent();
                if parent_dir.is_some() && (target_family() == "unix" || target_env() == "gnu") {
                    let parent_dir = parent_dir.unwrap();

                    let flag = format!("\"-ffile-prefix-map={}=\"", parent_dir.display());
                    if let Ok(true) = cc_build.is_flag_supported(&flag) {
                        emit_warning(&format!("Using flag: {}", &flag));
                        cmake_cfg.asmflag(&flag);
                        cmake_cfg.cflag(&flag);
                    } else {
                        let flag = format!("\"-fdebug-prefix-map={}=\"", parent_dir.display());
                        if let Ok(true) = cc_build.is_flag_supported(&flag) {
                            emit_warning(&format!("Using flag: {}", &flag));
                            cmake_cfg.asmflag(&flag);
                            cmake_cfg.cflag(&flag);
                        }
                    }
                }
            }
        } else if target_os() == "windows" {
            // The Windows/FIPS build rejects "debug" profile
            // https://github.com/aws/aws-lc/blob/main/CMakeLists.txt#L656
            cmake_cfg.define("CMAKE_BUILD_TYPE", "relwithdebinfo");
        } else {
            cmake_cfg.define("CMAKE_BUILD_TYPE", "debug");
        }

        Self::verify_compiler_support(&cc_build.get_compiler());

        if let Some(prefix) = &self.build_prefix {
            cmake_cfg.define("BORINGSSL_PREFIX", format!("{prefix}_"));
            let include_path = self.manifest_dir.join("generated-include");
            cmake_cfg.define(
                "BORINGSSL_PREFIX_HEADERS",
                include_path.display().to_string(),
            );
        }

        // Build flags that minimize our crate size.
        cmake_cfg.define("BUILD_TESTING", "OFF");
        if cfg!(feature = "ssl") {
            cmake_cfg.define("BUILD_LIBSSL", "ON");
        } else {
            cmake_cfg.define("BUILD_LIBSSL", "OFF");
        }
        cmake_cfg.define("FIPS", "1");

        if is_no_asm() {
            let opt_level = cargo_env("OPT_LEVEL");
            if opt_level == "0" {
                cmake_cfg.define("OPENSSL_NO_ASM", "1");
            } else {
                panic!("AWS_LC_SYS_NO_ASM only allowed for debug builds!")
            }
        } else if !has_target_cpu_optimization() {
            emit_warning(&format!(
                "Assembly optimizations not available for target arch: {}.",
                target_arch()
            ));
            // TODO: This should not be needed once resolved upstream
            // See: https://github.com/aws/aws-lc-rs/issues/655
            cmake_cfg.define("OPENSSL_NO_ASM", "1");
        }

        if cfg!(feature = "asan") {
            env::set_var("CC", "clang");
            env::set_var("CXX", "clang++");
            env::set_var("ASM", "clang");

            cmake_cfg.define("ASAN", "1");
        }

        // Allow environment to specify CMake toolchain.
        if let Some(toolchain) = option_env("CMAKE_TOOLCHAIN_FILE").or(option_env(format!(
            "CMAKE_TOOLCHAIN_FILE_{}",
            target_underscored()
        ))) {
            emit_warning(&format!(
                "CMAKE_TOOLCHAIN_FILE environment variable set: {toolchain}"
            ));
            return cmake_cfg;
        }

        if target_vendor() == "apple" {
            let disable_warnings: [&str; 2] =
                ["-Wno-overriding-t-option", "-Wno-overriding-option"];
            for disabler in disable_warnings {
                if let Ok(true) = cc_build.is_flag_supported(disabler) {
                    cmake_cfg.cflag(disabler);
                }
            }
            if target_arch() == "aarch64" {
                cmake_cfg.define("CMAKE_OSX_ARCHITECTURES", "arm64");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "arm64");
            }
            if target_arch() == "x86_64" {
                cmake_cfg.define("CMAKE_OSX_ARCHITECTURES", "x86_64");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "x86_64");
            }
            if target_os().trim() == "ios" {
                cmake_cfg.define("CMAKE_SYSTEM_NAME", "iOS");
                if target().trim().ends_with("-ios-sim") {
                    cmake_cfg.define("CMAKE_OSX_SYSROOT", "iphonesimulator");
                }
            }
        }

        if target_os() == "windows" {
            cmake_cfg.generator("Ninja");
            let env_map = self
                .collect_vcvarsall_bat()
                .map_err(|x| panic!("{}", x))
                .unwrap();
            for (key, value) in env_map {
                cmake_cfg.env(key, value);
            }
        }

        if target_env() == "ohos" {
            Self::configure_open_harmony(&mut cmake_cfg);
        }

        cmake_cfg
    }

    fn verify_compiler_support(compiler: &cc::Tool) -> Option<bool> {
        let compiler_path = compiler.path();

        if compiler.is_like_gnu() || compiler.is_like_clang() {
            if let TestCommandResult {
                stderr: _,
                stdout,
                executed: true,
                status: true,
            } = execute_command(compiler_path.as_os_str(), &["--version".as_ref()])
            {
                if let Some(first_line) = stdout.lines().nth(0) {
                    if let Some((major, minor, patch)) = parse_version(first_line) {
                        // We don't force a build failure, but we generate a clear message.
                        if compiler.is_like_gnu() {
                            emit_warning(&format!("GCC v{major}.{minor}.{patch} detected."));
                            if major > 13 {
                                // TODO: Update when FIPS GCC 14 build is fixed
                                emit_warning("WARNING: FIPS build is known to fail on GCC >= 14. See: https://github.com/aws/aws-lc-rs/issues/569");
                                return Some(false);
                            }
                        }
                        if compiler.is_like_clang() {
                            // AWS-LC-FIPS 2.0 was unable to compile with Clang 19
                            emit_warning(&format!("Clang v{major}.{minor}.{patch} detected."));
                        }
                        return Some(true);
                    }
                }
            }
        } else if compiler.is_like_msvc() {
            if let TestCommandResult {
                stderr,
                stdout: _,
                executed: true,
                status: true,
            } = execute_command(compiler_path.as_os_str(), &["/help".as_ref()])
            {
                if let Some(first_line) = stderr.lines().nth(0) {
                    if let Some((major, minor, patch)) = parse_version(first_line) {
                        emit_warning(&format!("MSVC v{major}.{minor}.{patch} detected."));
                        return Some(true);
                    }
                }
            }
        }
        None
    }

    fn configure_open_harmony(cmake_cfg: &mut cmake::Config) {
        const OHOS_NDK_HOME: &str = "OHOS_NDK_HOME";
        if let Ok(ndk) = env::var(OHOS_NDK_HOME) {
            cmake_cfg.define(
                "CMAKE_TOOLCHAIN_FILE",
                format!("{ndk}/native/build/cmake/ohos.toolchain.cmake"),
            );
            let mut cflags = vec!["-Wno-unused-command-line-argument"];
            let mut asmflags = vec![];
            match target().as_str() {
                "aarch64-unknown-linux-ohos" => {}
                "armv7-unknown-linux-ohos" => {
                    const ARM7_FLAGS: [&str; 6] = [
                        "-march=armv7-a",
                        "-mfloat-abi=softfp",
                        "-mtune=generic-armv7-a",
                        "-mthumb",
                        "-mfpu=neon",
                        "-DHAVE_NEON",
                    ];
                    cflags.extend(ARM7_FLAGS);
                    asmflags.extend(ARM7_FLAGS);
                }
                "x86_64-unknown-linux-ohos" => {
                    const X86_64_FLAGS: [&str; 3] = ["-msse4.1", "-DHAVE_NEON_X86", "-DHAVE_NEON"];
                    cflags.extend(X86_64_FLAGS);
                    asmflags.extend(X86_64_FLAGS);
                }
                ohos_target => {
                    emit_warning(format!("Target: {ohos_target} is not support yet!").as_str());
                }
            }
            cmake_cfg
                .cflag(cflags.join(" ").as_str())
                .cxxflag(cflags.join(" ").as_str())
                .asmflag(asmflags.join(" ").as_str());
        } else {
            emit_warning(format!("{OHOS_NDK_HOME} not set!").as_str());
        }
    }

    fn build_rust_wrapper(&self) -> PathBuf {
        self.prepare_cmake_build()
            .configure_arg("--no-warn-unused-cli")
            .build()
    }

    fn collect_vcvarsall_bat(&self) -> Result<HashMap<String, String>, String> {
        let mut map: HashMap<String, String> = HashMap::new();
        let script_path = self.manifest_dir.join("builder").join("printenv.bat");
        let result = execute_command(script_path.as_os_str(), &[]);
        if !result.status {
            eprintln!("{}", result.stdout);
            return Err("Failed to run vcvarsall.bat.".to_owned());
        }
        eprintln!("{}", result.stdout);
        let lines = result.stdout.lines();
        for line in lines {
            if let Some((var, val)) = line.split_once('=') {
                map.insert(var.to_string(), val.to_string());
            }
        }
        Ok(map)
    }
}

impl crate::Builder for CmakeBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        let mut missing_dependency = false;
        if target_os() == "windows" && !test_ninja_command() {
            eprintln!("Missing dependency: Ninja is required for FIPS on Windows.");
            missing_dependency = true;
        }
        if !test_go_command() {
            eprintln!("Missing dependency: Go is required for FIPS.");
            missing_dependency = true;
        }
        if !test_perl_command() {
            eprintln!("Missing dependency: perl is required for FIPS.");
            missing_dependency = true;
        }
        if target_os() == "windows"
            && target_arch() == "x86_64"
            && !test_nasm_command()
            && !is_no_asm()
        {
            eprintln!(
                "Consider setting `AWS_LC_FIPS_SYS_NO_ASM` in the environment for development builds.\
            See User Guide about the limitations: https://aws.github.io/aws-lc-rs/index.html"
            );
            eprintln!("Missing dependency: nasm is required for FIPS.");
            missing_dependency = true;
        }
        if let Some(cmake_cmd) = find_cmake_command() {
            env::set_var("CMAKE", cmake_cmd);
        } else {
            eprintln!("Missing dependency: cmake");
            missing_dependency = true;
        };

        if missing_dependency {
            return Err("Required build dependency is missing. Halting build.".to_owned());
        }

        Ok(())
    }
    fn build(&self) -> Result<(), String> {
        self.build_rust_wrapper();

        println!(
            "cargo:rustc-link-search=native={}",
            self.artifact_output_dir().display()
        );

        println!(
            "cargo:rustc-link-lib={}={}",
            self.output_lib_type.rust_lib_type(),
            Crypto.libname(&self.build_prefix)
        );

        if cfg!(feature = "ssl") {
            println!(
                "cargo:rustc-link-lib={}={}",
                self.output_lib_type.rust_lib_type(),
                Ssl.libname(&self.build_prefix)
            );
        }

        println!(
            "cargo:rustc-link-lib={}={}",
            self.output_lib_type.rust_lib_type(),
            RustWrapper.libname(&self.build_prefix)
        );

        Ok(())
    }
}

fn parse_version(line: &str) -> Option<(u32, u32, u32)> {
    let version_pattern = regex::Regex::new(r"\s(\d{1,2})\.(\d{1,2})\.(\d+)").ok()?;
    let captures = version_pattern.captures(line)?;

    let major_str = captures.get(1)?.as_str();
    let minor_str = captures.get(2)?.as_str();
    let patch_str = captures.get(3)?.as_str();
    let major = major_str.parse::<u32>().ok()?;
    let minor = minor_str.parse::<u32>().ok()?;
    let patch = patch_str.parse::<u32>().ok()?;

    Some((major, minor, patch))
}

// Tests inside build script don't actually get run.
// These tests and the function above need to be copied elsewhere to test.
//
// #[cfg(test)]
// mod tests {
//     #[test]
//     fn test_parse_version() {
//         let test_cases = [
//             ("Apple clang version 14.0.0 (clang-1500.1.0.2.5)\n", (14, 0, 0)),
//             ("gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0", (13,2,0)),
//             ("FreeBSD clang version 18.1.5 (https://github.com/llvm/llvm-project.git llvmorg-18.1.5-0-g617a15a9eac9)", (18,1,5)),
//             ("gcc (GCC) 11.4.1 20230605 (Red Hat 11.4.1-2)", (11, 4, 1)),
//             ("Microsoft (R) C/C++ Optimizing Compiler Version 19.40.33812 for x64", (19, 40, 33812))
//         ];
//         for case in test_cases {
//             let (major, minor, patch) = super::parse_version(case.0).unwrap();
//             assert_eq!(major, case.1 .0);
//             assert_eq!(minor, case.1 .1);
//             assert_eq!(patch, case.1 .2);
//         }
//     }
// }
