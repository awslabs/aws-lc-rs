// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::cc_builder::CcBuilder;
use crate::OutputLib::{Crypto, RustWrapper, Ssl};
use crate::{
    allow_prebuilt_nasm, cargo_env, effective_target, emit_warning, execute_command,
    get_crate_cflags, is_crt_static, is_no_asm, option_env, requested_c_std, target_arch,
    target_env, target_os, target_underscored, target_vendor, test_nasm_command, use_prebuilt_nasm,
    CStdRequested, OutputLibType,
};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

pub(crate) struct CmakeBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

fn test_clang_cl_command() -> bool {
    execute_command("clang-cl".as_ref(), &["--version".as_ref()]).status
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

    fn collect_compiler_cflags(&self) -> OsString {
        // Use the compiler options identified by CcBuilder
        let cc_builder = CcBuilder::new(
            self.manifest_dir.clone(),
            self.out_dir.clone(),
            self.build_prefix.clone(),
            self.output_lib_type,
        );
        let mut cflags = OsString::new();
        let compiler = cc_builder.prepare_builder().get_compiler();
        let args = compiler.args();
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                cflags.push(" ");
            }
            if let Some(arg) = arg.to_str() {
                if arg.contains(' ') {
                    cflags.push("\"");
                    cflags.push(arg);
                    cflags.push("\"");
                } else {
                    cflags.push(arg);
                }
            } else {
                cflags.push(arg);
            }
        }

        cflags
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_cmake_build(&self) -> cmake::Config {
        let mut cmake_cfg = self.get_cmake_config();

        if OutputLibType::default() == OutputLibType::Dynamic {
            cmake_cfg.define("BUILD_SHARED_LIBS", "1");
        } else {
            cmake_cfg.define("BUILD_SHARED_LIBS", "0");
        }

        let opt_level = cargo_env("OPT_LEVEL");
        if opt_level.ne("0") {
            if opt_level.eq("1") || opt_level.eq("2") {
                cmake_cfg.define("CMAKE_BUILD_TYPE", "relwithdebinfo");
            } else {
                cmake_cfg.define("CMAKE_BUILD_TYPE", "release");
            }
        } else {
            cmake_cfg.define("CMAKE_BUILD_TYPE", "debug");
        }

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
        // Build flags that minimize our dependencies.
        cmake_cfg.define("DISABLE_PERL", "ON");
        cmake_cfg.define("DISABLE_GO", "ON");

        if is_no_asm() {
            let opt_level = cargo_env("OPT_LEVEL");
            if opt_level == "0" {
                cmake_cfg.define("OPENSSL_NO_ASM", "1");
            } else {
                panic!("AWS_LC_SYS_NO_ASM only allowed for debug builds!")
            }
        }

        if cfg!(feature = "asan") {
            env::set_var("CC", "clang");
            env::set_var("CXX", "clang++");
            env::set_var("ASM", "clang");

            cmake_cfg.define("ASAN", "1");
        }
        match requested_c_std() {
            CStdRequested::C99 => {
                cmake_cfg.define("CMAKE_C_STANDARD", "99");
            }
            CStdRequested::C11 => {
                cmake_cfg.define("CMAKE_C_STANDARD", "11");
            }
            CStdRequested::None => {}
        }

        if target_env() == "ohos" {
            Self::configure_open_harmony(&mut cmake_cfg, get_crate_cflags());
            return cmake_cfg;
        }

        let mut cflags = OsString::from(get_crate_cflags());

        // Allow environment to specify CMake toolchain.
        let toolchain_var_name = format!("CMAKE_TOOLCHAIN_FILE_{}", target_underscored());
        if let Some(toolchain) =
            option_env(&toolchain_var_name).or(option_env("CMAKE_TOOLCHAIN_FILE"))
        {
            emit_warning(&format!(
                "CMAKE_TOOLCHAIN_FILE environment variable set: {toolchain}"
            ));
            emit_warning(&format!("Setting CFLAGS: {cflags:?}"));
            env::set_var("CFLAGS", cflags);
            return cmake_cfg;
        }
        // We only consider compiler CFLAGS when no cmake toolchain is set
        let compiler_cflags = self.collect_compiler_cflags();
        cflags.push(" ");
        cflags.push(&compiler_cflags);
        emit_warning(&format!("Setting CFLAGS: {cflags:?}"));
        env::set_var("CFLAGS", cflags);

        // See issue: https://github.com/aws/aws-lc-rs/issues/453
        if target_os() == "windows" {
            self.configure_windows(&mut cmake_cfg);
        }

        // If the build environment vendor is Apple
        #[cfg(target_vendor = "apple")]
        {
            if target_arch() == "aarch64" {
                cmake_cfg.define("CMAKE_OSX_ARCHITECTURES", "arm64");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "arm64");
            }
            if target_arch() == "x86_64" {
                cmake_cfg.define("CMAKE_OSX_ARCHITECTURES", "x86_64");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "x86_64");
            }
        }

        if target_os() == "android" {
            self.configure_android(&mut cmake_cfg);
        }

        if target_vendor() == "apple" && target_os().to_lowercase() == "ios" {
            cmake_cfg.define("CMAKE_SYSTEM_NAME", "iOS");
            if effective_target().ends_with("-ios-sim") || target_arch() == "x86_64" {
                cmake_cfg.define("CMAKE_OSX_SYSROOT", "iphonesimulator");
            } else {
                cmake_cfg.define("CMAKE_OSX_SYSROOT", "iphoneos");
            }
            cmake_cfg.define("CMAKE_THREAD_LIBS_INIT", "-lpthread");
        }

        cmake_cfg
    }

    #[allow(clippy::unused_self)]
    fn configure_android(&self, _cmake_cfg: &mut cmake::Config) {
        // If we leave CMAKE_SYSTEM_PROCESSOR unset, then cmake-rs should handle properly setting
        // CMAKE_SYSTEM_NAME and CMAKE_SYSTEM_PROCESSOR:
        // https://github.com/rust-lang/cmake-rs/blob/b689783b5448966e810d515c798465f2e0ab56fd/src/lib.rs#L450-L499

        // Log relevant environment variables.
        if let Some(value) = option_env("ANDROID_NDK_ROOT") {
            emit_warning(&format!("Found ANDROID_NDK_ROOT={value}"));
        } else {
            emit_warning("ANDROID_NDK_ROOT not set.");
        }
        if let Some(value) = option_env("ANDROID_NDK") {
            emit_warning(&format!("Found ANDROID_NDK={value}"));
        } else {
            emit_warning("ANDROID_NDK not set.");
        }
        if let Some(value) = option_env("ANDROID_STANDALONE_TOOLCHAIN") {
            emit_warning(&format!("Found ANDROID_STANDALONE_TOOLCHAIN={value}"));
        } else {
            emit_warning("ANDROID_STANDALONE_TOOLCHAIN not set.");
        }
    }

    fn configure_windows(&self, cmake_cfg: &mut cmake::Config) {
        match (target_env().as_str(), target_arch().as_str()) {
            ("msvc", "aarch64") => {
                cmake_cfg.generator_toolset(format!(
                    "ClangCL{}",
                    if cfg!(target_arch = "x86_64") {
                        ",host=x64"
                    } else {
                        ""
                    }
                ));
                cmake_cfg.static_crt(is_crt_static());
                cmake_cfg.define("CMAKE_GENERATOR_PLATFORM", "ARM64");
                cmake_cfg.define("CMAKE_SYSTEM_NAME", "Windows");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "ARM64");
            }
            ("msvc", "x86") => {
                cmake_cfg.static_crt(is_crt_static());
                cmake_cfg.define("CMAKE_SYSTEM_NAME", "");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "");
            }
            ("msvc", _) => {
                cmake_cfg.static_crt(is_crt_static());
            }
            ("gnu", "x86") => {
                cmake_cfg.define("CMAKE_SYSTEM_NAME", "Windows");
                cmake_cfg.define("CMAKE_SYSTEM_PROCESSOR", "x86");
            }
            _ => {}
        }
        if use_prebuilt_nasm() {
            emit_warning("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            emit_warning("!!!   Using pre-built NASM binaries   !!!");
            emit_warning("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

            let script_name = if cfg!(target_os = "windows") {
                "prebuilt-nasm.bat"
            } else {
                "prebuilt-nasm.sh"
            };

            let script_path = self
                .manifest_dir
                .join("builder")
                .join(script_name)
                .display()
                .to_string();
            let script_path = script_path.replace('\\', "/");

            cmake_cfg.define("CMAKE_ASM_NASM_COMPILER", script_path.as_str());
        }
    }

    fn configure_open_harmony(cmake_cfg: &mut cmake::Config, crate_cflags: &str) {
        env::set_var("CFLAGS", crate_cflags);
        let mut cflags = vec!["-Wno-unused-command-line-argument"];
        let mut asmflags = vec![];

        let toolchain_var_name = format!("CMAKE_TOOLCHAIN_FILE_{}", target_underscored());
        // If a toolchain is not specified by the environment
        if option_env(&toolchain_var_name)
            .or(option_env("CMAKE_TOOLCHAIN_FILE"))
            .is_none()
        {
            if let Ok(ndk) = env::var("OHOS_NDK_HOME") {
                env::set_var(
                    toolchain_var_name,
                    format!("{ndk}/native/build/cmake/ohos.toolchain.cmake"),
                );
            } else if let Ok(sdk) = env::var("OHOS_SDK_NATIVE") {
                env::set_var(
                    toolchain_var_name,
                    format!("{sdk}/build/cmake/ohos.toolchain.cmake"),
                );
            } else {
                emit_warning(
                    "Neither OHOS_NDK_HOME nor OHOS_SDK_NATIVE are set! No toolchain found.",
                );
            }
        }

        match effective_target().as_str() {
            "aarch64-unknown-linux-ohos" => {
                cmake_cfg.define("OHOS_ARCH", "arm64-v8a");
            }
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
                cmake_cfg.define("OHOS_ARCH", "armeabi-v7a");
            }
            "x86_64-unknown-linux-ohos" => {
                const X86_64_FLAGS: [&str; 3] = ["-msse4.1", "-DHAVE_NEON_X86", "-DHAVE_NEON"];
                cflags.extend(X86_64_FLAGS);
                asmflags.extend(X86_64_FLAGS);
                cmake_cfg.define("OHOS_ARCH", "x86_64");
            }
            ohos_target => {
                emit_warning(format!("Target: {ohos_target} is not support yet!").as_str());
            }
        }
        cmake_cfg
            .cflag(cflags.join(" ").as_str())
            .cxxflag(cflags.join(" ").as_str())
            .asmflag(asmflags.join(" ").as_str());
    }

    fn build_rust_wrapper(&self) -> PathBuf {
        self.prepare_cmake_build()
            .configure_arg("--no-warn-unused-cli")
            .build()
    }
}

impl crate::Builder for CmakeBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        let mut missing_dependency = false;
        if target_os() == "windows" && target_arch() == "x86_64" {
            if is_no_asm() && Some(true) == allow_prebuilt_nasm() {
                eprintln!(
                    "Build environment has both `AWS_LC_SYS_PREBUILT_NASM` and `AWS_LC_SYS_NO_ASM` set.\
                Please remove one of these environment variables.
                See User Guide: https://aws.github.io/aws-lc-rs/index.html"
                );
            }
            if !is_no_asm() && !test_nasm_command() && !use_prebuilt_nasm() {
                eprintln!(
                    "Consider installing NASM or setting `AWS_LC_SYS_PREBUILT_NASM` in the build environment.\
                See User Guide: https://aws.github.io/aws-lc-rs/index.html"
                );
                eprintln!("Missing dependency: nasm");
                missing_dependency = true;
            }
            if target_arch() == "aarch64" && target_env() == "msvc" && !test_clang_cl_command() {
                eprintln!("Missing dependency: clang-cl");
                missing_dependency = true;
            }
        }
        if let Some(cmake_cmd) = find_cmake_command() {
            env::set_var("CMAKE", cmake_cmd);
        } else {
            eprintln!("Missing dependency: cmake");
            missing_dependency = true;
        }

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

    fn name(&self) -> &'static str {
        "CMake"
    }
}
