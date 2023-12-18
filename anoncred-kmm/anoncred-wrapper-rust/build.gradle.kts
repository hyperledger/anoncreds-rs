import org.gradle.internal.os.OperatingSystem
import java.io.ByteArrayOutputStream

val os: OperatingSystem = OperatingSystem.current()

@Throws(GradleException::class)
fun getNDKOSVariant(): String {
    return if (os.isMacOsX) {
        "darwin-x86_64"
    } else if (os.isLinux) {
        "linux-x86_64"
    } else {
        // It would be windows-x86_64 but we don't support Windows enviroment
        throw GradleException("Unsported OS: ${os.name}")
    }
}

val minAndroidVersion: Int = 21
val ANDROID_SDK = System.getenv("ANDROID_HOME")
val NDK = System.getenv("ANDROID_NDK_HOME")
val TOOLCHAIN = "$NDK/toolchains/llvm/prebuilt/${getNDKOSVariant()}"
val AR = "$TOOLCHAIN/bin/llvm-ar"
val CC = "$TOOLCHAIN/bin/aarch64-linux-android$minAndroidVersion-clang"
val CXX = "$TOOLCHAIN/bin/aarch64-linux-android$minAndroidVersion-clang++"
val LD = "$TOOLCHAIN/bin/ld"
val RANLIB = "$TOOLCHAIN/bin/llvm-ranlib"
val STRIP = "$TOOLCHAIN/bin/llvm-strip"

/**
 * Run CommandLine and return the output
 * @param spec executions commands to run
 * @return the result of these executions commands like they would show up in system terminal
 */
fun Project.execWithOutput(spec: ExecSpec.() -> Unit): String {
    return ByteArrayOutputStream().use { outputStream ->
        exec {
            this.spec()
            this.standardOutput = outputStream
        }
        outputStream.toString().trim()
    }
}

/*
fun Project.commandLineWithOutput(vararg commands: String) {
    val pb = ProcessBuilder()
}
*/

// TODO: Replace commandLine with
// val pb = ProcessBuilder("brew", "--version")
// pb.start().waitFor()
// println(pb.output)

/**
 * Delete the generated `Target` folder that is being generated by Rust Cargo
 */
val rustClean by tasks.register("rustClean") {
    group = "rust"
    description = "Delete the generated files and folders that is being generated by this Gradle Script"
    delete(projectDir.resolve("target"))
    delete(rootDir.parentFile.resolve("target"))
    delete(buildDir)
}

tasks.matching { it.name == "clean" }.all {
    dependsOn(rustClean)
}

/**
 * Building the original Rust anoncreds lib
 * @note no longer needed.
 */
val buildAnoncredsLib by tasks.register<Exec>("buildAnoncredsLib") {
    group = "rust"
    description = "Building the original Rust anoncreds lib"
    onlyIf {
        rootDir
            .resolve("target")
            .resolve("release")
            .exists()
            .not()
    }
    workingDir = rootDir.parentFile
    inputs.files(rootDir.parentFile.resolve("Cargo.toml"))
    outputs.files(fileTree(rootDir.parentFile.resolve("target")))
    commandLine("cargo", "build", "--release")
}

// Compiling Tasks

val buildAnonCredWrapperForMacOSArch64 by tasks.register<Exec>("buildAnonCredWrapperForMacOSArch64") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for macOS aarch64"
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("aarch64-apple-darwin")))
    commandLine("cargo", "build", "--release", "--target", "aarch64-apple-darwin", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForMacOSX8664 by tasks.register<Exec>("buildAnonCredWrapperForMacOSX86_64") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for macOS x86_64"
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("x86_64-apple-darwin")))
    commandLine("cargo", "build", "--release", "--target", "x86_64-apple-darwin", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForMacOSUniversal by tasks.register("buildAnonCredWrapperForMacOSUniversal") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for macOS"
    dependsOn(buildAnonCredWrapperForMacOSArch64, buildAnonCredWrapperForMacOSX8664)
}

val buildAnonCredWrapperForiOSArch64 by tasks.register<Exec>("buildAnonCredWrapperForiOSArch64") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for iOS aarch64"
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("aarch64-apple-ios")))
    commandLine("cargo", "build", "--release", "--target", "aarch64-apple-ios", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForiOSArch64Sim by tasks.register<Exec>("buildAnonCredWrapperForiOSArch64Sim") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for iOS aarch64 sim"
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("aarch64-apple-ios-sim")))
    commandLine("cargo", "build", "--release", "--target", "aarch64-apple-ios-sim", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForiOSX8664 by tasks.register<Exec>("buildAnonCredWrapperForiOSX86_64") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for iOS x86_64"
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("x86_64-apple-ios")))
    commandLine("cargo", "build", "--release", "--target", "x86_64-apple-ios", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForiOSUniversal by tasks.register("buildAnonCredWrapperForiOSUniversal") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for iOS"
    dependsOn(buildAnonCredWrapperForiOSArch64, buildAnonCredWrapperForiOSArch64Sim, buildAnonCredWrapperForiOSX8664)
}

val buildAnonCredWrapperForLinuxX8664 by tasks.register<Exec>("buildAnonCredWrapperForLinuxX86_64") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for Linux x86_64"
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("x86_64-unknown-linux-gnu")))
    commandLine("cargo", "build", "--release", "--target", "x86_64-unknown-linux-gnu", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForLinuxArch64 by tasks.register<Exec>("buildAnonCredWrapperForLinuxArch64") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for Linux aarch64"
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("aarch64-unknown-linux-gnu")))
    commandLine("cargo", "build", "--release", "--target", "aarch64-unknown-linux-gnu", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForLinuxUniversal by tasks.register("buildAnonCredWrapperForLinuxUniversal") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for Linux"
    dependsOn(buildAnonCredWrapperForLinuxArch64, buildAnonCredWrapperForLinuxX8664)
}

val buildAnonCredWrapperForAndroidX8664 by tasks.register<Exec>("buildAnonCredWrapperForAndroidX86_64") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for Android X86_64"
    val localEnv = this.environment
    localEnv += mapOf(
        "PATH" to "${environment["PATH"]}:$TOOLCHAIN:$AR:$CC:$CXX:$LD:$RANLIB:$STRIP:$TOOLCHAIN/bin/",
        "ANDROID_SDK" to ANDROID_SDK,
        "NDK" to NDK,
        "TOOLCHAIN" to TOOLCHAIN,
        "AR" to AR,
        "CC" to CC,
        "CXX" to CXX,
        "LD" to LD,
        "RANLIB" to RANLIB,
        "STRIP" to STRIP
    )
    this.environment = localEnv
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("x86_64-linux-android")))
    commandLine("cargo", "ndk", "build", "--release", "--target", "x86_64-linux-android", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForAndroidArch64 by tasks.register<Exec>("buildAnonCredWrapperForAndroidArch64") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for Android arch64"
    val localEnv = this.environment
    localEnv += mapOf(
        "PATH" to "${environment["PATH"]}:$TOOLCHAIN:$AR:$CC:$CXX:$LD:$RANLIB:$STRIP:$TOOLCHAIN/bin/",
        "ANDROID_SDK" to ANDROID_SDK,
        "NDK" to NDK,
        "TOOLCHAIN" to TOOLCHAIN,
        "AR" to AR,
        "CC" to CC,
        "CXX" to CXX,
        "LD" to LD,
        "RANLIB" to RANLIB,
        "STRIP" to STRIP
    )
    this.environment = localEnv
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("aarch64-linux-android")))
    commandLine("cargo", "ndk", "build", "--release", "--target", "aarch64-linux-android", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForAndroidI686 by tasks.register<Exec>("buildAnonCredWrapperForAndroidI686") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for Android I686"
    val localEnv = this.environment
    localEnv += mapOf(
        "PATH" to "${environment["PATH"]}:$TOOLCHAIN:$AR:$CC:$CXX:$LD:$RANLIB:$STRIP:$TOOLCHAIN/bin/",
        "ANDROID_SDK" to ANDROID_SDK,
        "NDK" to NDK,
        "TOOLCHAIN" to TOOLCHAIN,
        "AR" to AR,
        "CC" to CC,
        "CXX" to CXX,
        "LD" to LD,
        "RANLIB" to RANLIB,
        "STRIP" to STRIP
    )
    this.environment = localEnv
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("i686-linux-android")))
    commandLine("cargo", "ndk", "build", "--release", "--target", "i686-linux-android", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForAndroidArmv7a by tasks.register<Exec>("buildAnonCredWrapperForAndroidArmv7a") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for Android Armv7a"
    val localEnv = this.environment
    localEnv += mapOf(
        "PATH" to "${environment["PATH"]}:$TOOLCHAIN:$AR:$CC:$CXX:$LD:$RANLIB:$STRIP:$TOOLCHAIN/bin/",
        "ANDROID_SDK" to ANDROID_SDK,
        "NDK" to NDK,
        "TOOLCHAIN" to TOOLCHAIN,
        "AR" to AR,
        "CC" to CC,
        "CXX" to CXX,
        "LD" to LD,
        "RANLIB" to RANLIB,
        "STRIP" to STRIP
    )
    this.environment = localEnv
    inputs.files(fileTree(projectDir.resolve("src")))
    outputs.files(fileTree(projectDir.resolve("target").resolve("armv7-linux-androideabi")))
    commandLine("cargo", "ndk", "build", "--release", "--target", "armv7-linux-androideabi", "--target-dir", "${projectDir.resolve("target")}")
}

val buildAnonCredWrapperForAndroidUniversal by tasks.register("buildAnonCredWrapperForAndroidUniversal") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper for Android"
    dependsOn(buildAnonCredWrapperForAndroidX8664, buildAnonCredWrapperForAndroidArch64, buildAnonCredWrapperForAndroidI686, buildAnonCredWrapperForAndroidArmv7a)
}

val buildAnonCredWrapper by tasks.register("buildAnonCredWrapper") {
    group = "rust-compiling"
    description = "Build and compile AnonCred Wrapper"
    dependsOn(buildAnonCredWrapperForMacOSUniversal, buildAnonCredWrapperForLinuxUniversal, buildAnonCredWrapperForAndroidUniversal) // buildAnonCredWrapperForiOSUniversal
}

// Copy Bindings Tasks

val copyGeneratedBinaryForMacOSX8664 by tasks.register<Copy>("copyGeneratedBinaryForMacOSX86_64") {
    group = "rust-compiling"
    description = "Copy all generated macOS x86_64 binaries to generated resources folder"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    include("*.so", "*.a", "*.d", "*.dylib")
    from(projectDir.resolve("target").resolve("x86_64-apple-darwin").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generatedResources").resolve("jvm").resolve("main").resolve("darwin-x86-64"))
    dependsOn(buildAnonCredWrapperForMacOSX8664)
}

val copyGeneratedBinaryForMacOSArch64 by tasks.register<Copy>("copyGeneratedBinaryForMacOSArch64") {
    group = "rust-compiling"
    description = "Copy all generated macOS aarch64 binaries to generated resources folder"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    include("*.so", "*.a", "*.d", "*.dylib")
    from(projectDir.resolve("target").resolve("aarch64-apple-darwin").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generatedResources").resolve("jvm").resolve("main").resolve("darwin-aarch64"))
    dependsOn(buildAnonCredWrapperForMacOSArch64)
}

val copyGeneratedBinaryForMacOS by tasks.register("copyGeneratedBinaryForMacOS") {
    group = "rust-compiling"
    description = "Copy all generated macOS binaries to generated resources folder"
    dependsOn(copyGeneratedBinaryForMacOSX8664, copyGeneratedBinaryForMacOSArch64)
}

val copyGeneratedBinaryForLinuxX8664 by tasks.register<Copy>("copyGeneratedBinaryForLinuxX86_64") {
    group = "rust-compiling"
    description = "Copy all generated Linux x86_64 binaries to generated resources folder"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    include("*.so", "*.a", "*.d", "*.dylib")
    from(projectDir.resolve("target").resolve("x86_64-unknown-linux-gnu").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generatedResources").resolve("jvm").resolve("main").resolve("linux-x86-64"))
    dependsOn(buildAnonCredWrapperForLinuxX8664)
}

val copyGeneratedBinaryForLinuxArch64 by tasks.register<Copy>("copyGeneratedBinaryForLinuxArch64") {
    group = "rust-compiling"
    description = "Copy all generated Linux aarch64 binaries to generated resources folder"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    include("*.so", "*.a", "*.d", "*.dylib")
    from(projectDir.resolve("target").resolve("aarch64-unknown-linux-gnu").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generatedResources").resolve("jvm").resolve("main").resolve("linux-aarch64"))
    dependsOn(buildAnonCredWrapperForLinuxArch64)
}

val copyGeneratedBinaryForLinux by tasks.register("copyGeneratedBinaryForLinux") {
    group = "rust-compiling"
    description = "Copy all generated Linux binaries to generated resources folder"
    dependsOn(copyGeneratedBinaryForLinuxX8664, copyGeneratedBinaryForLinuxArch64)
}

val copyGeneratedBinaryForiOS by tasks.register<Copy>("copyGeneratedBinaryForiOS") {
    group = "rust-compiling"
    description = "Copy all generated iOS binaries to generated resources folder"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    include("*.so", "*.a", "*.d", "*.dylib")
    from(projectDir.resolve("target").resolve("ios-universal").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("processedResources").resolve("binaries").resolve("ios"))
    dependsOn(buildAnonCredWrapperForiOSUniversal)
}

val copyGeneratedBinaryForAndroidX8664 by tasks.register<Copy>("copyGeneratedBinaryForAndroidX86_64") {
    group = "rust-compiling"
    description = "Copy all generated Android X86_64 binaries to generated resources folder"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    include("*.so", "*.a", "*.d", "*.dylib")
    from(projectDir.resolve("target").resolve("x86_64-linux-android").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generatedResources").resolve("android").resolve("main").resolve("jniLibs").resolve("x86-64"))
    dependsOn(buildAnonCredWrapperForAndroidX8664)
}

val copyGeneratedBinaryForAndroidArch64 by tasks.register<Copy>("copyGeneratedBinaryForAndroidArch64") {
    group = "rust-compiling"
    description = "Copy all generated Android aarch64 binaries to generated resources folder"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    include("*.so", "*.a", "*.d", "*.dylib")
    from(projectDir.resolve("target").resolve("aarch64-linux-android").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generatedResources").resolve("android").resolve("main").resolve("jniLibs").resolve("arm64-v8a"))
    dependsOn(buildAnonCredWrapperForAndroidArch64)
}

val copyGeneratedBinaryForAndroidI686 by tasks.register<Copy>("copyGeneratedBinaryForAndroidI686") {
    group = "rust-compiling"
    description = "Copy all generated Android i686 binaries to generated resources folder"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    include("*.so", "*.a", "*.d", "*.dylib")
    from(projectDir.resolve("target").resolve("i686-linux-android").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generatedResources").resolve("android").resolve("main").resolve("jniLibs").resolve("x86"))
    dependsOn(buildAnonCredWrapperForAndroidI686)
}

val copyGeneratedBinaryForAndroidArmv7a by tasks.register<Copy>("copyGeneratedBinaryForAndroidArmv7a") {
    group = "rust-compiling"
    description = "Copy all generated Android armv7a binaries to generated resources folder"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    include("*.so", "*.a", "*.d", "*.dylib")
    from(projectDir.resolve("target").resolve("armv7-linux-androideabi").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generatedResources").resolve("android").resolve("main").resolve("jniLibs").resolve("armeabi-v7a"))
    dependsOn(buildAnonCredWrapperForAndroidArmv7a)
}

val copyGeneratedBinaryForAndroid by tasks.register("copyGeneratedBinaryForAndroid") {
    group = "rust-compiling"
    description = "Copy all generated Android binaries to generated resources folder"
    dependsOn(copyGeneratedBinaryForAndroidArch64, copyGeneratedBinaryForAndroidX8664, copyGeneratedBinaryForAndroidI686, copyGeneratedBinaryForAndroidArmv7a)
}

val copyGeneratedBinariesToCorrectLocation by tasks.register("copyGeneratedBinariesToCorrectLocation") {
    group = "rust-compiling"
    description = "Copy all generated binaries to generated resources folder"
    dependsOn(copyGeneratedBinaryForMacOS, copyGeneratedBinaryForLinux, copyGeneratedBinaryForAndroid) // copyGeneratedBinaryForiOS
}

/**
 * Copy generated bindings to the `anoncreds-kmm` module
 */
val copyBindings by tasks.register<Copy>("copyBindings") {
    group = "rust-compiling"
    description = "Copy generated bindings to the `anoncreds-kmm` module"
    from(buildDir.resolve("generated"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generated"))
    dependsOn(copyGeneratedBinariesToCorrectLocation)
}

/**
 * Copy generated dylib to correct location
 */
val copyAnoncredsBinariesToProcessedResources by tasks.register<Copy>("copyAnoncredsBinariesToProcessedResources") {
    group = "rust-compiling"
    description = "Copy generated AnonCreds binaries to generated resources folder"
    include("*.so", "*.a", "*.d", "*.dylib")
    from(rootDir.parentFile.resolve("target").resolve("release"))
    into(rootDir.resolve("anoncreds-kmp").resolve("build").resolve("generatedResources").resolve("jvm").resolve("main"))
    dependsOn(buildAnoncredsLib)
}

/**
 * Generate rust documentation
 */
val generateDocumentation by tasks.register<Exec>("rustDoc") {
    group = "documentation"
    description = "Generate rust documentation"
    commandLine("cargo", "doc")
    dependsOn(buildAnonCredWrapper)
}

// Verification Tasks

/**
 * Verify that all used rust targets are installed
 */
val verifyCrateTargets by tasks.register<Exec>("verifyCrateTargets") {
    group = "install"
    description = "Verify that all used rust targets are installed"
    val targets = if (os.isMacOsX) {
        listOf(
            "armv7-linux-androideabi",
            "i686-linux-android",
            "aarch64-linux-android",
            "x86_64-linux-android",
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu"
        )
    } else if (os.isLinux) {
        listOf(
            "armv7-linux-androideabi",
            "i686-linux-android",
            "aarch64-linux-android",
            "x86_64-linux-android",
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu"
        )
    } else {
        throw GradleException("Unsupported OS ${os.name}")
    }

    // Get all available targets
    val availableTargetsString = execWithOutput {
        commandLine("rustup", "target", "list")
    }
    var output = ""
    for (target in targets) {
        output += if (availableTargetsString.contains("$target (installed)").not()) {
            // Install target if not installed
            execWithOutput {
                commandLine("rustup", "target", "add", target)
            }
            "Installing target: $target\n"
        } else {
            "Target $target already installed\n"
        }
    }
    commandLine("echo", output)
}

/**
 * Verify that Rust is installed and if not, install it
 */
val verifyRustInstalled by tasks.register("verifyRustInstalled") {
    group = "install"
    description = "Verify that Rust is installed and if not, install it"
    if (os.isLinux || os.isMacOsX) {
        val output = execWithOutput {
            commandLine("rustup", "--version")
        }
        if (output.contains("command not found")) {
            // Install Rust
            execWithOutput {
                commandLine("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
            }
            execWithOutput {
                commandLine("echo", "Installed Rust")
            }
        } else {
            execWithOutput {
                commandLine("echo", "Rust is already installed")
            }
        }
    } else {
        throw GradleException("Unsupported OS ${os.name}")
    }
}

/**
 * Verify that all needed tools for Rust are installed correctly
 */
val verifyRust by tasks.register("verifyRust") {
    group = "install"
    description = "Verify that all needed tools for Rust are installed correctly"
    doFirst {
        verifyRustInstalled
    }
    dependsOn(verifyRustInstalled, verifyCrateTargets)
}

// Installation Tasks

val installCargoNDK by tasks.register<Exec>("installCargoNDK") {
    group = "install"
    description = "Install Cargo-NDK"
    commandLine("cargo", "install", "cargo-ndk")
}

val installHomeBrew by tasks.register("installHomeBrew") {
    group = "install"
    description = "Install HomeBrew"
    onlyIf {
        os.isMacOsX
    }
    val output = execWithOutput {
        commandLine("brew", "--version")
    }
    if (output.contains("command not found").not()) {
        execWithOutput {
            commandLine("echo", "HomeBrew already installed")
        }
    } else {
        execWithOutput {
            commandLine("/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
        }
    }
}

val updateLinuxApt by tasks.register<Exec>("updateLinuxApt") {
    group = "install"
    description = "Update Linux Apt"
    onlyIf {
        os.isLinux
    }
    commandLine("apt-get", "update", "-y")
}

val installMacToolChain by tasks.register<Exec>("installMacToolChain") {
    group = "install"
    description = "Install Mac ToolChain"
    onlyIf {
        os.isMacOsX
    }
    commandLine("brew", "tap", "messense/macos-cross-toolchains")
}

val installx8664LinuxGNU by tasks.register<Exec>("installx86_64LinuxGNU") {
    group = "install"
    description = "Install Linux GNU for x86_64"
    if (os.isMacOsX) {
        commandLine("brew", "install", "x86_64-unknown-linux-gnu")
    } else if (os.isLinux) {
        commandLine("apt-get", "install", "-y", "gcc-x86-64-linux-gnu")
    } else {
        throw GradleException("${os.name} is not supported. Need to switch to macOS or Linux")
    }
}

val installAarch64LinuxGNU by tasks.register<Exec>("installAarch64LinuxGNU") {
    group = "install"
    description = "Install Linux GNU for aarch64"
    if (os.isMacOsX) {
        commandLine("brew", "install", "aarch64-unknown-linux-gnu")
    } else if (os.isLinux) {
        commandLine("apt-get", "install", "-y", "gcc-4.8-aarch64-linux-gnu")
    } else {
        throw GradleException("${os.name} is not supported. Need to switch to macOS or Linux")
    }
}

/**
 * Install all required compiler tools that is needed for this project
 * - Homebrew for macOS
 * - MacToolChains for macOS
 * - Update APT for Linux
 * - x86_64-linux-gnu for macOS & Linux
 * - arch64-linux-gnu for macOS & Linux
 */
val requiredInstallation by tasks.register("RequiredInstallation") {
    group = "install"
    description = """
        Install all required compiler tools that is needed for this project
        - Homebrew for macOS
        - MacToolChains for macOS
        - Update APT for Linux
        - x86_64-linux-gnu for macOS & Linux
        - arch64-linux-gnu for macOS & Linux
    """.trimIndent()
    dependsOn(installHomeBrew, updateLinuxApt, installMacToolChain, installx8664LinuxGNU, installAarch64LinuxGNU, installCargoNDK)
}

val deleteRustSrcFiles by tasks.register<Delete>("deleteRustSrcFiles") {
    group = "rust"
    delete(
        fileTree(rootDir.resolve("anoncred-wrapper-rust").resolve("src"))
    )
}

val moveRustSrcFiles by tasks.register<Copy>("moveRustSrcFiles") {
    group = "rust"
    description = "Move rust src files from main rust folder to our sub module folder to generate all needed code"
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    from(
        fileTree(rootDir.parentFile.resolve("uniffi").resolve("src"))
    )
    into(rootDir.resolve("anoncred-wrapper-rust").resolve("src"))
    dependsOn(deleteRustSrcFiles)
}

/**
 * The main build Rust lib task. It will do the following:
 * - Build the lib
 * - Generate the bindings
 * - Move the generated bindings to the lib module to be used in Kotlin KMM
 */
val buildRust by tasks.register("buildRust") {
    group = "rust"
    description = """
        The main build Rust lib task. It will do the following:
        - Move Rust src files
        - Build the lib
        - Generate the bindings
        - Move the generated bindings to the lib module to be used in Kotlin KMM
    """.trimIndent()
    doFirst {
        moveRustSrcFiles
    }
    mustRunAfter(moveRustSrcFiles)
    dependsOn(moveRustSrcFiles, requiredInstallation, verifyRust, copyBindings, copyAnoncredsBinariesToProcessedResources)
}
