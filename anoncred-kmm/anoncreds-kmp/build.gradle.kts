import org.gradle.internal.os.OperatingSystem
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeCompilation
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

val os: OperatingSystem = OperatingSystem.current()

plugins {
    kotlin("multiplatform")
    id("com.android.library")
    id("maven-publish")
}

apply(plugin = "kotlinx-atomicfu")
version = "1.1.0"
group = "io.iohk.atala.prism.anoncredskmp"

fun KotlinNativeCompilation.anoncredsCinterops(type: String) {
    cinterops {
        val anoncreds_wrapper by creating {
            val crate = this.name
            packageName("$crate.cinterop")
            header(
                buildDir
                    .resolve("generated")
                    .resolve("nativeInterop")
                    .resolve("cinterop")
                    .resolve("headers")
                    .resolve(crate)
                    .resolve("$crate.h")
            )
            tasks.named(interopProcessingTaskName) {
                dependsOn(":anoncred-wrapper-rust:buildRust")
            }
            when (type) {
                "macosX64" -> {
                    extraOpts(
                        "-libraryPath",
                        rootDir
                            .resolve("anoncred-wrapper-rust")
                            .resolve("target")
                            .resolve("x86_64-apple-darwin")
                            .resolve("release")
                            .absolutePath
                    )
                }
                "macosArm64" -> {
                    extraOpts(
                        "-libraryPath",
                        rootDir
                            .resolve("anoncred-wrapper-rust")
                            .resolve("target")
                            .resolve("aarch64-apple-darwin")
                            .resolve("release")
                            .absolutePath
                    )
                }
//                "ios" -> {
//                    extraOpts(
//                        "-libraryPath",
//                        rootDir
//                            .resolve("anoncred-wrapper-rust")
//                            .resolve("target")
//                            .resolve("ios-universal")
//                            .resolve("release")
//                            .absolutePath
//                    )
//                }
                else -> {
                    throw GradleException("Unsupported linking")
                }
            }
        }
    }
}

kotlin {
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "11"
        }
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }
    android {
        publishAllLibraryVariants()
    }

//    if (os.isMacOsX) {
//        macosX64("native") {
//            compilations.getByName("main") {
//                this.anoncredsCinterops("macosX64")
//            }
//        }
//        if (System.getProperty("os.arch") != "x86_64") {
//            macosArm64 {
//                compilations.getByName("main") {
//                    this.anoncredsCinterops("macosArm64")
//                }
//            }
//        }
//    }

/*
    val crateTargetLibDir = rootDir.resolve("anoncred-wrapper-rust").resolve("target").resolve("debug")
    val hostOs = System.getProperty("os.name")
    val isMingwX64 = hostOs.startsWith("Windows")
    val nativeTarget = when {
        hostOs == "Mac OS X" -> {
            if (System.getProperty("os.arch") != "x86_64") {
                macosArm64("native")
            } else {
                macosX64("native")
            }
        }
        hostOs == "Linux" -> linuxArm64("native")
        isMingwX64 -> mingwX64("native")
        else -> throw GradleException("Host OS is not supported in Kotlin/Native.")
    }
    nativeTarget.apply {
        compilations.getByName("main") {
            println("nativeTarget-only-main")
            cinterops {
                val anoncreds_wrapper by creating {
                    val crate = this.name
                    packageName("$crate.cinterop")
                    header(
                        generatedDir.resolve("nativeInterop").resolve("cinterop").resolve("headers")
                            .resolve(crate).resolve("$crate.h")
                    )
                    tasks.named(interopProcessingTaskName) {
                        dependsOn(":anoncred-wrapper-rust:buildRust")
                    }
                    extraOpts("-libraryPath", crateTargetLibDir.absolutePath)
                }
            }
        }
    }
*/

    sourceSets {
        val commonMain by getting {
            val generatedDir = buildDir
                .resolve("generated")
                .resolve("commonMain")
                .resolve("kotlin")
            kotlin.srcDir(generatedDir)
            dependencies {
                implementation("com.squareup.okio:okio:3.4.0")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.4.1")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
            }
        }
        val jvmMain by getting {
            val generatedDir = buildDir
                .resolve("generated")
                .resolve("jvmMain")
                .resolve("kotlin")
            kotlin.srcDir(generatedDir)
            val generatedResources = buildDir
                .resolve("generatedResources")
                .resolve("jvm")
                .resolve("main")
            resources.srcDir(generatedResources)
            dependencies {
                implementation("net.java.dev.jna:jna:5.13.0")
            }
        }
        val jvmTest by getting
        val androidMain by getting {
            val generatedDir = buildDir
                .resolve("generated")
                .resolve("androidMain")
                .resolve("kotlin")
            kotlin.srcDir(generatedDir)
            val generatedResources = buildDir
                .resolve("generatedResources")
                .resolve("android")
                .resolve("main")
                .resolve("jniLibs")
            resources.srcDir(generatedResources)
            dependencies {
                implementation("net.java.dev.jna:jna:5.13.0@aar")
            }
        }
        val androidUnitTest by getting {
            dependencies {
                implementation("junit:junit:4.13.2")
            }
        }
//        if (os.isMacOsX) {
//            val nativeMain by getting { // aka "macosX64"
//                val generatedDir = buildDir
//                    .resolve("generated")
//                    .resolve("nativeMain")
//                    .resolve("kotlin")
//                kotlin.srcDir(generatedDir)
//            }
//            val nativeTest by getting
//            if (System.getProperty("os.arch") != "x86_64") {
//                val macosArm64Main by getting {
//                    dependsOn(nativeMain)
//                }
//            }
//        }
        all {
            languageSettings {
                optIn("kotlin.RequiresOptIn")
                optIn("kotlinx.cinterop.ExperimentalForeignApi")
            }
        }
    }
}

/**
 * Delete the generated `Target` folder that is being generated by Rust Cargo
 */
val rustClean by tasks.register("rustClean") {
    group = "rust"
    delete(projectDir.resolve("target"))
    dependsOn("clean")
}

publishing {
    repositories {
        maven {
            this.name = "GitHubPackages"
            this.url = uri("https://maven.pkg.github.com/input-output-hk/anoncreds-rs/")
            credentials {
                this.username = System.getenv("ATALA_GITHUB_ACTOR")
                this.password = System.getenv("ATALA_GITHUB_TOKEN")
            }
        }
    }
}

android {
    ndkVersion = "26.0.10792818"
    compileSdk = 33
    namespace = "io.iohk.atala.prism.anoncredskmp"
    sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")

    sourceSets["main"].jniLibs {
        setSrcDirs(
            listOf(
                buildDir
                    .resolve("generatedResources")
                    .resolve("android")
                    .resolve("main")
                    .resolve("jniLibs")
            )
        )
    }
    defaultConfig {
        minSdk = 21
        targetSdk = 32
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    /**
     * Because Software Components will not be created automatically for Maven publishing from
     * Android Gradle Plugin 8.0. To opt-in to the future behavior, set the Gradle property android.
     * disableAutomaticComponentCreation=true in the `gradle.properties` file or use the new
     * publishing DSL.
     */
    publishing {
        multipleVariants {
            withSourcesJar()
            withJavadocJar()
            allVariants()
        }
    }
}

afterEvaluate {
    tasks.withType<KotlinCompile> {
        dependsOn(":anoncred-wrapper-rust:buildRust")
    }
    tasks.withType<ProcessResources> {
        dependsOn(":anoncred-wrapper-rust:buildRust")
    }
    tasks.named("lintAnalyzeDebug") {
        this.enabled = false
    }
    tasks.named("lintAnalyzeRelease") {
        this.enabled = false
    }
}
