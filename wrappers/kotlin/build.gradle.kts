import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import java.util.*

plugins {
    kotlin("multiplatform") version "1.9.20"
    kotlin("plugin.serialization") version "1.9.0"
//    id("com.android.library") version "7.4.0" apply false
    id("maven-publish")
}

repositories {
    mavenCentral()
}

// Stub secrets to let the project sync and build without the publication values set up
ext["githubUsername"] = null
ext["githubToken"] = null
ext["anoncredsVersion"] = "0.1.0-dev.18"
ext["wrapperVersion"] = "5"

val secretPropsFile = project.rootProject.file("local.properties")
if(secretPropsFile.exists()) {
    secretPropsFile.reader().use {
        Properties().apply {
            load(it)
        }
    }.onEach{ (name, value) ->
        ext[name.toString()] = value
    }
} else {
    ext["githubUsername"] = System.getenv("GITHUB_ACTOR")
    ext["githubToken"] = System.getenv("GITHUB_TOKEN")
}

fun getExtraString(name: String) = ext[name]?.toString()

group = "org.hyperledger.anoncreds"
version = "${getExtraString("anoncredsVersion")}-wrapper.${getExtraString("wrapperVersion")}"

publishing{
    repositories{
        maven{
            name = "github"
            setUrl("https://maven.pkg.github.com/indicio-tech/anoncreds-rs")
            credentials {
                username = getExtraString("githubUsername")
                password = getExtraString("githubToken")
            }
        }
    }

    publications.withType<MavenPublication> {
        pom {
            name.set("Anoncreds-rs Kotlin")
            description.set("Kotlin MPP wrapper around anoncreds-rs")
            url.set("https://github.com/indicio-tech/anoncreds-rs")

            scm{
                url.set("https://github.com/indicio-tech/anoncreds-rs")
            }
        }
    }
}

private enum class PlatformType {
    APPLE,
    ANDROID
}

kotlin {

//    android {
//        compilations.all {
//            compileOptions {
//                sourceCompatibility JavaVersion.VERSION_1_8
//                        targetCompatibility JavaVersion.VERSION_1_8
//            }
//
//            kotlinOptions {
//                jvmTarget = "1.8"
//            }
//        }
//    }

    fun addLibs(libDirectory: String, target: KotlinNativeTarget) {
        target.compilations.getByName("main") {
            val anoncreds_rs by cinterops.creating {
                this.includeDirs("libraries/headers/")
                packageName("anoncreds_rs")
            }
        }

        target.binaries.all {
            linkerOpts("-L${libDirectory}", "-lanoncreds")
            linkerOpts("-Wl,-framework,Security")
        }

    }

    macosX64("macosNative"){
        val libDirectory = "${projectDir}/../../target/x86_64-apple-darwin/release"
        addLibs(libDirectory, this)
    }

    macosArm64(){
        val libDirectory = "${projectDir}/../../target/aarch64-apple-darwin/release"
        addLibs(libDirectory, this)
    }

    iosX64 {
        val libDirectory = "${projectDir}/../../target/x86_64-apple-ios/release"
        addLibs(libDirectory, this)
    }

    iosSimulatorArm64 {
        val libDirectory = "${projectDir}/../../target/aarch64-apple-ios-sim/release"
        addLibs(libDirectory, this)
    }

    iosArm64 {
        val libDirectory = "${projectDir}/../../target/aarch64-apple-ios/release"
        addLibs(libDirectory, this)
    }

//    androidNativeArm64(){
//        val libDirectory = "${projectDir}/../../target/aarch64-linux-android/release"
//        addLibs(libDirectory, this)
//    }
//
//    androidNativeX64(){
//        val libDirectory = "${projectDir}/../../target/i686-linux-android/release"
//        addLibs(libDirectory, this)
//    }
//
//    androidNativeX86(){
//        val libDirectory = "${projectDir}/../../target/x86_64-linux-android/release"
//        addLibs(libDirectory, this)
//    }
//
//    androidNativeArm32(){
//        val libDirectory = "${projectDir}/../../target/armv7-linux-androideabi/release"
//        addLibs(libDirectory, this)
//    }
    
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.5.1")
            }
        }
//        val androidMain by getting
        val commonTest by getting

        all {
            languageSettings.optIn("kotlin.RequiresOptIn")
            languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi")
//            languageSettings.useExperimentalAnnotation("kotlin.RequiresOptIn")
        }
    }
}

//android {
//    namespace = "org.hyperledger.anoncreds-rs-kotlin"
//    compileSdk = 33
//    defaultConfig {
//        minSdk = 24
//    }
//}
