plugins {
    id("org.jlleitschuh.gradle.ktlint") version "11.6.0"
    kotlin("jvm") version "1.8.20"
}

buildscript {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.8.20")
        classpath("com.android.tools.build:gradle:7.2.2")
        classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.21.0")
    }
}

allprojects {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        google()
        maven { url = uri("https://jitpack.io") }
    }
}

subprojects {
    apply(plugin = "org.jlleitschuh.gradle.ktlint")
    ktlint {
        verbose.set(true)
        outputToConsole.set(true)
        filter {
            val generatedCodePath = rootDir
                .resolve("anoncreds-kmp")
                .resolve("build")
                .resolve("generated")

            exclude(
                "$generatedCodePath/*/*",
                "$generatedCodePath/*",
                "$generatedCodePath/**",
                "$generatedCodePath/**/**"
            )
            exclude("**/generated/**")
            exclude { projectDir.toURI().relativize(it.file.toURI()).path.contains("/generated/") }
            exclude { element -> element.file.path.contains("generated/") }
            exclude { it.file.path.contains("$buildDir/generated/") }
            exclude { it.file.path.contains(layout.buildDirectory.dir("generated").get().toString()) }
        }
    }
}
