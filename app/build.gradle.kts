import com.android.build.gradle.AppExtension
import com.android.build.gradle.internal.api.BaseVariantOutputImpl
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

// Release signing — reads keystore.properties (kept out of version control).
// Absent file => release signingConfig stays null and a release build is unsigned.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

android {
    namespace = "com.qopsec.firewall"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.qopsec.firewall"
        minSdk = 29          // Android 10 — floor for getConnectionOwnerUid (Phase 1)
        targetSdk = 35
        versionCode = 6
        versionName = "1.1.3"
    }

    signingConfigs {
        if (keystorePropsFile.exists()) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment.ktx)
}

// --- Rust core (firewall_core) -> jniLibs, cross-compiled with cargo-ndk ---
// Only wires in if the Rust toolchain is present, so the app still builds without it
// (NativeBridge then reports "not built"). See RUST_SETUP.md. Re-sync Gradle after
// installing Rust so this block re-evaluates.
run {
    val cargoBin = File(System.getProperty("user.home"), ".cargo/bin/cargo")
    val rustDir = file("$rootDir/rust")
    if (cargoBin.exists() && rustDir.exists()) {
        val rustAbis = listOf("arm64-v8a", "x86_64") // emulator (Apple Silicon = arm64) + Intel
        val buildRustCore = tasks.register<Exec>("buildRustCore") {
            workingDir = rustDir
            runCatching { android.ndkDirectory.absolutePath }.getOrNull()?.let {
                environment("ANDROID_NDK_HOME", it)
            }
            val cmd = mutableListOf(cargoBin.absolutePath, "ndk")
            rustAbis.forEach { cmd += listOf("-t", it) }
            cmd += listOf("-o", file("src/main/jniLibs").absolutePath, "build", "--release")
            commandLine(cmd)
        }
        tasks.named("preBuild").configure { dependsOn(buildRustCore) }
    }
}

// Name the release artifact Q-OpSec-Firewall.apk instead of app-release.apk.
extensions.getByType<AppExtension>().applicationVariants.all {
    val isRelease = buildType.name == "release"
    outputs.all {
        if (isRelease) (this as BaseVariantOutputImpl).outputFileName = "Q-OpSec-Firewall.apk"
    }
}
