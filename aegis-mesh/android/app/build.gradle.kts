plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.google.devtools.ksp")
    id("com.google.dagger.hilt.android")
}

android {
    namespace = "network.aegis.mesh"
    compileSdk = 34

    defaultConfig {
        applicationId = "network.aegis.mesh"
        minSdk = 26
        targetSdk = 34
        versionCode = 2
        versionName = "0.2.0"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    signingConfigs {
        create("release") {
            // Audit fix: signing config (was missing — couldn't install release APK)
            // Set these in ~/.gradle/gradle.properties or environment:
            //   AEGIS_KEYSTORE_FILE, AEGIS_KEYSTORE_PASSWORD,
            //   AEGIS_KEY_ALIAS, AEGIS_KEY_PASSWORD
            storeFile = file(System.getenv("AEGIS_KEYSTORE_FILE") ?: "debug.keystore")
            storePassword = System.getenv("AEGIS_KEYSTORE_PASSWORD") ?: "android"
            keyAlias = System.getenv("AEGIS_KEY_ALIAS") ?: "androiddebugkey"
            keyPassword = System.getenv("AEGIS_KEY_PASSWORD") ?: "android"
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    // Compose BOM
    val composeBom = platform("androidx.compose:compose-bom:2024.09.00")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.4")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.navigation:navigation-compose:2.7.7")

    // Hilt (audit fix: KSP, not Java-only annotationProcessor)
    implementation("com.google.dagger:hilt-android:2.51.1")
    ksp("com.google.dagger:hilt-compiler:2.51.1")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")

    // Foreground service
    implementation("androidx.lifecycle:lifecycle-service:2.8.4")

    // Crypto (audit fix: jdk18on, not deprecated jdk15on)
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}
