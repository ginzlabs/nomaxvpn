plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing and the build number come from the environment (cmd/ops android).
val keystore: String? = System.getenv("ANDROID_KEYSTORE")

android {
    namespace = "com.example.nomax"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.example.nomax"
        minSdk = 29
        targetSdk = 37
        versionCode = System.getenv("VERSION_CODE")?.toInt() ?: 1
        versionName = System.getenv("VERSION_NAME") ?: "dev"
        buildConfigField("String", "HOST", "\"${System.getenv("NOMAX_HOST") ?: "example.com"}\"")
    }

    signingConfigs {
        if (keystore != null) {
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = "nomax"
                keyPassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // The APK is downloaded from the join page: compressed, the Go library is a third of the size.
    packaging {
        jniLibs.useLegacyPackaging = true
    }
}

dependencies {
    implementation(files("libs/nomaxcore.aar"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
}
