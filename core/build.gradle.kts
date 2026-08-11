plugins {
    alias(libs.plugins.kotlin.jvm)
}

// Deliberately a plain JVM module with no Android dependencies: the packet parsing,
// checksum and rule-matching code is the easiest part of a firewall to get subtly wrong,
// so it lives where it can be unit tested without an emulator.
kotlin {
    jvmToolchain(17)
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}
