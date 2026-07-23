// Kotlin/Native (linuxX64) build for the Causalontology Kotlin binding.
//
// Produces the `causalontology-kotlin` klib and its Maven Central metadata.
// The library sources are the shared, pure-Kotlin core under src/ (the JVM
// helper Io.kt and the JVM test runner Conformance.kt are excluded; POSIX
// actuals for the three OS touches live in kmp-linuxX64/).

plugins {
    kotlin("multiplatform") version "2.0.21"
    id("maven-publish")
    id("signing")
}

group = "io.github.ai-university-aiu"
version = "4.0.0"

repositories {
    mavenCentral()
}

kotlin {
    linuxX64()

    sourceSets {
        val commonMain by getting {
            kotlin.srcDir("src")
            kotlin.srcDir("kmp-common")
            kotlin.exclude("**/Io.kt", "**/Conformance.kt")
        }
        val linuxX64Main by getting {
            kotlin.srcDir("kmp-linuxX64")
        }
    }
}

// A javadoc jar is required by Maven Central; klibs have no Javadoc, so ship
// an empty one that satisfies the requirement.
val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
}

publishing {
    publications.withType<MavenPublication>().configureEach {
        artifact(javadocJar)
        pom {
            name.set("causalontology-kotlin")
            description.set(
                "The Kotlin/Native binding of the Causalontology standard - reified " +
                    "causation as a programming-language-neutral standard and shared commons. " +
                    "Pure Kotlin, all cryptography (SHA-2, Ed25519, bignum) hand-built; " +
                    "passes all 137 frozen conformance vectors."
            )
            url.set("https://github.com/ai-university-aiu/causalontology")
            licenses {
                license {
                    name.set("Apache-2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                }
            }
            developers {
                developer {
                    id.set("ai-university-aiu")
                    name.set("AI University (AIU)")
                    email.set("ai.university.aiu@gmail.com")
                }
            }
            scm {
                url.set("https://github.com/ai-university-aiu/causalontology")
                connection.set("scm:git:https://github.com/ai-university-aiu/causalontology.git")
                developerConnection.set("scm:git:https://github.com/ai-university-aiu/causalontology.git")
            }
        }
    }
    repositories {
        maven {
            name = "bundle"
            url = uri(layout.buildDirectory.dir("central-bundle"))
        }
    }
}

signing {
    useGpgCmd()
    sign(publishing.publications)
}

// KMP + signing: the shared javadoc jar's signature is consumed by multiple
// publish tasks. Make every publish task depend on every signing task so
// Gradle's task graph is well-ordered.
tasks.withType<AbstractPublishToMaven>().configureEach {
    dependsOn(tasks.withType<Sign>())
}
