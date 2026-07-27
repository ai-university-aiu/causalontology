// Kotlin/Native (linuxX64) build for the Causalontology Kotlin binding.
//
// Produces the `causalontology-kotlin` klib and its Maven Central metadata.
// The library sources are the shared, pure-Kotlin core under src/ (the JVM
// helper Io.kt and the JVM test runner Conformance.kt are excluded; POSIX
// actuals for the three OS touches live in kmp-linuxX64/).
//
// PACKAGING THE SPECIFICATION SCHEMAS
// A Kotlin/Native klib cannot carry loose resource files, so the twenty-one
// JSON Schemas are shipped as compiled-in string constants in the generated
// source src/SpecSchemas.kt (the same technique the Rust binding uses with
// include_str!). Because it sits in the commonMain source directory below it
// is compiled into every published artifact automatically - there is nothing
// to remember to add to a file list. The verifyBundledSchemas task below
// fails the build if that generated source is missing or has drifted from
// spec/schema, so a stale or absent copy can never be published.

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

// The twenty-one schemas vendored into src/SpecSchemas.kt must be byte-for-byte
// identical to spec/schema/*.schema.json. Escape one schema file's text the way
// tools/gen_spec_schemas.py does, then look for that exact entry in the
// generated source; anything else is drift.
fun kotlinLiteral(s: String): String = buildString {
    for (ch in s) {
        val code = ch.code
        when {
            ch == '\\' -> append("\\\\")
            ch == '"' -> append("\\\"")
            ch == '$' -> append("\\\$")
            ch == '\n' -> append("\\n")
            ch == '\r' -> append("\\r")
            ch == '\t' -> append("\\t")
            code in 0x20..0x7E -> append(ch)
            else -> append("\\u%04x".format(code))
        }
    }
}

val verifyBundledSchemas by tasks.registering {
    description = "Fails if the vendored JSON Schemas are missing or have drifted from spec/schema."
    val bundled = file("src/SpecSchemas.kt")
    val specDir = file("../../spec/schema")
    doLast {
        if (!bundled.isFile) {
            throw GradleException(
                "src/SpecSchemas.kt is missing - the published artifact would carry no " +
                    "schemas. Generate it with: python3 tools/gen_spec_schemas.py")
        }
        val text = bundled.readText()
        // Outside a repository checkout there is nothing to compare against;
        // the vendored copy is then the only source of truth, as intended.
        if (!specDir.isDirectory) return@doLast
        val files = (specDir.listFiles() ?: emptyArray())
            .filter { it.name.endsWith(".schema.json") }.sortedBy { it.name }
        if (files.size != 21) {
            throw GradleException("expected 21 schema files in spec/schema, found ${files.size}")
        }
        for (f in files) {
            val entry = "\"${f.name}\" to \"${kotlinLiteral(f.readText())}\""
            if (!text.contains(entry)) {
                throw GradleException(
                    "bundled schema drift: ${f.name} differs from spec/schema - " +
                        "regenerate with: python3 tools/gen_spec_schemas.py")
            }
        }
        logger.lifecycle("bundled schemas verified: ${files.size} files match spec/schema")
    }
}

tasks.named("assemble") { dependsOn(verifyBundledSchemas) }
tasks.named("check") { dependsOn(verifyBundledSchemas) }

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
    dependsOn(verifyBundledSchemas)
}
