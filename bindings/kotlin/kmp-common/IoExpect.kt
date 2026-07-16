// Platform IO for the Causalontology Kotlin binding, as expect declarations.
// The JVM binding uses java.io.File (src/Io.kt); the Kotlin/Native klib
// provides actuals over POSIX. The only three OS touches the binding needs.
package org.causalontology

expect fun readFile(path: String): String
expect fun listDir(path: String): List<String>
expect fun getEnvVar(name: String): String?
