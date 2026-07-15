// Minimal file access for Kotlin/JVM (standard library / JDK only).
// Encapsulates the only three OS touches the binding needs: read a whole file,
// list a directory, and read an environment variable.
package org.causalontology

import java.io.File

fun readFile(path: String): String = File(path).readText(Charsets.UTF_8)

fun listDir(path: String): List<String> =
    (File(path).list()?.toList() ?: emptyList()).sorted()

fun getEnvVar(name: String): String? = System.getenv(name)
