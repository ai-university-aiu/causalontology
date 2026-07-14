// Minimal POSIX file access for Kotlin/Native (no dependencies, no cinterop defs).
// Encapsulates the only three OS touches the binding needs: read a whole file,
// list a directory, and read an environment variable.
package org.causalontology

import kotlinx.cinterop.*
import platform.posix.*

@OptIn(ExperimentalForeignApi::class)
fun readFile(path: String): String {
    val f = fopen(path, "rb") ?: throw RuntimeException("cannot open $path")
    try {
        fseek(f, 0, SEEK_END)
        val size = ftell(f)
        fseek(f, 0, SEEK_SET)
        if (size <= 0L) return ""
        val bytes = ByteArray(size.toInt())
        val read = bytes.usePinned { pinned ->
            fread(pinned.addressOf(0), 1u, size.toULong(), f)
        }
        if (read.toLong() != size) throw RuntimeException("short read on $path")
        return bytes.decodeToString()
    } finally {
        fclose(f)
    }
}

@OptIn(ExperimentalForeignApi::class)
fun listDir(path: String): List<String> {
    val d = opendir(path) ?: throw RuntimeException("cannot open directory $path")
    val names = mutableListOf<String>()
    try {
        while (true) {
            val entry = readdir(d) ?: break
            val name = entry.pointed.d_name.toKString()
            if (name != "." && name != "..") names.add(name)
        }
    } finally {
        closedir(d)
    }
    return names.sorted()
}

@OptIn(ExperimentalForeignApi::class)
fun getEnvVar(name: String): String? = getenv(name)?.toKString()
