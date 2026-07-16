// Kotlin/Native (linuxX64) actuals for the three OS touches, over POSIX.
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package org.causalontology

import kotlinx.cinterop.*
import platform.posix.*

actual fun getEnvVar(name: String): String? = getenv(name)?.toKString()

actual fun readFile(path: String): String {
    val f = fopen(path, "rb") ?: throw RuntimeException("cannot open: $path")
    try {
        fseek(f, 0, SEEK_END)
        val size = ftell(f)
        fseek(f, 0, SEEK_SET)
        if (size <= 0) return ""
        val buf = ByteArray(size.convert())
        buf.usePinned { pinned ->
            fread(pinned.addressOf(0), 1.convert(), size.convert(), f)
        }
        return buf.decodeToString()
    } finally {
        fclose(f)
    }
}

actual fun listDir(path: String): List<String> {
    val dir = opendir(path) ?: return emptyList()
    val out = mutableListOf<String>()
    try {
        while (true) {
            val entry = readdir(dir) ?: break
            val name = entry.pointed.d_name.toKString()
            if (name != "." && name != "..") out.add(name)
        }
    } finally {
        closedir(dir)
    }
    return out.sorted()
}
