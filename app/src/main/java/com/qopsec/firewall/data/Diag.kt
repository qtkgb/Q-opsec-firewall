package com.qopsec.firewall.data

import android.util.Log

/**
 * Runtime gate for the app's own (Kotlin-side) diagnostic logging, mirroring the user's
 * Settings → Diagnostics level. The native core has the same Off/Simplified/Full gate
 * (see NativeBridge.nativeSetLogLevel). Default OFF, so a shipped build is silent and no
 * connection metadata reaches logcat unless a (tech-savvy) user opts in.
 *
 *  - [life]: lifecycle / summary lines (no destination hostnames) — emitted at SIMPLE and FULL.
 *  - [flow]: per-connection lines that may include a destination host — emitted only at FULL.
 *
 * All lines use the `qopsec_fw` tag so [LogExporter] can capture them.
 */
object Diag {
    private const val TAG = "qopsec_fw"

    @Volatile
    var level: DiagLevel = DiagLevel.OFF

    fun life(msg: String) {
        if (level != DiagLevel.OFF) Log.i(TAG, msg)
    }

    fun flow(msg: String) {
        if (level == DiagLevel.FULL) Log.d(TAG, msg)
    }
}
