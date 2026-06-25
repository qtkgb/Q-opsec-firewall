package com.qopsec.firewall.data

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Backs Settings → Diagnostics: dumps THIS app's own logcat (our two tags only) to a cache file
 * and shares it, so a user can capture a log from the phone with no adb. What's actually in the
 * buffer depends on the user's chosen [DiagLevel] — at SIMPLE only lifecycle lines were emitted
 * (no hostnames); at FULL the per-connection lines (with destination hosts) are included. An app
 * may only read its OWN logs, so this never sees other apps.
 */
object LogExporter {

    /** Capture the recent log buffer for our tags into a cache file and return it. */
    fun capture(context: Context): File {
        val dir = File(context.cacheDir, "logs").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val out = File(dir, "qopsec-diag-$stamp.txt")
        val version = runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull() ?: "?"
        out.bufferedWriter().use { w ->
            w.write("Q opsec firewall diagnostic log\n")
            w.write(
                "app v$version  device ${Build.MANUFACTURER} ${Build.MODEL}  " +
                    "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\n",
            )
            w.write("captured ${Date()}\n")
            w.write("diagnostics level: ${Diag.level}\n")
            w.write("----------------------------------------\n")
            // `-d` dumps the buffer and exits. An app may only read its OWN logs, so this is just
            // our process. Filter to our two tags. DEBUG level (ad-block leak investigation) so the
            // per-connection sinkhole/SNI/decide lines (with hostnames) are included.
            runCatching {
                val proc = Runtime.getRuntime().exec(
                    arrayOf("logcat", "-d", "-v", "time", "firewall_core:D", "qopsec_fw:D", "*:S"),
                )
                proc.inputStream.bufferedReader().forEachLine { line ->
                    w.write(line); w.write("\n")
                }
                proc.waitFor()
            }.onFailure { w.write("logcat capture failed: $it\n") }
        }
        return out
    }

    /** Launch a share sheet for the captured log file. */
    fun share(context: Context, file: File) {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "Q opsec firewall diagnostic log")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(
            Intent.createChooser(send, "Share diagnostic log").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }
}
