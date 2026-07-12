package com.qopsec.firewall.data

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Per-app connection export (the ↓ button on a Connections app group): dumps every recorded
 * flow of one app to a plain-text file and opens the share sheet — so a long destination list
 * can be reviewed off-device (e.g. pasted to an assistant to assess what the app talks to).
 * Verdicts are computed against CURRENT rules, same as the Connections list shows them.
 */
object ConnExporter {

    suspend fun export(context: Context, uid: Int, packageName: String?, label: String): File =
        withContext(Dispatchers.IO) {
            val app = context.applicationContext
            val repo = RuleRepository.get(app)
            val blockList = BlockList.get(app)
            val adBlockOn = Settings.get(app).adBlock.value
            val rows = repo.connsForUid(uid)

            val dir = File(app.cacheDir, "logs").apply { mkdirs() }
            val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
            val safe = (packageName ?: label).replace(Regex("[^A-Za-z0-9._-]"), "_")
            val out = File(dir, "qopsec-conns-$safe-$stamp.txt")

            val version = runCatching {
                app.packageManager.getPackageInfo(app.packageName, 0).versionName
            }.getOrNull() ?: "?"
            val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

            var allowed = 0
            var blocked = 0
            var adBlocked = 0
            val lines = rows.map { c ->
                val proto = if (c.proto == 6) "TCP" else if (c.proto == 17) "UDP" else "P${c.proto}"
                val host = c.dstHost
                val isAd = adBlockOn && host != null && blockList.isBlocked(host)
                val action = repo.decide(uid, packageName, c.proto, c.dstIp, host, c.dstPort).action
                val verdict = when {
                    action == Rule.ACTION_DENY -> { blocked++; "blocked" }
                    isAd -> { adBlocked++; "ad-blocked" }
                    else -> { allowed++; "allowed" }
                }
                verdict.padEnd(11) + proto.padEnd(6) +
                    "${host ?: "-"}:${c.dstPort}".padEnd(52) +
                    "${c.dstIp}:${c.dstPort}".padEnd(24) + ts.format(Date(c.ts))
            }

            out.bufferedWriter().use { w ->
                w.write("Q OpSec Firewall — per-app connection export\n")
                w.write("App: $label\n")
                w.write("Package: ${packageName ?: "-"} (uid $uid)\n")
                w.write(
                    "Device: ${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE}" +
                        " · app v$version\n",
                )
                w.write("Exported: ${ts.format(Date())}\n")
                w.write(
                    "Flows: ${rows.size} distinct destinations (persistent history; " +
                        "verdicts reflect current rules)\n",
                )
                w.write("Summary: $allowed allowed · $blocked blocked · $adBlocked ad-blocked\n")
                w.write("\n")
                w.write("VERDICT".padEnd(11) + "PROTO".padEnd(6) + "DESTINATION".padEnd(52) +
                    "IP:PORT".padEnd(24) + "LAST SEEN\n")
                lines.forEach { w.write(it); w.write("\n") }
            }
            Diag.life("exported ${rows.size} conns for ${packageName ?: label}")
            out
        }

    /** Launch a share sheet for the exported list. */
    fun share(context: Context, file: File, label: String) {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "Q opsec firewall — $label connections")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(
            Intent.createChooser(send, "Share connection list").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }
}
