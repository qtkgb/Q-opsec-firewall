package com.qopsec.firewall.data

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/** A newer release found on GitHub. */
data class UpdateInfo(
    val version: String,        // semver without the leading "v", e.g. "1.2.0"
    val notes: String,          // release body / changelog
    val downloadUrl: String,    // direct .apk asset URL
    val assetName: String,
)

/** Progress/UI state for the in-app updater. */
sealed interface UpdateState {
    data object Idle : UpdateState
    data object Checking : UpdateState
    data object UpToDate : UpdateState
    data class Downloading(val percent: Int) : UpdateState
    data class Error(val message: String) : UpdateState
}

/**
 * Self-updater for the sideloaded build. Checks the project's public GitHub Releases for a newer
 * version, downloads the signed APK, and hands it to the system installer (same signing key ⇒
 * installs over the top, keeps data). Requires the releases to be PUBLIC (no token is embedded in
 * the app). The system always shows its install-confirm UI — this is not a silent updater.
 */
class UpdateManager private constructor(context: Context) {

    private val appContext = context.applicationContext

    private val _available = MutableStateFlow<UpdateInfo?>(null)
    val available: StateFlow<UpdateInfo?> = _available.asStateFlow()

    private val _state = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val state: StateFlow<UpdateState> = _state.asStateFlow()

    /** Installed versionName, e.g. "1.1.0". */
    fun currentVersion(): String =
        runCatching {
            appContext.packageManager.getPackageInfo(appContext.packageName, 0).versionName
        }.getOrNull() ?: "0"

    /**
     * Queries GitHub for the latest release. Returns the [UpdateInfo] if it's newer than the
     * installed build (also stored in [available]); null if up-to-date or on error. Safe to call
     * from a worker or a UI coroutine.
     */
    suspend fun checkForUpdate(): UpdateInfo? = withContext(Dispatchers.IO) {
        _state.value = UpdateState.Checking
        runCatching {
            val conn = (URL(LATEST_URL).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("User-Agent", "QOpSecFirewall-Updater")
                connectTimeout = 15000
                readTimeout = 15000
            }
            val code = conn.responseCode
            if (code != 200) {
                // 404 on this endpoint = no published release, or the repo is still private
                // (anonymous access can't see it). Give a human message, not the raw HTTP error.
                val msg = if (code == 404) "No public release found (is the repo public?)"
                else "Update check failed (HTTP $code)"
                _state.value = UpdateState.Error(msg)
                return@withContext null
            }
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)
            val tag = json.optString("tag_name").trimStart('v', 'V')
            val notes = json.optString("body", "")
            val assets = json.optJSONArray("assets")
            var apkUrl: String? = null
            var apkName = ""
            if (assets != null) {
                for (i in 0 until assets.length()) {
                    val a = assets.getJSONObject(i)
                    val name = a.optString("name")
                    if (name.endsWith(".apk", ignoreCase = true)) {
                        apkUrl = a.optString("browser_download_url")
                        apkName = name
                        break
                    }
                }
            }
            if (tag.isNotEmpty() && apkUrl != null && isNewer(tag, currentVersion())) {
                val info = UpdateInfo(tag, notes, apkUrl!!, apkName)
                _available.value = info
                _state.value = UpdateState.Idle
                info
            } else {
                _available.value = null
                _state.value = UpdateState.UpToDate
                null
            }
        }.getOrElse {
            _state.value = UpdateState.Error("Couldn't reach GitHub — check your connection")
            null
        }
    }

    /**
     * Downloads [info]'s APK into the cache, then launches the system installer. Returns true once
     * the installer was launched (the user still confirms the install themselves).
     */
    suspend fun downloadAndInstall(info: UpdateInfo): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val dir = File(appContext.cacheDir, "updates").apply { mkdirs() }
            // Single slot — overwrite any previous download.
            dir.listFiles()?.forEach { it.delete() }
            val apk = File(dir, info.assetName.ifEmpty { "update.apk" })

            val conn = (URL(info.downloadUrl).openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "QOpSecFirewall-Updater")
                connectTimeout = 15000
                readTimeout = 30000
            }
            val total = conn.contentLength.toLong()
            conn.inputStream.use { input ->
                apk.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    var read: Int
                    var done = 0L
                    while (input.read(buf).also { read = it } != -1) {
                        out.write(buf, 0, read)
                        done += read
                        if (total > 0) {
                            _state.value = UpdateState.Downloading(((done * 100) / total).toInt())
                        }
                    }
                }
            }
            _state.value = UpdateState.Idle
            launchInstaller(apk)
            true
        }.getOrElse { e ->
            _state.value = UpdateState.Error(e.message ?: "Download failed")
            false
        }
    }

    private fun launchInstaller(apk: File) {
        val uri: Uri = FileProvider.getUriForFile(appContext, "${appContext.packageName}.fileprovider", apk)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        appContext.startActivity(intent)
    }

    companion object {
        // PUBLIC repo — anonymous API access (60 req/hr is plenty for a daily check).
        private const val LATEST_URL =
            "https://api.github.com/repos/qtkgb/Q-opsec-firewall/releases/latest"

        /** True if [latest] is a strictly higher semver than [current] (dot-separated ints). */
        fun isNewer(latest: String, current: String): Boolean {
            val a = latest.trim().trimStart('v', 'V').split('.').map { it.toIntOrNull() ?: 0 }
            val b = current.trim().trimStart('v', 'V').split('.').map { it.toIntOrNull() ?: 0 }
            for (i in 0 until maxOf(a.size, b.size)) {
                val x = a.getOrElse(i) { 0 }
                val y = b.getOrElse(i) { 0 }
                if (x != y) return x > y
            }
            return false
        }

        @Volatile private var INSTANCE: UpdateManager? = null

        fun get(context: Context): UpdateManager =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: UpdateManager(context).also { INSTANCE = it }
            }
    }
}
