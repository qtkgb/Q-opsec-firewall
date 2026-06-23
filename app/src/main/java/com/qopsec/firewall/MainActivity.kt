package com.qopsec.firewall

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.qopsec.firewall.data.BiometricAuth
import com.qopsec.firewall.data.BlocklistManager
import com.qopsec.firewall.data.BlocklistUpdateWorker
import com.qopsec.firewall.data.LockStore
import com.qopsec.firewall.data.Settings
import com.qopsec.firewall.data.TrashPurgeWorker
import com.qopsec.firewall.ui.CaptureScreen
import com.qopsec.firewall.ui.FirewallTheme
import com.qopsec.firewall.ui.LockScreen
import com.qopsec.firewall.ui.PerAppScreen
import com.qopsec.firewall.ui.SettingsScreen
import com.qopsec.firewall.vpn.VpnFirewallService
import java.util.concurrent.TimeUnit

class MainActivity : FragmentActivity() {

    // VPN consent dialog result -> start the service only if the user approved.
    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) startCaptureService()
        }

    private val notifPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* best-effort */ }

    private val lock by lazy { LockStore.get(this) }
    private val appSettings by lazy { Settings.get(this) }
    // true = the app-lock gate is showing. Re-armed whenever we leave the foreground.
    private val locked = mutableStateOf(false)
    // true = show the "another VPN is active, starting will disconnect it" confirm dialog.
    private val showVpnConflict = mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        locked.value = lock.isEnabled
        maybeRequestNotifPermission()
        scheduleTrashPurge()
        BlocklistManager.get(this)   // load cached blocklists into the matcher
        scheduleBlocklistUpdate()
        setContent {
            val themeMode by appSettings.themeMode.collectAsStateWithLifecycle()
            FirewallTheme(themeMode = themeMode) {
                var showSettings by remember { mutableStateOf(false) }
                var showPerApp by remember { mutableStateOf(false) }
                val isLocked by locked
                when {
                    isLocked -> LockScreen(
                        onUnlock = { pin ->
                            val ok = lock.verify(pin)
                            if (ok) locked.value = false
                            ok
                        },
                        onBiometric = if (lock.isBiometric && BiometricAuth.available(this)) {
                            { promptBiometric { locked.value = false } }
                        } else null,
                    )
                    showPerApp -> PerAppScreen(onBack = { showPerApp = false })
                    showSettings -> SettingsScreen(
                        onBack = { showSettings = false },
                        onPerApp = { showPerApp = true },
                    )
                    else -> CaptureScreen(
                        onStart = ::requestStart,
                        onStop = ::stopCaptureService,
                        onKill = ::setKill,
                        onSettings = { showSettings = true },
                    )
                }

                if (showVpnConflict.value) {
                    AlertDialog(
                        onDismissRequest = { showVpnConflict.value = false },
                        title = { Text("Another VPN is active") },
                        text = {
                            Text(
                                "Starting the firewall will disconnect your current VPN " +
                                    "(e.g. Mullvad or NordVPN) — Android allows only one VPN at a time.",
                            )
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                showVpnConflict.value = false
                                prepareAndStart()
                            }) { Text("Continue") }
                        },
                        dismissButton = {
                            TextButton(onClick = { showVpnConflict.value = false }) { Text("Cancel") }
                        },
                    )
                }
            }
        }
    }

    /** Entry from the Start button: warn first if another VPN owns the tunnel. */
    private fun requestStart() {
        if (anotherVpnActive()) showVpnConflict.value = true else prepareAndStart()
    }

    private fun anotherVpnActive(): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java)
        return cm.allNetworks.any {
            cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }

    /** Re-arm the lock when the app leaves the foreground, so returning requires the passcode. */
    override fun onStop() {
        super.onStop()
        if (lock.isEnabled) locked.value = true
    }

    /** When we come to the foreground locked, offer biometrics straight away (passcode is fallback). */
    override fun onStart() {
        super.onStart()
        if (locked.value && lock.isBiometric && BiometricAuth.available(this)) {
            promptBiometric { locked.value = false }
        }
    }

    /** Show the system biometric prompt; [onSuccess] runs on the main thread when authenticated. */
    private fun promptBiometric(onSuccess: () -> Unit) {
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock Q opsec firewall")
            .setSubtitle("Use your fingerprint or face")
            .setNegativeButtonText("Use passcode")
            .setAllowedAuthenticators(BiometricAuth.AUTHENTICATORS)
            .build()
        runCatching { prompt.authenticate(info) }
    }

    private fun prepareAndStart() {
        // Returns an intent if the user hasn't yet consented to this app being the VPN.
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else startCaptureService()
    }

    private fun startCaptureService() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, VpnFirewallService::class.java).setAction(VpnFirewallService.ACTION_START)
        )
    }

    private fun stopCaptureService() {
        startService(
            Intent(this, VpnFirewallService::class.java).setAction(VpnFirewallService.ACTION_STOP)
        )
    }

    private fun setKill(on: Boolean) {
        startService(
            Intent(this, VpnFirewallService::class.java).setAction(
                if (on) VpnFirewallService.ACTION_KILL_ON else VpnFirewallService.ACTION_KILL_OFF
            )
        )
    }

    private fun scheduleTrashPurge() {
        val req = PeriodicWorkRequestBuilder<TrashPurgeWorker>(1, TimeUnit.DAYS).build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "trash-purge", ExistingPeriodicWorkPolicy.KEEP, req,
        )
    }

    private fun scheduleBlocklistUpdate() {
        val req = PeriodicWorkRequestBuilder<BlocklistUpdateWorker>(1, TimeUnit.DAYS)
            .setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build(),
            )
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "blocklist-update", ExistingPeriodicWorkPolicy.KEEP, req,
        )
    }

    private fun maybeRequestNotifPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
