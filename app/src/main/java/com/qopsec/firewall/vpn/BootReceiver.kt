package com.qopsec.firewall.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.qopsec.firewall.data.Settings

/**
 * Boot-lock: if enabled, bring the firewall up deny-all on device boot, so nothing leaves the
 * device until the user unlocks (toggles the kill switch off). Only works if VPN consent was
 * already granted (we can't show the consent dialog from a receiver) — otherwise it's a no-op
 * and the user starts it from the app.
 *
 * Note: Android 14+ can block starting a foreground service from BOOT_COMPLETED, so this is
 * best-effort (wrapped). The robust OS-level equivalent is "Always-on VPN" + "Block connections
 * without VPN" in system VPN settings.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!Settings.get(context).bootLock.value) return
        if (VpnService.prepare(context) != null) return   // consent not granted yet

        runCatching {
            ContextCompat.startForegroundService(
                context,
                Intent(context, VpnFirewallService::class.java)
                    .setAction(VpnFirewallService.ACTION_START)
                    .putExtra(VpnFirewallService.EXTRA_BOOT_LOCK, true),
            )
        }
    }
}
