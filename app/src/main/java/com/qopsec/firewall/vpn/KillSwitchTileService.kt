package com.qopsec.firewall.vpn

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.qopsec.firewall.MainActivity

/**
 * Quick Settings tile for the kill switch. Toggles deny-all on the running firewall straight
 * from the notification shade. If the firewall isn't running, it opens the app (consent/start
 * needs the activity). Runs in the app process, so it reads live state from [CaptureLog].
 */
class KillSwitchTileService : TileService() {

    override fun onStartListening() = updateTile()

    override fun onClick() {
        if (!CaptureLog.running.value) {
            openApp()
            return
        }
        val turnOn = !CaptureLog.killed.value
        startService(
            Intent(this, VpnFirewallService::class.java).setAction(
                if (turnOn) VpnFirewallService.ACTION_KILL_ON else VpnFirewallService.ACTION_KILL_OFF,
            ),
        )
        updateTile()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        tile.state = when {
            !CaptureLog.running.value -> Tile.STATE_UNAVAILABLE
            CaptureLog.killed.value -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }
        tile.label = "Kill switch"
        tile.updateTile()
    }

    @Suppress("DEPRECATION")
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE),
            )
        } else {
            startActivityAndCollapse(intent)
        }
    }
}
