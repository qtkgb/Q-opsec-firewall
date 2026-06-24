package com.qopsec.firewall.data

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.qopsec.firewall.MainActivity
import com.qopsec.firewall.R
import java.util.concurrent.TimeUnit

/**
 * Daily background check for a newer GitHub release. When one is found, posts a notification that
 * deep-links into the app (Settings shows the "Update available" banner). Does nothing if the user
 * turned auto-update off.
 */
class UpdateCheckWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        if (!Settings.get(applicationContext).autoUpdateCheck.value) return Result.success()
        return runCatching {
            val info = UpdateManager.get(applicationContext).checkForUpdate()
            if (info != null) notifyUpdate(info.version)
            Result.success()
        }.getOrElse { Result.retry() }
    }

    private fun notifyUpdate(version: String) {
        val ctx = applicationContext
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "App updates", NotificationManager.IMPORTANCE_DEFAULT),
            )
        }
        val open = PendingIntent.getActivity(
            ctx, 0,
            Intent(ctx, MainActivity::class.java).putExtra(EXTRA_SHOW_UPDATE, true),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(ctx, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Update available")
            .setContentText("Q opsec firewall $version is ready to install")
            .setAutoCancel(true)
            .setContentIntent(open)
            .build()
        nm.notify(NOTIF_ID, n)
    }

    companion object {
        private const val CHANNEL_ID = "updates"
        private const val NOTIF_ID = 42
        private const val WORK_NAME = "update-check"
        const val EXTRA_SHOW_UPDATE = "show_update"

        /** Enqueue (or cancel) the daily update check to match the user's setting. */
        fun schedule(context: Context, enabled: Boolean) {
            val wm = WorkManager.getInstance(context)
            if (enabled) {
                val req = PeriodicWorkRequestBuilder<UpdateCheckWorker>(1, TimeUnit.DAYS)
                    .setConstraints(
                        Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build(),
                    )
                    .build()
                wm.enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, req)
            } else {
                wm.cancelUniqueWork(WORK_NAME)
            }
        }
    }
}
