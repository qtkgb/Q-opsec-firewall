package com.qopsec.firewall.data

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/**
 * Permanently removes rules that have sat in the Trash longer than the retention window
 * (30 days). Runs daily via WorkManager; until it fires, trashed rules stay restorable.
 */
class TrashPurgeWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val dao = AppDatabase.get(applicationContext).ruleDao()
        dao.purgeTrashed(System.currentTimeMillis() - RETENTION_MS)
        dao.trimConn(CONN_LOG_KEEP)   // bound the persistent history
        return Result.success()
    }

    companion object {
        const val RETENTION_DAYS = 30L
        val RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000L
        const val CONN_LOG_KEEP = 2000
    }
}
