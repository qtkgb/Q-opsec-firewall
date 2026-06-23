package com.qopsec.firewall.data

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/** Periodically re-downloads the enabled ad/tracker blocklists and rebuilds the matcher. */
class BlocklistUpdateWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        return runCatching {
            BlocklistManager.get(applicationContext).updateAllBlocking()
            Result.success()
        }.getOrElse { Result.retry() }
    }
}
