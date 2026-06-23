package com.qopsec.firewall.data

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface RuleDao {

    // Active (not trashed) rules. Stable order (by id) so toggling never reshuffles.
    @Query("SELECT * FROM rule WHERE deletedAt IS NULL ORDER BY id")
    fun allRules(): Flow<List<Rule>>

    /** Enabled, non-trashed rules — the snapshot the matcher reads on the hot path. */
    @Query("SELECT * FROM rule WHERE enabled = 1 AND deletedAt IS NULL ORDER BY priority DESC")
    fun activeRules(): Flow<List<Rule>>

    /** Trashed rules (soft-deleted), newest first. */
    @Query("SELECT * FROM rule WHERE deletedAt IS NOT NULL ORDER BY deletedAt DESC")
    fun trashedRules(): Flow<List<Rule>>

    @Query("SELECT * FROM rule")
    suspend fun allOnce(): List<Rule>

    @Insert
    suspend fun insert(rule: Rule): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(rule: Rule)

    @Update
    suspend fun update(rule: Rule)

    @Delete
    suspend fun delete(rule: Rule)

    @Query("DELETE FROM rule WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("UPDATE rule SET deletedAt = :ts WHERE id = :id")
    suspend fun softDelete(id: Long, ts: Long)

    @Query("UPDATE rule SET deletedAt = NULL WHERE id = :id")
    suspend fun restore(id: Long)

    /** Permanently remove rules trashed before [cutoff] (WorkManager purge). */
    @Query("DELETE FROM rule WHERE deletedAt IS NOT NULL AND deletedAt < :cutoff")
    suspend fun purgeTrashed(cutoff: Long)

    // --- undo journal ---

    @Insert
    suspend fun insertChange(change: RuleChange)

    @Query("SELECT * FROM rule_change ORDER BY id DESC LIMIT 1")
    suspend fun latestChange(): RuleChange?

    /** All entries of a batch, newest first (undo order). */
    @Query("SELECT * FROM rule_change WHERE batchId = :batchId ORDER BY id DESC")
    suspend fun changesInBatch(batchId: String): List<RuleChange>

    @Query("DELETE FROM rule_change WHERE batchId = :batchId")
    suspend fun deleteBatch(batchId: String)

    @Query("SELECT COUNT(*) FROM rule_change")
    fun changeCount(): Flow<Int>

    // --- secure wipe (irreversible) ---

    @Query("DELETE FROM rule WHERE deletedAt IS NOT NULL")
    suspend fun purgeAllTrashed()

    @Query("DELETE FROM rule_change")
    suspend fun clearJournal()

    // --- snapshots (restore points) ---

    @Query("SELECT * FROM rule WHERE deletedAt IS NULL")
    suspend fun activeRulesOnce(): List<Rule>

    @Query("SELECT * FROM snapshot ORDER BY ts DESC")
    fun snapshots(): Flow<List<Snapshot>>

    @Insert
    suspend fun insertSnapshot(snapshot: Snapshot)

    @Delete
    suspend fun deleteSnapshot(snapshot: Snapshot)

    @Query("DELETE FROM snapshot")
    suspend fun clearSnapshots()

    // --- persistent connection history ---

    @Query("SELECT * FROM conn_log ORDER BY ts DESC LIMIT 1000")
    fun connLog(): Flow<List<ConnLog>>

    /** Update an existing flow row in place; returns rows affected (0 = not present). */
    @Query("UPDATE conn_log SET ts = :ts, dstHost = :host, appLabel = :label, ipVersion = :ipv WHERE flowKey = :key")
    suspend fun touchConn(key: String, ts: Long, host: String?, label: String?, ipv: Int): Int

    @Insert
    suspend fun insertConn(c: ConnLog)

    @Query("DELETE FROM conn_log")
    suspend fun clearConn()

    /** Bound the history table to the [keep] most-recent rows. */
    @Query("DELETE FROM conn_log WHERE id NOT IN (SELECT id FROM conn_log ORDER BY ts DESC LIMIT :keep)")
    suspend fun trimConn(keep: Int)
}
