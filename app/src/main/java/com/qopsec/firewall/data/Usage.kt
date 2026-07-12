package com.qopsec.firewall.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Traffic that ran THROUGH the firewall, in hourly buckets ([hourStart] = epoch ms floored
 * to the hour), split by the network that carried it. Hourly is the finest grain the Stats
 * tab shows; the day/week/month views aggregate these rows. Only counted while the tunnel
 * is up — which is exactly the question the tab answers ("how much ran through the app").
 */
@Entity(tableName = "usage_bucket")
data class UsageBucket(
    @PrimaryKey val hourStart: Long,
    val wifiRx: Long = 0,
    val wifiTx: Long = 0,
    val mobileRx: Long = 0,
    val mobileTx: Long = 0,
)

@Dao
interface UsageDao {

    /** Accumulate a sample delta into its hour bucket (insert-or-add; minSdk 29 ⇒ SQLite ≥ 3.28). */
    @Query(
        "INSERT INTO usage_bucket (hourStart, wifiRx, wifiTx, mobileRx, mobileTx) " +
            "VALUES (:hour, :wifiRx, :wifiTx, :mobileRx, :mobileTx) " +
            "ON CONFLICT(hourStart) DO UPDATE SET " +
            "wifiRx = wifiRx + :wifiRx, wifiTx = wifiTx + :wifiTx, " +
            "mobileRx = mobileRx + :mobileRx, mobileTx = mobileTx + :mobileTx",
    )
    suspend fun add(hour: Long, wifiRx: Long, wifiTx: Long, mobileRx: Long, mobileTx: Long)

    @Query("SELECT * FROM usage_bucket WHERE hourStart >= :since ORDER BY hourStart")
    fun since(since: Long): Flow<List<UsageBucket>>

    @Query("DELETE FROM usage_bucket")
    suspend fun clearAll()

    /** Retention: hourly rows are tiny (~9k/year) but don't keep them forever. */
    @Query("DELETE FROM usage_bucket WHERE hourStart < :cutoff")
    suspend fun trim(cutoff: Long)
}
