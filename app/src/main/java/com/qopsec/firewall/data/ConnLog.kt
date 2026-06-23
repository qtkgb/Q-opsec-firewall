package com.qopsec.firewall.data

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Persistent connection history. One row per distinct flow ([flowKey] =
 * "uid|proto|dstIp|dstPort"), updated on each re-sighting — so the Connections view survives
 * restarts and powers "decide from history". The verdict is NOT stored; it's computed live
 * from current rules, so the list always reflects present policy.
 */
@Entity(tableName = "conn_log", indices = [Index(value = ["flowKey"], unique = true)])
data class ConnLog(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val flowKey: String,
    val ts: Long,                 // last seen
    val appUid: Int,
    val appLabel: String?,
    val packageName: String?,
    val proto: Int,               // 6 TCP, 17 UDP, 0 other
    val ipVersion: Int,
    val dstIp: String,
    val dstHost: String?,
    val dstPort: Int,
)
