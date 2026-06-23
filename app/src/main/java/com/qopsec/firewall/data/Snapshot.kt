package com.qopsec.firewall.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * A restore point: a named, timestamped capture of the active rule set ([rulesJson] = a JSON
 * array of rules). Restoring replaces the current active rules with these. An auto-snapshot is
 * taken before a restore so the restore itself can be reversed.
 */
@Entity(tableName = "snapshot")
data class Snapshot(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val label: String,
    val rulesJson: String,
    val ts: Long = System.currentTimeMillis(),
    val ruleCount: Int,
)
