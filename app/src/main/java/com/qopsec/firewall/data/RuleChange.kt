package com.qopsec.firewall.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Undo/replay journal entry. Every rule mutation records one (or several, sharing a
 * [batchId]) of these so a single "Undo" can revert the whole user action.
 *
 * [before]/[after] are JSON snapshots of the affected [Rule]:
 *  - create        → before null, after = new rule
 *  - update/trash/restore → before = prior, after = new
 *  - delete (hard) → before = rule, after null
 * Undo restores [before] (or deletes the created row when before is null).
 */
@Entity(tableName = "rule_change")
data class RuleChange(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val op: String,                 // create | update | trash | restore | delete
    val before: String?,            // JSON of Rule before, or null
    val after: String?,             // JSON of Rule after, or null
    val batchId: String,            // groups a multi-step action for a single undo
    val ts: Long = System.currentTimeMillis(),
)
