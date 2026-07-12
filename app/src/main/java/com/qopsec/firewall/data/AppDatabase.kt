package com.qopsec.firewall.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [Rule::class, RuleChange::class, ConnLog::class, Snapshot::class, UsageBucket::class, AppUsage::class],
    version = 7,
    exportSchema = false,
)
abstract class AppDatabase : RoomDatabase() {

    abstract fun ruleDao(): RuleDao

    abstract fun usageDao(): UsageDao

    companion object {
        @Volatile private var INSTANCE: AppDatabase? = null

        // v2: add Trash column (soft-delete). Plain ADD COLUMN — preserves existing rules.
        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE rule ADD COLUMN deletedAt INTEGER")
            }
        }

        // v3: add the undo journal table.
        private val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `rule_change` (" +
                        "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "`op` TEXT NOT NULL, `before` TEXT, `after` TEXT, " +
                        "`batchId` TEXT NOT NULL, `ts` INTEGER NOT NULL)"
                )
            }
        }

        // v4: persistent connection history.
        private val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `conn_log` (" +
                        "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "`flowKey` TEXT NOT NULL, `ts` INTEGER NOT NULL, " +
                        "`appUid` INTEGER NOT NULL, `appLabel` TEXT, `packageName` TEXT, " +
                        "`proto` INTEGER NOT NULL, `ipVersion` INTEGER NOT NULL, " +
                        "`dstIp` TEXT NOT NULL, `dstHost` TEXT, `dstPort` INTEGER NOT NULL)"
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS `index_conn_log_flowKey` " +
                        "ON `conn_log` (`flowKey`)"
                )
            }
        }

        // v5: add restore-point snapshots.
        private val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `snapshot` (" +
                        "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "`label` TEXT NOT NULL, `rulesJson` TEXT NOT NULL, " +
                        "`ts` INTEGER NOT NULL, `ruleCount` INTEGER NOT NULL)"
                )
            }
        }

        // v6: hourly traffic-usage buckets for the Stats tab.
        private val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `usage_bucket` (" +
                        "`hourStart` INTEGER PRIMARY KEY NOT NULL, " +
                        "`wifiRx` INTEGER NOT NULL, `wifiTx` INTEGER NOT NULL, " +
                        "`mobileRx` INTEGER NOT NULL, `mobileTx` INTEGER NOT NULL)"
                )
            }
        }

        // v7: per-app hourly traffic buckets (Stats per-app breakdown).
        private val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `app_usage` (" +
                        "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "`hourStart` INTEGER NOT NULL, `appKey` TEXT NOT NULL, " +
                        "`label` TEXT NOT NULL, `rx` INTEGER NOT NULL, `tx` INTEGER NOT NULL)"
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS `index_app_usage_hourStart_appKey` " +
                        "ON `app_usage` (`hourStart`, `appKey`)"
                )
            }
        }

        fun get(context: Context): AppDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "qopsec.db",
                ).addMigrations(
                    MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6,
                    MIGRATION_6_7,
                ).build().also { INSTANCE = it }
            }
    }
}
