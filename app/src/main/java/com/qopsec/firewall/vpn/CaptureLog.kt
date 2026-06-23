package com.qopsec.firewall.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Process-wide running indicator for the capture/filter service. Connection data now lives
 * in the persistent `conn_log` table (see RuleRepository.connLog) — this only tracks whether
 * the tunnel is active, so the UI header reflects state across screens.
 */
object CaptureLog {

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    /** Kill switch state — true = deny-all (tunnel up, everything blocked). */
    private val _killed = MutableStateFlow(false)
    val killed: StateFlow<Boolean> = _killed.asStateFlow()

    fun setRunning(value: Boolean) {
        _running.value = value
    }

    fun setKilled(value: Boolean) {
        _killed.value = value
    }
}
