package com.qopsec.firewall.data

import android.content.Context
import androidx.biometric.BiometricManager

/**
 * Thin wrapper over [BiometricManager]. We use BIOMETRIC_WEAK (fingerprint/face) as an unlock
 * shortcut for the app-lock; the PBKDF2 passcode in [LockStore] stays the source of truth and the
 * fallback, so we don't need a Keystore-bound CryptoObject here (the gate is UI access, not data).
 */
object BiometricAuth {

    const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_WEAK

    /** True if the device has biometrics enrolled and usable right now. */
    fun available(context: Context): Boolean =
        BiometricManager.from(context).canAuthenticate(AUTHENTICATORS) ==
            BiometricManager.BIOMETRIC_SUCCESS
}
