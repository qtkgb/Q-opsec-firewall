package com.qopsec.firewall.data

import android.content.Context
import android.util.Base64
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * App-lock passcode store. Fixes the APK-review findings F-1 (lock was a no-op) and F-2
 * (passcode stored in plaintext): the passcode is NEVER stored — only a salted, slow
 * PBKDF2-HMAC-SHA256 hash is kept, and the gate actually blocks the UI (see MainActivity).
 *
 * (Future hardening: wrap the verifier key with the Android Keystore / add BiometricPrompt.)
 */
class LockStore private constructor(context: Context) {

    private val prefs =
        context.applicationContext.getSharedPreferences("qopsec_lock", Context.MODE_PRIVATE)

    private val _enabled = MutableStateFlow(prefs.contains(KEY_HASH))
    val enabled: StateFlow<Boolean> = _enabled.asStateFlow()

    val isEnabled: Boolean get() = _enabled.value

    /** Whether biometric unlock is opted in (passcode stays the source of truth + fallback). */
    private val _biometric = MutableStateFlow(prefs.getBoolean(KEY_BIO, false))
    val biometricEnabled: StateFlow<Boolean> = _biometric.asStateFlow()
    val isBiometric: Boolean get() = _biometric.value

    fun setBiometric(on: Boolean) {
        prefs.edit().putBoolean(KEY_BIO, on).apply()
        _biometric.value = on
    }

    fun setPasscode(passcode: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        prefs.edit()
            .putString(KEY_SALT, b64(salt))
            .putString(KEY_HASH, b64(pbkdf2(passcode, salt, ITERATIONS)))
            .putInt(KEY_ITER, ITERATIONS)
            .apply()
        _enabled.value = true
    }

    fun verify(passcode: String): Boolean {
        val salt = prefs.getString(KEY_SALT, null)?.let { unb64(it) } ?: return false
        val hash = prefs.getString(KEY_HASH, null)?.let { unb64(it) } ?: return false
        val iter = prefs.getInt(KEY_ITER, ITERATIONS)
        return constantTimeEquals(pbkdf2(passcode, salt, iter), hash)
    }

    fun clear() {
        prefs.edit().remove(KEY_SALT).remove(KEY_HASH).remove(KEY_ITER).remove(KEY_BIO).apply()
        _enabled.value = false
        _biometric.value = false
    }

    private fun pbkdf2(passcode: String, salt: ByteArray, iter: Int): ByteArray {
        val spec = PBEKeySpec(passcode.toCharArray(), salt, iter, 256)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    private fun b64(x: ByteArray): String = Base64.encodeToString(x, Base64.NO_WRAP)
    private fun unb64(s: String): ByteArray = Base64.decode(s, Base64.NO_WRAP)

    companion object {
        private const val KEY_SALT = "salt"
        private const val KEY_HASH = "hash"
        private const val KEY_ITER = "iter"
        private const val KEY_BIO = "biometric"
        private const val ITERATIONS = 120_000

        @Volatile private var INSTANCE: LockStore? = null

        fun get(context: Context): LockStore =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: LockStore(context).also { INSTANCE = it }
            }
    }
}
