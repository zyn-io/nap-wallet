// Fingerprint unlock for Nap's kept wallet (DECISIONS §151).
//
// One secret — the kept wallet's password — encrypted with an AES key that
// lives in the Android Keystore and works only after a strong biometric says
// yes, once per use; enrolling a new fingerprint invalidates the key. The
// ciphertext sits in the app's private preferences and is useless without it.
package win.cavebro.napvault

import android.app.Activity
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
class StoreArgs {
    lateinit var secret: String
}

@InvokeArg
class UnlockArgs {
    var reason: String = "Open your Nap wallet"
}

@TauriPlugin
class NapVaultPlugin(private val activity: Activity) : Plugin(activity) {
    private val alias = "nap-vault-kept-wallet"
    private val prefs get() = activity.getSharedPreferences("nap-vault", Context.MODE_PRIVATE)
    private fun keystore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Command
    fun status(invoke: Invoke) {
        val available = BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        val ret = JSObject()
        ret.put("available", available)
        ret.put("kind", if (available) "fingerprint" else "none")
        ret.put("stored", prefs.contains("ct") && keystore().containsAlias(alias))
        invoke.resolve(ret)
    }

    @Command
    fun store(invoke: Invoke) {
        val args = invoke.parseArgs(StoreArgs::class.java)
        try {
            keystore().deleteEntry(alias)
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= 30) {
                spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                spec.setUserAuthenticationValidityDurationSeconds(-1)
            }
            gen.init(spec.build())
            val key = gen.generateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            prompt(invoke, cipher, "Turn on fingerprint unlock") { c ->
                val ct = c.doFinal(args.secret.toByteArray(Charsets.UTF_8))
                prefs.edit()
                    .putString("ct", Base64.encodeToString(ct, Base64.NO_WRAP))
                    .putString("iv", Base64.encodeToString(c.iv, Base64.NO_WRAP))
                    .apply()
                invoke.resolve()
            }
        } catch (e: Exception) {
            invoke.reject("This device cannot protect a secret with biometrics: ${e.message}")
        }
    }

    @Command
    fun unlock(invoke: Invoke) {
        val args = invoke.parseArgs(UnlockArgs::class.java)
        val ct = prefs.getString("ct", null)
        val iv = prefs.getString("iv", null)
        val key = keystore().getKey(alias, null) as? SecretKey
        if (ct == null || iv == null || key == null) {
            invoke.reject("not set up")
            return
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)))
        } catch (e: KeyPermanentlyInvalidatedException) {
            // A fingerprint was added or removed: the key is gone for good.
            forgetAll()
            invoke.reject("Your fingerprints changed; open with your password and turn fingerprint unlock on again.")
            return
        }
        prompt(invoke, cipher, args.reason) { c ->
            val secret = String(c.doFinal(Base64.decode(ct, Base64.NO_WRAP)), Charsets.UTF_8)
            val ret = JSObject()
            ret.put("secret", secret)
            invoke.resolve(ret)
        }
    }

    @Command
    fun forget(invoke: Invoke) {
        forgetAll()
        invoke.resolve()
    }

    private fun forgetAll() {
        try { keystore().deleteEntry(alias) } catch (_: Exception) {}
        prefs.edit().clear().apply()
    }

    private fun prompt(invoke: Invoke, cipher: Cipher, title: String, onOk: (Cipher) -> Unit) {
        activity.runOnUiThread {
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (c == null) { invoke.reject("Biometric unlock failed"); return }
                    try { onOk(c) } catch (e: Exception) { invoke.reject("Biometric unlock failed: ${e.message}") }
                }
                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    invoke.reject(if (code == BiometricPrompt.ERROR_NEGATIVE_BUTTON || code == BiometricPrompt.ERROR_USER_CANCELED) "cancelled" else message.toString())
                }
            }
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText("Use password")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .build()
            BiometricPrompt(activity as FragmentActivity, ContextCompat.getMainExecutor(activity), callback)
                .authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
    }
}
