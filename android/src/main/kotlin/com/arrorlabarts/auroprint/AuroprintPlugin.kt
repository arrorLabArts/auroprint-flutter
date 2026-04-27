package com.arrorlabarts.auroprint

import android.content.Context
import android.media.MediaDrm
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.Executors
import android.os.Handler
import android.os.Looper

class AuroprintPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private val executor = Executors.newCachedThreadPool()
    private val mainHandler = Handler(Looper.getMainLooper())

    // FIX: Guard async callbacks — if the engine detaches while a Play Integrity
    // or Keystore operation is in-flight, calling result.success/error on the
    // stale MethodChannel.Result will invoke a freed Dart FFI trampoline and
    // crash with "Callback invoked after it has been deleted".
    @Volatile private var isAttached = false

    companion object {
        private const val CHANNEL_NAME = "com.arrorlabarts.auroprint/channel"
        private const val KEY_ALIAS = "auroprint_signing_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private val WIDEVINE_UUID = UUID(-0x121074568629b532L, -0x5c37d8232ae2de13L)

        // Persistent cache for the derived device ID. Once computed, the value
        // is pinned for the lifetime of the install. Cleared by app uninstall
        // or by the host explicitly clearing app data. The version key lets a
        // future algorithm change force a recompute without ambiguity.
        private const val DID_CACHE_PREFS = "auroprint_did_cache"
        private const val DID_CACHE_KEY = "did"
        private const val DID_CACHE_VERSION_KEY = "did_version"
        private const val DID_CACHE_VERSION = 1

        // Widevine ID retry: PROPERTY_DEVICE_UNIQUE_ID can throw transiently
        // (resource busy, MediaDrm session pressure). Retry with light backoff
        // before deciding the value is genuinely unreadable.
        private const val WIDEVINE_RETRY_ATTEMPTS = 3
        private const val WIDEVINE_RETRY_BASE_DELAY_MS = 100L
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        isAttached = true
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
        context = flutterPluginBinding.applicationContext
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        isAttached = false
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "generateAuroprint" -> generateAuroprint(result)
            "isHardwareBackedAvailable" -> isHardwareBackedAvailable(result)
            "resetKey" -> resetKey(result)
            "requestIntegrityToken" -> {
                val nonce = call.argument<String>("nonce")
                val cloudProjectNumber = call.argument<Long>("cloudProjectNumber")
                requestIntegrityToken(nonce, cloudProjectNumber, result)
            }
            else -> result.notImplemented()
        }
    }

    private fun generateAuroprint(result: Result) {
        executor.execute {
            try {
                ensureKeyExists()
                val deviceId = getDeviceId()
                val timestamp = System.currentTimeMillis() / 1000
                val nonce = UUID.randomUUID().toString().replace("-", "")

                val payloadJson = JSONObject().apply {
                    put("did", deviceId)
                    put("ts", timestamp)
                    put("nonce", nonce)
                }
                val payload = payloadJson.toString()
                val signature = signPayload(payload)

                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
                keyStore.load(null)
                val certificateChain = keyStore.getCertificateChain(KEY_ALIAS)

                val publicKeyPem = certificateToPem(certificateChain[0])
                val attestationChain = certificateChain.map { certificateToPem(it) }
                val isHardwareBacked = isKeyHardwareBacked()

                val response = hashMapOf(
                    "deviceId" to deviceId,
                    "payload" to payload,
                    "signature" to signature,
                    "publicKey" to publicKeyPem,
                    "attestationChain" to attestationChain,
                    "timestamp" to timestamp,
                    "nonce" to nonce,
                    "isHardwareBacked" to isHardwareBacked
                )

                mainHandler.post {
                    if (isAttached) result.success(response)
                }
            } catch (e: Exception) {
                mainHandler.post {
                    if (isAttached) result.error("AUROPRINT_ERROR", e.message, e.stackTraceToString())
                }
            }
        }
    }

    private fun ensureKeyExists() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            generateSigningKey()
        }
    }

    private fun generateSigningKey() {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE
        )

        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setKeySize(2048)
            .setUserAuthenticationRequired(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val challenge = "auroprint_attestation_${System.currentTimeMillis()}".toByteArray()
            builder.setAttestationChallenge(challenge)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                builder.setIsStrongBoxBacked(true)
                keyPairGenerator.initialize(builder.build())
                keyPairGenerator.generateKeyPair()
                return
            } catch (e: StrongBoxUnavailableException) {
                val teeBuilder = KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setKeySize(2048)
                    .setUserAuthenticationRequired(false)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    val challenge = "auroprint_attestation_${System.currentTimeMillis()}".toByteArray()
                    teeBuilder.setAttestationChallenge(challenge)
                }

                keyPairGenerator.initialize(teeBuilder.build())
                keyPairGenerator.generateKeyPair()
                return
            }
        }

        keyPairGenerator.initialize(builder.build())
        keyPairGenerator.generateKeyPair()
    }

    private fun signPayload(payload: String): String {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey

        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(payload.toByteArray(Charsets.UTF_8))
        val signatureBytes = signature.sign()

        return Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
    }

    private fun getDeviceId(): String {
        val prefs = context.getSharedPreferences(DID_CACHE_PREFS, Context.MODE_PRIVATE)
        val cachedVersion = prefs.getInt(DID_CACHE_VERSION_KEY, -1)
        val cachedDid = prefs.getString(DID_CACHE_KEY, null)
        if (cachedVersion == DID_CACHE_VERSION && !cachedDid.isNullOrEmpty()) {
            return cachedDid
        }

        val components = mutableListOf<String>()

        // Widevine inclusion is decided by whether the platform reports support
        // for the scheme — a stable property that doesn't depend on transient
        // provisioning state. When supported, the per-device unique ID is
        // mandatory; we retry transient failures and throw if still unreadable
        // rather than silently producing a different input set.
        val supportsWidevine = try {
            MediaDrm.isCryptoSchemeSupported(WIDEVINE_UUID)
        } catch (e: Exception) {
            false
        }

        if (supportsWidevine) {
            val widevineId = readWidevineIdWithRetry()
                ?: throw IllegalStateException(
                    "Widevine reported supported but PROPERTY_DEVICE_UNIQUE_ID is unreadable"
                )
            components.add(widevineId)
        }

        // Hardware identifiers stable across the device's lifetime.
        // Build.BOOTLOADER is omitted because it can change with vendor
        // bootloader/firmware updates on some devices, which would shift
        // the derived ID after a system OTA.
        components.addAll(listOf(
            Build.BOARD,
            Build.BRAND,
            Build.DEVICE,
            Build.HARDWARE,
            Build.MANUFACTURER,
            Build.MODEL,
            Build.PRODUCT
        ))

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            components.add(Build.SOC_MANUFACTURER)
            components.add(Build.SOC_MODEL)
        }

        // displayMetrics is intentionally excluded: widthPixels/heightPixels
        // swap on rotation, change in multi-window/picture-in-picture, and
        // shift when an external display is attached. densityDpi changes with
        // the user's display-size accessibility setting.

        val combined = components.joinToString("|")
        val did = hashString(combined)

        prefs.edit()
            .putString(DID_CACHE_KEY, did)
            .putInt(DID_CACHE_VERSION_KEY, DID_CACHE_VERSION)
            .apply()

        return did
    }

    private fun readWidevineIdWithRetry(): String? {
        for (attempt in 1..WIDEVINE_RETRY_ATTEMPTS) {
            try {
                val id = getMediaDrmId()
                if (id.isNotEmpty()) return id
            } catch (e: Exception) {
                // Swallow and retry; final failure becomes a thrown error
                // at the call site so the input set never silently changes.
            }
            if (attempt < WIDEVINE_RETRY_ATTEMPTS) {
                try {
                    Thread.sleep(WIDEVINE_RETRY_BASE_DELAY_MS * attempt)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return null
                }
            }
        }
        return null
    }

    private fun getMediaDrmId(): String {
        val mediaDrm = MediaDrm(WIDEVINE_UUID)
        try {
            val deviceId = mediaDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
            return Base64.encodeToString(deviceId, Base64.NO_WRAP)
        } finally {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                mediaDrm.close()
            } else {
                @Suppress("DEPRECATION")
                mediaDrm.release()
            }
        }
    }

    private fun hashString(input: String): String {
        val bytes = java.security.MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun certificateToPem(certificate: Certificate): String {
        val base64 = Base64.encodeToString(certificate.encoded, Base64.NO_WRAP)
        return "-----BEGIN CERTIFICATE-----\n${base64.chunked(64).joinToString("\n")}\n-----END CERTIFICATE-----"
    }

    private fun isKeyHardwareBacked(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return false
        }

        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            val certificate = keyStore.getCertificate(KEY_ALIAS) as? X509Certificate
                ?: return false

            return certificate.publicKey != null
        } catch (e: Exception) {
            return false
        }
    }

    private fun isHardwareBackedAvailable(result: Result) {
        try {
            val available = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
            result.success(available)
        } catch (e: Exception) {
            result.error("AUROPRINT_ERROR", e.message, null)
        }
    }

    private fun resetKey(result: Result) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }
            result.success(null)
        } catch (e: Exception) {
            result.error("AUROPRINT_ERROR", e.message, null)
        }
    }

    private fun requestIntegrityToken(nonce: String?, cloudProjectNumber: Long?, result: Result) {
        if (nonce == null) {
            result.error("AUROPRINT_ERROR", "Nonce is required", null)
            return
        }

        try {
            val integrityManager = IntegrityManagerFactory.create(context)

            val requestBuilder = IntegrityTokenRequest.builder()
                .setNonce(nonce)

            if (cloudProjectNumber != null) {
                requestBuilder.setCloudProjectNumber(cloudProjectNumber)
            }

            val integrityTokenResponse = integrityManager.requestIntegrityToken(requestBuilder.build())

            integrityTokenResponse.addOnSuccessListener { response ->
                if (isAttached) {
                    result.success(hashMapOf(
                        "token" to response.token()
                    ))
                }
            }.addOnFailureListener { exception ->
                if (isAttached) {
                    result.error(
                        "INTEGRITY_ERROR",
                        exception.message,
                        exception.stackTraceToString()
                    )
                }
            }
        } catch (e: Exception) {
            if (isAttached) {
                result.error("AUROPRINT_ERROR", e.message, e.stackTraceToString())
            }
        }
    }
}
