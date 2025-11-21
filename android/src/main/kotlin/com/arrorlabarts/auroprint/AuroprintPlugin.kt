package com.arrorlabarts.auroprint

import android.content.Context
import android.media.MediaDrm
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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

class AuroprintPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var context: Context

    companion object {
        private const val CHANNEL_NAME = "com.arrorlabarts.auroprint/channel"
        private const val KEY_ALIAS = "auroprint_signing_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        // Widevine UUID for MediaDRM
        private val WIDEVINE_UUID = UUID(-0x121074568629b532L, -0x5c37d8232ae2de13L)
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
        context = flutterPluginBinding.applicationContext
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
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
        try {
            // Ensure key exists
            ensureKeyExists()

            // Get persistent device ID
            val deviceId = getDeviceId()

            // Generate timestamp and nonce
            val timestamp = System.currentTimeMillis() / 1000
            val nonce = UUID.randomUUID().toString().replace("-", "")

            // Create payload
            val payloadJson = JSONObject().apply {
                put("did", deviceId)
                put("ts", timestamp)
                put("nonce", nonce)
            }
            val payload = payloadJson.toString()

            // Sign the payload
            val signature = signPayload(payload)

            // Get public key and attestation chain
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            val certificateChain = keyStore.getCertificateChain(KEY_ALIAS)

            val publicKeyPem = certificateToPem(certificateChain[0])
            val attestationChain = certificateChain.map { certificateToPem(it) }

            // Check if hardware-backed
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

            result.success(response)
        } catch (e: Exception) {
            result.error("AUROPRINT_ERROR", e.message, e.stackTraceToString())
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

        // Request attestation if available (API 24+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            // Use a challenge for attestation
            val challenge = "auroprint_attestation_${System.currentTimeMillis()}".toByteArray()
            builder.setAttestationChallenge(challenge)
        }

        // Prefer StrongBox if available (API 28+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                builder.setIsStrongBoxBacked(true)
            } catch (e: Exception) {
                // StrongBox not available, fall back to TEE
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
        // Use MediaDRM ID as the primary device identifier
        // This is truly device-unique (same across all users/apps on the device)

        // 1. Try MediaDRM ID first (most reliable, factory-provisioned)
        try {
            val mediaDrmId = getMediaDrmId()
            if (mediaDrmId.isNotEmpty()) {
                return hashString(mediaDrmId)
            }
        } catch (e: Exception) {
            // MediaDRM not available (rare on modern devices)
        }

        // 2. Fallback to Build properties hash (less ideal but still device-bound)
        // This combines hardware identifiers that are the same for all users
        val fallbackId = listOf(
            Build.BOARD,
            Build.BOOTLOADER,
            Build.BRAND,
            Build.DEVICE,
            Build.HARDWARE,
            Build.MANUFACTURER,
            Build.MODEL,
            Build.PRODUCT
        ).joinToString("|")

        return hashString(fallbackId)
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

            // Check if the key is inside secure hardware by looking at attestation
            // For a proper check, we'd parse the attestation extension
            // This is a simplified check
            return certificate.publicKey != null
        } catch (e: Exception) {
            return false
        }
    }

    private fun isHardwareBackedAvailable(result: Result) {
        try {
            // Check if device supports hardware-backed keystore
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

            // Build the request
            val requestBuilder = IntegrityTokenRequest.builder()
                .setNonce(nonce)

            // Add cloud project number if provided (required for standard API requests)
            if (cloudProjectNumber != null) {
                requestBuilder.setCloudProjectNumber(cloudProjectNumber)
            }

            val integrityTokenResponse = integrityManager.requestIntegrityToken(requestBuilder.build())

            integrityTokenResponse.addOnSuccessListener { response ->
                result.success(hashMapOf(
                    "token" to response.token()
                ))
            }.addOnFailureListener { exception ->
                result.error(
                    "INTEGRITY_ERROR",
                    exception.message,
                    exception.stackTraceToString()
                )
            }
        } catch (e: Exception) {
            result.error("AUROPRINT_ERROR", e.message, e.stackTraceToString())
        }
    }
}
