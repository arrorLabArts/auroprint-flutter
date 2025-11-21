import Flutter
import UIKit
import Security
import LocalAuthentication
import CryptoKit

public class AuroprintPlugin: NSObject, FlutterPlugin {
    private static let keyTag = "com.arrorlabarts.auroprint.signing"

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "com.arrorlabarts.auroprint/channel",
            binaryMessenger: registrar.messenger()
        )
        let instance = AuroprintPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "generateAuroprint":
            generateAuroprint(result: result)
        case "isHardwareBackedAvailable":
            isHardwareBackedAvailable(result: result)
        case "resetKey":
            resetKey(result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func generateAuroprint(result: @escaping FlutterResult) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                // Ensure key exists
                try self.ensureKeyExists()

                // Get persistent device ID
                let deviceId = self.getDeviceId()

                // Generate timestamp and nonce
                let timestamp = Int(Date().timeIntervalSince1970)
                let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "")

                // Create payload
                let payload: [String: Any] = [
                    "did": deviceId,
                    "ts": timestamp,
                    "nonce": nonce
                ]
                let payloadData = try JSONSerialization.data(withJSONObject: payload)
                let payloadString = String(data: payloadData, encoding: .utf8)!

                // Sign the payload
                let signature = try self.signPayload(payloadString)

                // Get public key
                let publicKey = try self.getPublicKeyPem()

                // iOS doesn't have attestation chain like Android
                // For iOS attestation, you'd use DeviceCheck or App Attest
                let attestationChain: [String] = []

                let response: [String: Any] = [
                    "deviceId": deviceId,
                    "payload": payloadString,
                    "signature": signature,
                    "publicKey": publicKey,
                    "attestationChain": attestationChain,
                    "timestamp": timestamp,
                    "nonce": nonce,
                    "isHardwareBacked": self.isSecureEnclaveAvailable()
                ]

                DispatchQueue.main.async {
                    result(response)
                }
            } catch {
                DispatchQueue.main.async {
                    result(FlutterError(
                        code: "AUROPRINT_ERROR",
                        message: error.localizedDescription,
                        details: nil
                    ))
                }
            }
        }
    }

    private func ensureKeyExists() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: AuroprintPlugin.keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound {
            try generateSigningKey()
        } else if status != errSecSuccess {
            throw NSError(domain: "Auroprint", code: Int(status), userInfo: [
                NSLocalizedDescriptionKey: "Failed to check for existing key"
            ])
        }
    }

    private func generateSigningKey() throws {
        var error: Unmanaged<CFError>?

        // Try Secure Enclave first
        var accessControl: SecAccessControl?
        if isSecureEnclaveAvailable() {
            accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .privateKeyUsage,
                &error
            )
        } else {
            accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [],
                &error
            )
        }

        guard let access = accessControl else {
            throw error!.takeRetainedValue() as Error
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrApplicationTag as String: AuroprintPlugin.keyTag,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: access
            ]
        ]

        // Use Secure Enclave if available
        if isSecureEnclaveAvailable() {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }

        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            throw error!.takeRetainedValue() as Error
        }
    }

    private func signPayload(_ payload: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: AuroprintPlugin.keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess, let privateKey = item else {
            throw NSError(domain: "Auroprint", code: Int(status), userInfo: [
                NSLocalizedDescriptionKey: "Failed to retrieve private key"
            ])
        }

        let data = payload.data(using: .utf8)!
        var error: Unmanaged<CFError>?

        guard let signature = SecKeyCreateSignature(
            privateKey as! SecKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }

        return (signature as Data).base64EncodedString()
    }

    private func getPublicKeyPem() throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: AuroprintPlugin.keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess, let privateKey = item else {
            throw NSError(domain: "Auroprint", code: Int(status), userInfo: [
                NSLocalizedDescriptionKey: "Failed to retrieve private key"
            ])
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey as! SecKey) else {
            throw NSError(domain: "Auroprint", code: -1, userInfo: [
                NSLocalizedDescriptionKey: "Failed to get public key"
            ])
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        let data = publicKeyData as Data
        let base64 = data.base64EncodedString()

        // Format as PEM
        var pem = "-----BEGIN PUBLIC KEY-----\n"
        let lineLength = 64
        var index = base64.startIndex
        while index < base64.endIndex {
            let endIndex = base64.index(index, offsetBy: lineLength, limitedBy: base64.endIndex) ?? base64.endIndex
            pem += String(base64[index..<endIndex]) + "\n"
            index = endIndex
        }
        pem += "-----END PUBLIC KEY-----"

        return pem
    }

    private func getDeviceId() -> String {
        // Use identifierForVendor - persists across app reinstalls for same vendor
        if let vendorId = UIDevice.current.identifierForVendor?.uuidString {
            return sha256(vendorId)
        }

        // Fallback to a stored UUID in Keychain
        return getOrCreateKeychainId()
    }

    private func getOrCreateKeychainId() -> String {
        let key = "com.arrorlabarts.auroprint.deviceId"

        // Try to retrieve existing
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess, let data = item as? Data,
           let id = String(data: data, encoding: .utf8) {
            return id
        }

        // Create new ID
        let newId = UUID().uuidString
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
            kSecValueData as String: newId.data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        SecItemAdd(addQuery as CFDictionary, nil)
        return sha256(newId)
    }

    private func sha256(_ string: String) -> String {
        let data = Data(string.utf8)
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }

    private func isSecureEnclaveAvailable() -> Bool {
        let context = LAContext()
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            || SecureEnclave.isAvailable
    }

    private func isHardwareBackedAvailable(result: @escaping FlutterResult) {
        result(isSecureEnclaveAvailable())
    }

    private func resetKey(result: @escaping FlutterResult) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: AuroprintPlugin.keyTag
        ]

        SecItemDelete(query as CFDictionary)
        result(nil)
    }
}
