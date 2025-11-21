library auroprint;

export 'src/auroprint_method_channel.dart';
export 'src/auroprint_platform_interface.dart';
export 'src/models/auroprint_result.dart';

import 'src/auroprint_platform_interface.dart';
import 'src/models/auroprint_result.dart';

/// Main class for generating spoof-proof device fingerprints.
///
/// Uses hardware-backed cryptographic signing (Android Keystore / iOS Secure Enclave)
/// with key attestation to prove device authenticity.
class Auroprint {
  /// Generates a spoof-proof device fingerprint with cryptographic signature.
  ///
  /// Returns [AuroprintResult] containing:
  /// - `deviceId`: Persistent device identifier
  /// - `payload`: JSON payload with deviceId, timestamp, and nonce
  /// - `signature`: Cryptographic signature of the payload
  /// - `publicKey`: Public key in PEM format for server verification
  /// - `attestationChain`: Certificate chain proving hardware backing (Android only)
  ///
  /// The fingerprint is:
  /// - Unique to device
  /// - Persistent across app reinstalls (uses hardware identifiers)
  /// - Signed by hardware-backed key (TEE on Android, Secure Enclave on iOS)
  /// - Protected against replay attacks (timestamp + nonce)
  ///
  /// Example:
  /// ```dart
  /// final result = await Auroprint.generateAuroprint();
  /// // Send to server: result.payload, result.signature, result.publicKey, result.attestationChain
  /// ```
  static Future<AuroprintResult> generateAuroprint() {
    return AuroprintPlatform.instance.generateAuroprint();
  }

  /// Checks if the device supports hardware-backed key storage.
  ///
  /// Returns `true` if the device has TEE (Android) or Secure Enclave (iOS).
  static Future<bool> isHardwareBackedAvailable() {
    return AuroprintPlatform.instance.isHardwareBackedAvailable();
  }

  /// Resets the stored signing key.
  ///
  /// Use this if you need to regenerate the key pair.
  /// Note: This will change the public key sent to the server.
  static Future<void> resetKey() {
    return AuroprintPlatform.instance.resetKey();
  }

  /// Requests a Play Integrity token from Google (Android only).
  ///
  /// This token should be sent to your server and verified with Google's API
  /// to check device integrity, app authenticity, and licensing status.
  ///
  /// Parameters:
  /// - [nonce]: A unique request identifier (use the same nonce from generateAuroprint)
  /// - [cloudProjectNumber]: Your Google Cloud project number (required for standard API)
  ///
  /// Returns the integrity token string to send to your server.
  ///
  /// Server verification: Use Google's playintegrity API to decode the token.
  /// See: https://developer.android.com/google/play/integrity/verdict
  ///
  /// Example:
  /// ```dart
  /// final auroprint = await Auroprint.generateAuroprint();
  /// final integrityToken = await Auroprint.requestIntegrityToken(
  ///   nonce: auroprint.nonce,
  ///   cloudProjectNumber: 123456789,
  /// );
  /// // Send both auroprint and integrityToken to server
  /// ```
  static Future<String> requestIntegrityToken({
    required String nonce,
    int? cloudProjectNumber,
  }) {
    return AuroprintPlatform.instance.requestIntegrityToken(
      nonce: nonce,
      cloudProjectNumber: cloudProjectNumber,
    );
  }
}
