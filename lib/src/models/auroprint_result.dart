/// Result of generating a device fingerprint with cryptographic proof.
class AuroprintResult {
  /// Persistent device identifier.
  ///
  /// On Android: Combination of MediaDRM ID and Android ID
  /// On iOS: Identifier for Vendor (persists across reinstalls for same vendor)
  final String deviceId;

  /// JSON payload containing deviceId, timestamp (Unix seconds), and nonce.
  ///
  /// Example: `{"did":"abc123","ts":1700000000,"nonce":"xyz789"}`
  final String payload;

  /// Base64-encoded signature of the payload.
  ///
  /// Signed using hardware-backed private key (RSA-SHA256).
  final String signature;

  /// Public key in PEM format.
  ///
  /// Use this on your server to verify the signature.
  final String publicKey;

  /// Certificate chain proving hardware backing (Android only).
  ///
  /// List of PEM-encoded certificates. The first certificate contains
  /// the public key and attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
  /// proving the key is TEE-backed.
  ///
  /// On iOS, this will be an empty list (iOS uses different attestation).
  final List<String> attestationChain;

  /// Timestamp when the fingerprint was generated (Unix seconds).
  final int timestamp;

  /// Random nonce to prevent replay attacks.
  final String nonce;

  /// Whether the signing key is hardware-backed (TEE/Secure Enclave).
  final bool isHardwareBacked;

  AuroprintResult({
    required this.deviceId,
    required this.payload,
    required this.signature,
    required this.publicKey,
    required this.attestationChain,
    required this.timestamp,
    required this.nonce,
    required this.isHardwareBacked,
  });

  factory AuroprintResult.fromMap(Map<String, dynamic> map) {
    return AuroprintResult(
      deviceId: map['deviceId'] as String,
      payload: map['payload'] as String,
      signature: map['signature'] as String,
      publicKey: map['publicKey'] as String,
      attestationChain: (map['attestationChain'] as List<dynamic>?)
              ?.map((e) => e as String)
              .toList() ??
          [],
      timestamp: map['timestamp'] as int,
      nonce: map['nonce'] as String,
      isHardwareBacked: map['isHardwareBacked'] as bool? ?? false,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'deviceId': deviceId,
      'payload': payload,
      'signature': signature,
      'publicKey': publicKey,
      'attestationChain': attestationChain,
      'timestamp': timestamp,
      'nonce': nonce,
      'isHardwareBacked': isHardwareBacked,
    };
  }

  @override
  String toString() {
    return 'AuroprintResult(deviceId: $deviceId, timestamp: $timestamp, nonce: $nonce, isHardwareBacked: $isHardwareBacked)';
  }
}
