# Auroprint

Spoof-proof device fingerprint generation with hardware-backed cryptographic signing.

## Features

- **Hardware-backed signing**: Uses Android Keystore (TEE) and iOS Secure Enclave
- **Key Attestation**: Certificate chain proving hardware backing (Android)
- **Persistent device ID**: Survives app reinstalls (MediaDRM ID + Android ID / iOS Vendor ID)
- **Anti-replay protection**: Timestamp and nonce in every request
- **Play Integrity API**: Detect rooted/hooked devices (Android)

## Installation

```yaml
dependencies:
  auroprint:
    git:
      url: https://github.com/arrorLabArts/auroprint-flutter
```

## Usage

```dart
import 'package:auroprint/auroprint.dart';

// Generate spoof-proof fingerprint
final result = await Auroprint.generateAuroprint();

// Send to your server
final requestBody = {
  'payload': result.payload,
  'signature': result.signature,
  'publicKey': result.publicKey,
  'attestationChain': result.attestationChain,
};
```

## Play Integrity API (Android)

Detects rooted devices, Frida hooking, and verifies app authenticity.
 
### Setup

1. Enable Play Integrity API in [Google Cloud Console](https://console.cloud.google.com/apis/library/playintegrity.googleapis.com)
2. Link your app in [Play Console](https://play.google.com/console) > App integrity
3. Note your Cloud Project Number

### Usage

```dart
// Generate fingerprint
final auroprint = await Auroprint.generateAuroprint();

// Request Play Integrity token
final integrityToken = await Auroprint.requestIntegrityToken(
  nonce: auroprint.nonce,
  cloudProjectNumber: 123456789012, // Your project number
);

// Send both to server
final requestBody = {
  'payload': auroprint.payload,
  'signature': auroprint.signature,
  'publicKey': auroprint.publicKey,
  'integrityToken': integrityToken,
};
```

### Server Verification (Go)

```go
import (
    "google.golang.org/api/playintegrity/v1"
)

func VerifyIntegrity(token string) error {
    service, _ := playintegrity.NewService(ctx)

    response, err := service.V1.DecodeIntegrityToken(
        "com.yourapp.package",
        &playintegrity.DecodeIntegrityTokenRequest{IntegrityToken: token},
    ).Do()

    verdict := response.TokenPayloadExternal

    // Check device integrity
    if verdict.DeviceIntegrity.DeviceRecognitionVerdict[0] != "MEETS_DEVICE_INTEGRITY" {
        return errors.New("device integrity check failed")
    }

    // Check app integrity
    if verdict.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
        return errors.New("app not from Play Store")
    }

    return nil
}
```

## Server Verification (Go)

A complete Go library is available for server-side verification with full attestation chain validation, public key matching, and Play Integrity support.

**Installation:**

```bash
go get github.com/arrorLabArts/auroprint-go
```

> **Note**: The library implements complete security verification including public key matching against the attestation chain and full certificate chain validation - features that are critical for production security.

### Basic Usage

```go
package main

import (
    "context"
    "encoding/json"
    "net/http"
    "time"

    "github.com/arrorLabArts/auroprint-go"
    "github.com/go-redis/redis/v8"
)

var redisClient *redis.Client

func handleAuroprint(w http.ResponseWriter, r *http.Request) {
    var req auroprint.Request
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // Verify the auroprint
    result := auroprint.Verify(r.Context(), req, &auroprint.VerifyOptions{
        PlayIntegrityPackageName: "com.yourapp.package",
        GoogleCredentialsJSON:    []byte("..."), // Service account JSON
    })

    if !result.Valid {
        http.Error(w, result.Error.Error(), http.StatusUnauthorized)
        return
    }

    // Anti-replay: Check timestamp (30 second window)
    if time.Now().Unix()-result.Payload.Timestamp > 30 {
        http.Error(w, "Request expired", http.StatusUnauthorized)
        return
    }

    // Anti-replay: Check nonce hasn't been used
    nonceKey := "auroprint:nonce:" + result.Payload.Nonce
    exists, _ := redisClient.Exists(r.Context(), nonceKey).Result()
    if exists > 0 {
        http.Error(w, "Nonce reused", http.StatusUnauthorized)
        return
    }
    redisClient.Set(r.Context(), nonceKey, "1", 60*time.Second)

    // Request verified! Process with device ID
    json.NewEncoder(w).Encode(map[string]string{
        "status":   "verified",
        "deviceId": result.Payload.DeviceID,
    })
}
```

### What Gets Verified

The `Verify` function performs comprehensive security checks:

**1. Signature Verification**
- Hashes the payload with SHA-256
- Verifies signature with the provided public key
- Supports both RSA (Android) and ECDSA (iOS)
- **Proves**: Request came from holder of the private key

**2. Public Key Matching** ✅
- Extracts public key from attestation chain's leaf certificate
- Compares it byte-for-byte with the provided public key
- **Proves**: The attested key is the one actually doing the signing
- **Prevents**: Attackers from mixing stolen attestation with their own keys

**3. Attestation Chain Verification** (Android only)
- Checks for Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
- Verifies each certificate is signed by the next in chain
- Validates chain from app key → device TEE → manufacturer → Google root
- **Proves**: Key is stored in hardware TEE/StrongBox, not software

**4. Play Integrity Verification** (optional)
- Validates device integrity (detects rooted/modified devices)
- Verifies app is Play Store recognized (detects sideloaded apps)
- **Proves**: Real device running legitimate app

**Note**: Anti-replay protection (timestamp/nonce checking) is left to your application code as shown above.

### Verification Options

```go
type VerifyOptions struct {
    // Skip attestation chain verification (not recommended for production)
    SkipAttestationVerification bool

    // Android package name (required for Play Integrity)
    PlayIntegrityPackageName string

    // Google service account credentials for Play Integrity API
    GoogleCredentialsJSON []byte
}
```

### Complete Example with All Features

```go
func verifyAuroprintComplete(ctx context.Context, req auroprint.Request) error {
    // Perform cryptographic verification
    result := auroprint.Verify(ctx, req, &auroprint.VerifyOptions{
        SkipAttestationVerification: false, // Always verify attestation
        PlayIntegrityPackageName:    "com.yourapp.package",
        GoogleCredentialsJSON:       loadServiceAccountJSON(),
    })

    if !result.Valid {
        return fmt.Errorf("verification failed: %w", result.Error)
    }

    // Application-level checks
    payload := result.Payload

    // Check timestamp
    if time.Now().Unix()-payload.Timestamp > 30 {
        return errors.New("request expired (replay attack)")
    }

    // Check nonce (requires Redis or similar)
    if nonceUsed(ctx, payload.Nonce) {
        return errors.New("nonce reused (replay attack)")
    }
    markNonceUsed(ctx, payload.Nonce, 60*time.Second)

    // All checks passed!
    return nil
}
```

## Security Architecture

The verification flow provides multiple layers of cryptographic proof:

**1. Device Identification**
- Composite ID from MediaDRM + hardware properties (Android)
- Vendor ID from iOS device (persists across reinstalls)
- Unique per physical device

**2. Hardware-Backed Signing Key**
- Generated in TEE (Android Keystore) or Secure Enclave (iOS)
- Private key never exportable or accessible to OS
- Each app gets its own isolated key pair

**3. Attestation Chain Verification** (Android)
- Validates certificate chain: app key → TEE → manufacturer → Google root
- Checks Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
- **Verifies public key matches the attested certificate** (prevents key substitution attacks)
- Confirms key is in hardware, not software

**4. Play Integrity Validation** (optional)
- Google independently verifies device authenticity
- Detects rooted devices, emulators, and modified apps
- Complements attestation with runtime integrity checks

**5. Anti-Replay Protection**
- Timestamp prevents old requests from being reused (30s window recommended)
- Nonce ensures each request is unique and non-repeatable
- Application must implement nonce tracking (Redis, database, etc.)

## Trust Guarantees

When all verifications pass, you have cryptographic proof that:

**✅ Authenticity**: The request came from your legitimate app (signature verification)
**✅ Hardware Origin**: The signing key is in device hardware, not software (attestation chain + public key matching)
**✅ Device Integrity**: Running on a real, unmodified device (Play Integrity API)
**✅ Uniqueness**: Each request is fresh and not replayed (timestamp + nonce)
**✅ Isolation**: Each app has its own key, preventing cross-app impersonation

## Limitations

- Signing key is deleted on app uninstall (Android security requirement)
- Device ID may change on factory reset
- Attestation chain only available on Android

## Requirements

- Android: API 24+ (minSdk 24)
- iOS: 12.0+
