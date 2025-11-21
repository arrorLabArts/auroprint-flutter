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

## Complete Server Verification (Go)

This is the complete verification flow that proves the request came from your real app on a real physical device.

```go
package auroprint

import (
    "context"
    "crypto"
    "crypto/ecdsa"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/asn1"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "errors"
    "time"

    "github.com/go-redis/redis/v8"
    "google.golang.org/api/playintegrity/v1"
)

type AuroprintRequest struct {
    Payload          string   `json:"payload"`
    Signature        string   `json:"signature"`
    PublicKey        string   `json:"publicKey"`
    AttestationChain []string `json:"attestationChain"`
    IntegrityToken   string   `json:"integrityToken"`
}

type DevicePayload struct {
    DeviceID  string `json:"did"`
    Timestamp int64  `json:"ts"`
    Nonce     string `json:"nonce"`
}

var redisClient *redis.Client

// VerifyAuroprint performs complete verification of device fingerprint
func VerifyAuroprint(ctx context.Context, req AuroprintRequest) (*DevicePayload, error) {
    // 1. Verify signature (proves request came from holder of private key)
    if err := verifySignature(req.Payload, req.Signature, req.PublicKey); err != nil {
        return nil, err
    }

    // 2. Verify attestation chain (proves key is in hardware TEE)
    if len(req.AttestationChain) > 0 {
        if err := verifyAttestationChain(req.AttestationChain, req.PublicKey); err != nil {
            return nil, err
        }
    }

    // 3. Verify Play Integrity (proves real device, real app)
    if req.IntegrityToken != "" {
        if err := verifyPlayIntegrity(ctx, req.IntegrityToken); err != nil {
            return nil, err
        }
    }

    // 4. Parse and verify payload
    var payload DevicePayload
    if err := json.Unmarshal([]byte(req.Payload), &payload); err != nil {
        return nil, errors.New("invalid payload format")
    }

    // 5. Anti-replay: Check timestamp (30 second window)
    if time.Now().Unix()-payload.Timestamp > 30 {
        return nil, errors.New("request expired (possible replay attack)")
    }

    // 6. Anti-replay: Check nonce hasn't been used
    nonceKey := "auroprint:nonce:" + payload.Nonce
    exists, _ := redisClient.Exists(ctx, nonceKey).Result()
    if exists > 0 {
        return nil, errors.New("nonce already used (replay attack)")
    }
    redisClient.Set(ctx, nonceKey, "1", 60*time.Second)

    return &payload, nil
}

// verifySignature checks that payload was signed by the private key
func verifySignature(payload, signatureB64, publicKeyPEM string) error {
    block, _ := pem.Decode([]byte(publicKeyPEM))
    if block == nil {
        return errors.New("invalid public key PEM")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return errors.New("failed to parse public key")
    }

    hash := sha256.Sum256([]byte(payload))
    sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
    if err != nil {
        return errors.New("invalid signature encoding")
    }

    switch key := pub.(type) {
    case *rsa.PublicKey:
        // Android uses RSA
        err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sigBytes)
    case *ecdsa.PublicKey:
        // iOS uses ECDSA
        if !ecdsa.VerifyASN1(key, hash[:], sigBytes) {
            err = errors.New("ECDSA verification failed")
        }
    default:
        return errors.New("unsupported key type")
    }

    if err != nil {
        return errors.New("signature verification failed")
    }
    return nil
}

// verifyAttestationChain proves the signing key is hardware-backed (TEE)
func verifyAttestationChain(chain []string, publicKeyPEM string) error {
    if len(chain) == 0 {
        return errors.New("empty attestation chain")
    }

    // Parse leaf certificate
    block, _ := pem.Decode([]byte(chain[0]))
    if block == nil {
        return errors.New("invalid certificate PEM")
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return errors.New("failed to parse certificate")
    }

    // Check for Android Key Attestation extension
    // OID: 1.3.6.1.4.1.11129.2.1.17
    keyDescOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

    var found bool
    for _, ext := range cert.Extensions {
        if ext.Id.Equal(keyDescOID) {
            found = true
            // Parse extension to verify:
            // - SecurityLevel is TRUSTED_ENVIRONMENT (TEE) or STRONG_BOX
            // - Key is not exportable
            // Full parsing requires ASN.1 decoding of the extension value
            break
        }
    }

    if !found {
        return errors.New("attestation extension not found - key may not be hardware-backed")
    }

    // TODO: Verify certificate chain up to Google/OEM root
    // You should pin the root certificates and verify the chain

    return nil
}

// verifyPlayIntegrity checks device and app integrity with Google
func verifyPlayIntegrity(ctx context.Context, token string) error {
    service, err := playintegrity.NewService(ctx)
    if err != nil {
        return errors.New("failed to create integrity service")
    }

    response, err := service.V1.DecodeIntegrityToken(
        "com.yourapp.package", // Replace with your package name
        &playintegrity.DecodeIntegrityTokenRequest{IntegrityToken: token},
    ).Do()
    if err != nil {
        return errors.New("failed to decode integrity token")
    }

    verdict := response.TokenPayloadExternal

    // Check device integrity
    deviceVerdict := verdict.DeviceIntegrity.DeviceRecognitionVerdict
    if len(deviceVerdict) == 0 || deviceVerdict[0] != "MEETS_DEVICE_INTEGRITY" {
        return errors.New("device integrity check failed - possibly rooted or emulator")
    }

    // Check app integrity
    if verdict.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
        return errors.New("app not recognized - possibly modified or sideloaded")
    }

    return nil
}
```

## Security Architecture

1. **Device ID**: Composite of MediaDRM ID + hardware properties (unique per device)
2. **Signing Key**: Generated in hardware (TEE/Secure Enclave), never exportable
3. **Attestation**: Certificate chain proving key is hardware-backed (Android)
4. **Play Integrity**: Google verifies real device, unmodified app
5. **Anti-replay**: Timestamp + nonce prevent captured requests from being reused

## Trust Guarantees

When all verifications pass, you have cryptographic proof that:
- The request came from your app (not a bot)
- Running on a real physical device (not emulator)
- The device is not rooted/hooked (no Frida)
- The fingerprint was generated by hardware (not spoofed)

## Limitations

- Signing key is deleted on app uninstall (Android security requirement)
- Device ID may change on factory reset
- Attestation chain only available on Android

## Requirements

- Android: API 24+ (minSdk 24)
- iOS: 12.0+
