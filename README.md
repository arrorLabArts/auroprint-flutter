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

```go
import (
    "crypto"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "encoding/json"
    "errors"
    "time"
)

type DevicePayload struct {
    DeviceID  string `json:"did"`
    Timestamp int64  `json:"ts"`
    Nonce     string `json:"nonce"`
}

func VerifyAuroprint(payloadJSON, signatureB64, publicKeyPEM string) error {
    // 1. Parse public key
    block, _ := pem.Decode([]byte(publicKeyPEM))
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return errors.New("invalid public key")
    }

    // 2. Verify signature
    hash := sha256.Sum256([]byte(payloadJSON))
    sigBytes, _ := base64.StdEncoding.DecodeString(signatureB64)

    switch key := pub.(type) {
    case *rsa.PublicKey:
        err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sigBytes)
    // Handle ECDSA for iOS...
    }
    if err != nil {
        return errors.New("signature verification failed")
    }

    // 3. Check timestamp (anti-replay)
    var payload DevicePayload
    json.Unmarshal([]byte(payloadJSON), &payload)
    if time.Now().Unix() - payload.Timestamp > 30 {
        return errors.New("request expired")
    }

    // 4. Check nonce in Redis (prevent immediate replays)
    // ...

    return nil
}
```

## Security Architecture

1. **Device ID**: Combination of MediaDRM ID and Android ID (persistent across reinstalls)
2. **Signing Key**: Generated in hardware (TEE/Secure Enclave), never exportable
3. **Attestation**: Certificate chain proving key is hardware-backed (Android)
4. **Anti-replay**: Timestamp + nonce prevent captured requests from being reused

## Limitations

- Signing key is deleted on app uninstall (Android security requirement)
- Device ID may change on factory reset
- Attestation chain only available on Android

## Requirements

- Android: API 24+ (minSdk 24)
- iOS: 12.0+
