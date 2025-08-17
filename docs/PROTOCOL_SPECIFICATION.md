# 3D Model Video Authentication Protocol (3MVAP) v2.0

## Abstract

The 3D Model Video Authentication Protocol (3MVAP) is a universal standard for embedding and verifying digital signatures of 3D models within video content with tamper-resistant security. This protocol enables content creators, distributors, and consumers to verify the authenticity and ownership of 3D assets used in video production, creating a robust digital rights management system for 3D content with enterprise-grade security protection.

## 1. Introduction

### 1.1 Purpose

This specification defines a standardized method for:

- Embedding 3D model digital signatures into video metadata with cryptographic protection
- Verifying 3D model authenticity in video content with tamper detection
- Providing two security levels: Basic (legacy) and Secure (tamper-resistant)
- Enabling universal adoption across video players, 3D software, and streaming platforms

### 1.2 Scope

This protocol covers:

- Dual security level metadata format specification (Basic v1.0 and Secure v2.0)
- Tamper-resistant signature embedding procedures
- Cryptographic verification algorithms with integrity protection
- Content binding and redundant storage mechanisms
- Integration guidelines for software vendors

### 1.3 Terminology

- **3MVAP**: 3D Model Video Authentication Protocol
- **Basic Mode**: Legacy authentication using simple metadata storage (v1.0)
- **Secure Mode**: Tamper-resistant authentication with cryptographic protection (v2.0)
- **Signature Manifest**: Collection of 3D model signatures embedded in video metadata
- **Artist Registry**: Database of verified artist public keys
- **Authentication Token**: Cryptographic proof of 3D model ownership
- **Content Binding**: Tying signatures to specific video content to prevent transplantation
- **Integrity Signature**: HMAC signature protecting metadata from tampering

## 2. Protocol Overview

### 2.1 Architecture

```
[3D Software] → [Signature Extraction] → [Video Export] → [Metadata Embedding]
                                                                    ↓
[Video Player] ← [Verification Engine] ← [Metadata Extraction] ← [Video File]
```

### 2.2 Workflow

1. **Creation Phase**: 3D models are digitally signed by artists
2. **Production Phase**: Signed models are used in video production
3. **Export Phase**: Video export tools embed model signatures into metadata
4. **Distribution Phase**: Videos are distributed with embedded authentication
5. **Playback Phase**: Players verify signatures before content display

## 3. Metadata Format Specification

### 3.1 Security Levels

3MVAP v2.0 supports two security levels:

#### 3.1.1 Basic Mode (v1.0) - Legacy

- **Storage**: Single metadata field (`comment`)
- **Protection**: Base64 encoding only
- **Vulnerability**: Easily tampered with standard tools
- **Use Case**: Backward compatibility

#### 3.1.2 Secure Mode (v2.0) - Recommended

- **Storage**: Multiple metadata fields (`comment`, `description`, `album`)
- **Protection**: HMAC integrity + XOR obfuscation + double Base64
- **Features**: Content binding, tamper detection, redundant storage
- **Use Case**: Production environments requiring tamper resistance

### 3.2 Container Format

#### 3.2.1 Basic Mode Container

```yaml
Metadata Key: "comment"
Encoding: Base64
Content-Type: JSON
```

#### 3.2.2 Secure Mode Container

```yaml
Metadata Keys: "comment", "description", "album" (redundant storage)
Encoding: XOR obfuscation + double Base64
Content-Type: JSON with integrity signature
```

### 3.3 JSON Schema

#### 3.3.1 Basic Mode Schema (v1.0)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "signature_version": {
      "type": "string",
      "enum": ["1.0"]
    },
    "created_at": {
      "type": "string",
      "format": "date-time"
    },
    "total_models": {
      "type": "integer",
      "minimum": 1
    },
    "signatures": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/signature_entry"
      }
    }
  },
  "$defs": {
    "signature_entry": {
      "type": "object",
      "properties": {
        "model_name": {
          "type": "string",
          "description": "Identifier for the 3D model"
        },
        "signature": {
          "type": "string",
          "description": "RSA digital signature (hex encoded)"
        },
        "artist_info": {
          "type": "object",
          "properties": {
            "name": { "type": "string" },
            "email": { "type": "string", "format": "email" },
            "website": { "type": "string", "format": "uri" },
            "public_key_fingerprint": { "type": "string" }
          },
          "required": ["name"]
        },
        "model_hash": {
          "type": "string",
          "description": "SHA-256 hash of original model (hex encoded)"
        },
        "timestamp": {
          "type": "string",
          "format": "date-time"
        }
      },
      "required": ["model_name", "signature", "artist_info", "model_hash", "timestamp"]
    }
  }
}
```

#### 3.3.2 Secure Mode Schema (v2.0)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "version": {
      "type": "string",
      "enum": ["2.0"]
    },
    "security_level": {
      "type": "string",
      "enum": ["secure"]
    },
    "content_hash": {
      "type": "string",
      "description": "SHA-256 hash of video content for binding"
    },
    "created_at": {
      "type": "string",
      "format": "date-time"
    },
    "signatures": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/secure_signature_entry"
      }
    },
    "integrity_signature": {
      "type": "string",
      "description": "HMAC-SHA256 signature of the payload for tamper detection"
    }
  },
  "$defs": {
    "secure_signature_entry": {
      "type": "object",
      "properties": {
        "model_name": {
          "type": "string",
          "description": "Identifier for the 3D model"
        },
        "signature": {
          "type": "string",
          "description": "RSA digital signature (base64 encoded)"
        },
        "artist_info": {
          "type": "object",
          "properties": {
            "name": { "type": "string" },
            "email": { "type": "string", "format": "email" },
            "website": { "type": "string", "format": "uri" }
          },
          "required": ["name"]
        },
        "model_hash": {
          "type": "string",
          "description": "SHA-256 hash of original model"
        },
        "timestamp": {
          "type": "string",
          "format": "date-time"
        }
      },
      "required": ["model_name", "signature", "artist_info", "model_hash", "timestamp"]
    }
  }
}
```

### 3.4 Example Payloads

#### 3.4.1 Basic Mode Example

```json
{
  "signature_version": "1.0",
  "created_at": "2025-01-17T14:35:26+05:30",
  "total_models": 1,
  "signatures": [
    {
      "model_name": "character_main.obj",
      "signature": "a1b2c3d4e5f6...",
      "artist_info": {
        "name": "John Artist",
        "email": "john@example.com",
        "website": "https://johnartist.com"
      },
      "model_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "timestamp": "2025-01-17T10:30:00+05:30"
    }
  ]
}
```

#### 3.4.2 Secure Mode Example

```json
{
  "version": "2.0",
  "security_level": "secure",
  "content_hash": "f7c3bc1d808e04732adf679965ccc34ca7ae3441",
  "created_at": "2025-01-17T14:35:26+05:30",
  "signatures": [
    {
      "model_name": "character_main.obj",
      "signature": "SGVsbG8gV29ybGQ=",
      "artist_info": {
        "name": "John Artist",
        "email": "john@example.com",
        "website": "https://johnartist.com"
      },
      "model_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "timestamp": "2025-01-17T10:30:00+05:30"
    }
  ],
  "integrity_signature": "a8f5f167f44f4964e6c998dee827110c"
}
```

## 4. Cryptographic Specifications

### 4.1 Basic Mode Cryptography

- **Algorithm**: RSA-PSS with SHA-256
- **Key Size**: Minimum 2048 bits (4096 bits recommended)
- **Salt Length**: Maximum length (PSS.MAX_LENGTH)
- **Hash Function**: SHA-256

### 4.2 Secure Mode Cryptography

#### 4.2.1 Integrity Protection
- **Algorithm**: HMAC-SHA256
- **Key**: System-specific key for metadata integrity
- **Purpose**: Detect tampering of signature metadata

#### 4.2.2 Content Binding
- **Hash Function**: SHA-256 of video content
- **Purpose**: Prevent signature transplantation between videos
- **Implementation**: Video hash included in signature payload

#### 4.2.3 Obfuscation
- **Method**: XOR encoding with system key
- **Encoding**: Double Base64 encoding
- **Purpose**: Hide metadata from casual inspection

#### 4.2.4 Redundant Storage
- **Fields**: comment, description, album metadata fields
- **Verification**: Cross-check all fields for consistency
- **Purpose**: Detect partial tampering attempts

### 4.2 Key Management

- Artists generate RSA key pairs
- Public keys are distributed through artist registries
- Private keys remain with artists for signing
- Key fingerprints use SHA-256 hash of public key DER encoding

## 5. Implementation Guidelines

### 5.1 For 3D Software Vendors

#### 5.1.1 Export Integration

```python
# Pseudo-code for 3D software integration
def export_authenticated_video(scene, output_path):
    signed_models = scan_scene_for_signed_models(scene)
    signatures = extract_signatures(signed_models)

    # Render video normally
    render_video(scene, temp_path)

    # Embed signatures
    embed_3mvap_metadata(temp_path, output_path, signatures)
```

#### 5.1.2 Required APIs

- `scan_scene_models()`: Identify 3D models in scene
- `extract_model_signature()`: Extract signature from signed model
- `embed_metadata()`: Add 3MVAP data to video metadata

### 5.2 For Video Player Vendors

#### 5.2.1 Verification Integration

```python
# Pseudo-code for player integration
def verify_video_before_playback(video_path):
    metadata = extract_3mvap_metadata(video_path)
    if not metadata:
        return PlaybackDecision.ALLOW  # No authentication required

    verification_results = verify_all_signatures(metadata, artist_registry)

    if all_verified(verification_results):
        return PlaybackDecision.ALLOW
    else:
        return PlaybackDecision.BLOCK_WITH_WARNING
```

#### 5.2.2 Required Components

- Metadata extraction engine
- Signature verification library
- Artist registry integration
- User notification system

### 5.3 For Streaming Platform Vendors

#### 5.3.1 Upload Processing

```python
def process_uploaded_video(video_file):
    metadata = extract_3mvap_metadata(video_file)

    if metadata:
        verification_results = verify_signatures(metadata)
        store_verification_status(video_file.id, verification_results)

        if not all_verified(verification_results):
            flag_for_review(video_file)
```

## 6. Artist Registry Specification

### 6.1 Registry Structure

```json
{
  "registry_version": "1.0",
  "artists": [
    {
      "id": "uuid-v4",
      "name": "Artist Name",
      "email": "artist@example.com",
      "public_key": "-----BEGIN PUBLIC KEY-----...",
      "verified": true,
      "verification_date": "2025-01-17T14:35:26+05:30",
      "verification_authority": "registry.3mvap.org"
    }
  ]
}
```

### 6.2 Registry Distribution

- Centralized registry at `registry.3mvap.org`
- Distributed via HTTPS with certificate pinning
- Regular updates through delta synchronization
- Fallback to cached registries for offline verification

## 7. Security Considerations

### 7.1 Threat Model

- **Signature Forgery**: Prevented by RSA cryptography
- **Metadata Tampering**: Detected through signature verification
- **Replay Attacks**: Mitigated by timestamp validation
- **Key Compromise**: Handled through registry revocation

### 7.2 Best Practices

- Regular key rotation (recommended every 2 years)
- Secure key storage for artists
- Certificate transparency for public keys
- Audit trails for signature verification

## 8. Compliance and Certification

### 8.1 Certification Levels

- **Level 1**: Basic metadata support
- **Level 2**: Full signature verification
- **Level 3**: Artist registry integration
- **Level 4**: Real-time verification with user controls

### 8.2 Testing Requirements

- Metadata parsing accuracy: 100%
- Signature verification correctness: 100%
- Performance: <100ms verification time
- Compatibility: Support for major video formats

## 9. Migration and Adoption

### 9.1 Backward Compatibility

- Videos without 3MVAP metadata play normally
- Graceful degradation for unsupported players
- Optional verification warnings

### 9.2 Adoption Phases

1. **Phase 1**: Reference implementations and SDKs
2. **Phase 2**: Major 3D software integration
3. **Phase 3**: Video player adoption
4. **Phase 4**: Streaming platform integration
5. **Phase 5**: Industry-wide standardization

## 10. Reference Implementations

### 10.1 Available Libraries

- **Python**: `3mvap-python` (reference implementation)
- **JavaScript**: `3mvap-js` (web integration)
- **C++**: `lib3mvap` (native performance)
- **Java**: `3mvap-java` (Android/enterprise)

### 10.2 Integration Examples

- Blender addon (production ready)
- VLC plugin (proof of concept)
- Chrome extension (web verification)
- FFmpeg integration (command-line tools)

## 11. Governance

### 11.1 Protocol Governance

- **Maintainer**: 3D Model Authentication Consortium
- **Updates**: Semantic versioning (major.minor.patch)
- **RFC Process**: Public proposals and review
- **Compatibility**: Backward compatibility guaranteed

### 11.2 Registry Governance

- **Authority**: Independent registry consortium
- **Verification**: Multi-party verification process
- **Transparency**: Public audit logs
- **Appeals**: Artist verification appeals process

## 12. Future Extensions

### 12.1 Planned Features

- Multi-signature support for collaborative works
- Blockchain integration for decentralized registries
- AI-generated content detection
- Real-time streaming verification

### 12.2 Version Roadmap

- **v1.1**: Enhanced metadata compression
- **v1.2**: Blockchain registry support
- **v2.0**: Quantum-resistant cryptography

---

## Appendices

### Appendix A: Video Format Compatibility Matrix

| Format | Metadata Support | 3MVAP Compatible | Notes           |
| ------ | ---------------- | ---------------- | --------------- |
| MP4    | ✅ Full          | ✅ Yes           | Recommended     |
| AVI    | ✅ Full          | ✅ Yes           | Legacy support  |
| MOV    | ✅ Full          | ✅ Yes           | Apple ecosystem |
| MKV    | ✅ Full          | ✅ Yes           | Open standard   |
| WebM   | ⚠️ Limited       | ⚠️ Partial       | Web streaming   |

### Appendix B: Cryptographic Test Vectors

[Detailed test vectors for signature verification]

### Appendix C: SDK Integration Guide

[Step-by-step integration instructions for developers]

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-17  
**Status**: Draft Specification  
**Contact**: protocol@3mvap.org
