# 3MVAP SDK Integration Guide

## Quick Start for Developers

This guide helps you integrate 3D Model Video Authentication Protocol (3MVAP) into your applications.

## Installation

### Python SDK

```bash
pip install 3mvap-python
# or from source
pip install git+https://github.com/3mvap/3mvap-python.git
```

### JavaScript SDK

```bash
npm install 3mvap-js
# or
yarn add 3mvap-js
```

### C++ Library

```bash
# Ubuntu/Debian
sudo apt install lib3mvap-dev

# macOS
brew install lib3mvap

# From source
git clone https://github.com/3mvap/lib3mvap.git
cd lib3mvap && make install
```

## Basic Usage

### Python - Video Verification

```python
from mvap import VideoAuthenticator, ArtistRegistry

# Initialize
authenticator = VideoAuthenticator()
registry = ArtistRegistry.load_default()

# Verify a video
result = authenticator.verify_video("video.mp4", registry)

if result.is_authenticated:
    print(f"✅ Video verified with {len(result.signatures)} models")
    for sig in result.signatures:
        print(f"  - {sig.model_name} by {sig.artist_name}")
else:
    print("❌ Video authentication failed")
```

### JavaScript - Browser Integration

```javascript
import { VideoAuthenticator, ArtistRegistry } from "3mvap-js";

const authenticator = new VideoAuthenticator();
const registry = await ArtistRegistry.loadDefault();

// Verify video before playback
async function verifyVideo(videoElement) {
  const result = await authenticator.verifyVideo(videoElement.src, registry);

  if (result.isAuthenticated) {
    showVerificationBadge(result.signatures);
    return true; // Allow playback
  } else {
    showWarningDialog("Unverified 3D content detected");
    return false; // Block or warn
  }
}
```

### C++ - Native Integration

```cpp
#include <3mvap/authenticator.h>
#include <3mvap/registry.h>

using namespace mvap;

int main() {
    VideoAuthenticator auth;
    ArtistRegistry registry = ArtistRegistry::loadDefault();

    auto result = auth.verifyVideo("video.mp4", registry);

    if (result.isAuthenticated()) {
        std::cout << "✅ Video verified\n";
    } else {
        std::cout << "❌ Verification failed\n";
    }

    return 0;
}
```

## Integration Patterns

### 1. Video Player Integration

#### Pre-Playback Verification

```python
class AuthenticatedVideoPlayer:
    def __init__(self):
        self.authenticator = VideoAuthenticator()
        self.registry = ArtistRegistry.load_default()

    def load_video(self, video_path):
        # Verify before loading
        result = self.authenticator.verify_video(video_path, self.registry)

        if not result.is_authenticated:
            self.show_warning_dialog(result.errors)
            return False

        # Load and play video
        self.media_player.load(video_path)
        self.show_verification_badge(result.signatures)
        return True
```

#### Background Verification

```python
import asyncio

class BackgroundVerifier:
    async def verify_in_background(self, video_path):
        result = await self.authenticator.verify_video_async(video_path)

        # Update UI with verification status
        self.update_verification_status(result)
```

### 2. 3D Software Integration

#### Export Hook

```python
# Blender/Maya/Cinema 4D integration
class VideoExportHook:
    def on_export_start(self, scene, output_path):
        # Scan scene for signed models
        signed_models = self.scan_scene_models(scene)

        if signed_models:
            # Extract signatures
            signatures = [self.extract_signature(model) for model in signed_models]

            # Register post-export callback
            self.register_post_export_callback(output_path, signatures)

    def on_export_complete(self, video_path, signatures):
        # Embed signatures into video metadata
        self.authenticator.embed_signatures(video_path, signatures)
```

### 3. Streaming Platform Integration

#### Upload Processing

```python
class StreamingPlatformProcessor:
    def process_upload(self, video_file):
        # Extract and verify signatures
        result = self.authenticator.verify_video(video_file.path, self.registry)

        # Store verification status
        self.database.store_verification(
            video_id=video_file.id,
            is_authenticated=result.is_authenticated,
            signatures=result.signatures,
            verification_date=datetime.now()
        )

        # Flag for review if needed
        if not result.is_authenticated and self.requires_authentication:
            self.flag_for_manual_review(video_file)
```

#### Playback API

```python
@app.route('/api/video/<video_id>/verify')
def verify_video_api(video_id):
    verification = database.get_verification(video_id)

    return {
        'authenticated': verification.is_authenticated,
        'signatures': [
            {
                'model_name': sig.model_name,
                'artist_name': sig.artist_name,
                'verified': sig.verified
            } for sig in verification.signatures
        ]
    }
```

## Advanced Features

### Custom Artist Registry

```python
# Use custom registry instead of default
registry = ArtistRegistry()
registry.add_artist({
    'name': 'Custom Artist',
    'public_key': '-----BEGIN PUBLIC KEY-----...',
    'verified': True
})

# Or load from custom source
registry = ArtistRegistry.load_from_url('https://mycompany.com/artists.json')
```

### Signature Embedding

```python
# Create authenticated video from scratch
embedder = SignatureEmbedder()

signatures = [
    {
        'model_name': 'character.obj',
        'signature': 'abc123...',
        'artist_info': {'name': 'Artist Name'},
        'model_hash': 'def456...'
    }
]

embedder.embed_signatures('input.mp4', 'output_authenticated.mp4', signatures)
```

### Performance Optimization

```python
# Async verification for better performance
async def verify_multiple_videos(video_paths):
    tasks = [
        authenticator.verify_video_async(path, registry)
        for path in video_paths
    ]

    results = await asyncio.gather(*tasks)
    return results

# Cached registry for faster lookups
registry = ArtistRegistry.load_default()
registry.enable_cache(ttl=3600)  # Cache for 1 hour
```

## Error Handling

### Common Error Patterns

```python
try:
    result = authenticator.verify_video(video_path, registry)
except VideoNotFoundError:
    print("Video file not found")
except InvalidMetadataError:
    print("Invalid 3MVAP metadata format")
except RegistryUnavailableError:
    print("Artist registry unavailable, using cached data")
except SignatureVerificationError as e:
    print(f"Signature verification failed: {e.details}")
```

### Graceful Degradation

```python
def verify_with_fallback(video_path):
    try:
        return authenticator.verify_video(video_path, registry)
    except Exception as e:
        logger.warning(f"Verification failed: {e}")

        # Return permissive result for backward compatibility
        return VerificationResult(
            is_authenticated=None,  # Unknown status
            allow_playback=True,    # Allow by default
            error=str(e)
        )
```

## Testing

### Unit Tests

```python
import unittest
from mvap.testing import MockRegistry, create_test_video

class TestVideoAuthentication(unittest.TestCase):
    def setUp(self):
        self.authenticator = VideoAuthenticator()
        self.registry = MockRegistry()

    def test_valid_signature_verification(self):
        # Create test video with valid signatures
        video_path = create_test_video(signatures=['valid_sig_1'])

        result = self.authenticator.verify_video(video_path, self.registry)

        self.assertTrue(result.is_authenticated)
        self.assertEqual(len(result.signatures), 1)

    def test_invalid_signature_rejection(self):
        video_path = create_test_video(signatures=['invalid_sig'])

        result = self.authenticator.verify_video(video_path, self.registry)

        self.assertFalse(result.is_authenticated)
```

### Integration Tests

```python
def test_end_to_end_workflow():
    # 1. Create signed model
    model = create_signed_model('test_artist')

    # 2. Create video with model
    video = create_video_with_model(model)

    # 3. Embed signatures
    authenticated_video = embed_signatures(video, [model.signature])

    # 4. Verify
    result = verify_video(authenticated_video)

    assert result.is_authenticated
```

## Platform-Specific Notes

### Web Browsers

- Use Web Workers for signature verification to avoid blocking UI
- Implement Content Security Policy (CSP) for registry requests
- Cache verification results in localStorage

### Mobile Apps

- Use native crypto libraries for better performance
- Implement offline verification with cached registries
- Consider battery impact of verification operations

### Desktop Applications

- Integrate with system certificate stores
- Provide user preferences for verification strictness
- Support proxy configurations for registry access

## Performance Guidelines

### Optimization Tips

1. **Cache Registry Data**: Load artist registry once, cache for session
2. **Async Verification**: Use async/await for non-blocking verification
3. **Batch Processing**: Verify multiple videos in parallel
4. **Lazy Loading**: Only verify when needed (e.g., before playback)
5. **Metadata Caching**: Cache verification results to avoid re-verification

### Benchmarks

- **Metadata Extraction**: <10ms for typical video files
- **Signature Verification**: <50ms per signature
- **Registry Lookup**: <5ms with local cache
- **Total Verification**: <100ms for videos with 1-5 models

## Security Best Practices

1. **Validate Input**: Always validate video files and metadata
2. **Secure Registry**: Use HTTPS and certificate pinning for registry access
3. **Key Management**: Never expose private keys in client applications
4. **Audit Logging**: Log all verification attempts for security monitoring
5. **Rate Limiting**: Implement rate limits for registry requests

## Support and Resources

- **Documentation**: https://docs.3mvap.org
- **GitHub**: https://github.com/3mvap
- **Discord**: https://discord.gg/3mvap
- **Email**: support@3mvap.org

## License

All 3MVAP SDKs are released under MIT License for maximum compatibility and adoption.
