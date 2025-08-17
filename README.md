# 3D-Model-Auth

A robust tool for embedding and verifying digital signatures in `.obj` 3D model files and video content using advanced steganography and metadata embedding. Protect your 3D assets from piracy and unauthorized modifications using RSA cryptography and create a universal protocol for video content authentication.

## Features

### **3D Model Authentication**

- **Artist Management**: Create and manage multiple artist profiles, each with their own unique cryptographic identity. Duplicate artist names are prevented for security and clarity.
- **Digital Signatures**: Generate RSA-based tamper-proof signatures for your 3D models. Signing is only allowed for unsigned models, preventing re-signing and preserving artist attribution.
- **Steganographic Embedding**: Hide signatures within the 3D model's geometry using vertex-level steganography, making them tamper-resistant and visually undetectable.
- **Artist Attribution**: Each signed model contains embedded, verifiable artist information.
- **Tamper-Resistant**: Signatures are distributed across multiple vertices, making them difficult to detect or remove.
- **Signature Verification**: Authenticate files, detect unauthorized modifications, and identify the original artist.

### **🎬 Video Authentication Protocol (NEW)**

- **Universal Video Protection**: Embed 3D model signatures directly into video metadata during export/rendering
- **Metadata-Based Verification**: Lightweight verification system that checks video metadata instead of processing frames
- **Production Pipeline Integration**: Blender addon for seamless integration into 3D workflows
- **Real-time Verification**: Media players can instantly verify video authenticity before playback
- **Multi-Model Support**: Track and verify multiple 3D models within a single video
- **Platform Agnostic**: Works with any video format that supports custom metadata

### **Technical Features**

- **Preserves Visual Quality**: The steganographic approach makes imperceptible changes that don't affect the model's appearance.
- **Interactive UI**: Streamlit-based interface for managing artists, signing, and verifying models and videos.
- **Modern 3D Viewer**: Black background, white static models (no auto-spin), and enhanced lighting for maximum clarity and contrast.
- **Database-Backed**: Artist profiles and keys are securely stored in a local SQLite database.
- **Modular Codebase**: Clean separation of concerns with dedicated modules for crypto, database, viewer, and video authentication.

## Tech Stack

- **Python**: Core implementation
- **Streamlit**: Interactive web UI
- **Three.js (via Streamlit component)**: 3D model visualization
- **SQLite**: Local database for artist registry
- **cryptography**: RSA key generation and digital signatures
- **FFmpeg**: Video metadata embedding and extraction
- **MoviePy**: Video processing utilities
- **Blender API**: 3D software integration

## Getting Started

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Install FFmpeg** (required for video authentication):

   ```bash
   # macOS
   brew install ffmpeg

   # Ubuntu/Debian
   sudo apt install ffmpeg

   # Windows
   # Download from https://ffmpeg.org/download.html
   ```

3. **Run the app:**
   ```bash
   streamlit run app.py
   ```
4. **Open the app:**
   Visit the Streamlit URL shown in your terminal (usually `http://localhost:8501`).

## Project Structure

```
3d-model-auth/
├── app.py                          # Main Streamlit app with video authentication
├── utils/
│   ├── crypto.py                   # Digital signature and steganography logic
│   ├── database.py                 # Database setup and artist management
│   ├── viewer.py                   # 3D model viewer (Three.js via Streamlit)
│   └── video_auth.py               # Video metadata authentication system
├── blender_plugin/
│   └── video_auth_addon.py         # Blender addon for video export integration
├── data/                           # SQLite DB and uploaded files (auto-created)
├── objects/                        # Sample 3D models
├── .gitignore                      # Ignores __pycache__ and other artifacts
├── requirements.txt                # Python dependencies
└── README.md                       # This documentation
```

## Usage

### **Manage Artist Profiles**

1. Navigate to the **Artist Management** tab.
2. Create a new artist profile by entering name, email, and optional website.
3. The system will generate a unique cryptographic key pair for the artist.
4. Artist profiles are saved to a local SQLite database for persistence between sessions.
5. Select an existing artist when you want to sign models as that artist.

### **Sign a 3D Model**

1. Select an artist from your artist profiles.
2. Upload your `.obj` file.
3. Click **Sign and Download** to generate and embed a digital signature using steganography.
4. The signature will include both authentication data and artist information.
5. Download the signed file for secure sharing.

### **Verify a Signed 3D Model**

1. Upload a signed `.obj` file.
2. Click **Verify Signature** to check authenticity.
3. The system will display the embedded artist information (name, email, website).
4. You'll see whether the file is authentic and who created it.

### **🎬 Video Authentication**

#### **Create Authenticated Video**

1. Navigate to the **Video Authentication** tab.
2. Upload a video file and the signed `.obj` models used in that video.
3. The system extracts signatures from the 3D models.
4. Click **Create Authenticated Video** to embed signatures into video metadata.
5. Download the authenticated video with embedded protection.

#### **Verify Authenticated Video**

1. Upload an authenticated video file.
2. Click **Verify Video Signatures** to check all embedded signatures.
3. View verification results showing which models are authentic and their artists.
4. The system provides instant feedback without processing video frames.

### **Blender Integration**

1. Install the Blender addon from `blender_plugin/video_auth_addon.py`.
2. In Blender's Render Properties, enable **Video Authentication**.
3. Add signed `.obj` files used in your scene.
4. Extract signatures from the models.
5. Render with **Render Authenticated Video** to automatically create protected content.

## How It Works

### **3D Model Authentication**

1. **Artist Registration**: Each artist gets a unique RSA key pair for signing their work, stored securely in a local database.
2. **Signature Generation**: The application creates a unique digital signature based on the file content using the artist's private key.
3. **Artist Attribution**: The artist's information is embedded alongside the signature.
4. **Steganographic Embedding**: Both signature and artist data are embedded by making imperceptible modifications to vertex coordinates in the 3D model.
5. **Verification**: When verifying, the application extracts the hidden signature and artist information, then validates the signature against the file content.

### **Video Authentication Protocol**

1. **Export-Time Embedding**: During video rendering/export, 3D model signatures are collected and embedded into video metadata.
2. **Metadata Storage**: Signatures are stored as Base64-encoded JSON in custom metadata fields.
3. **Player-Side Verification**: Media players or browser extensions can read metadata and verify signatures before playback.
4. **Universal Protocol**: Any video platform or player can implement this verification system.

## Universal Protocol Specification

The video authentication system creates a universal protocol for protecting 3D content in videos:

### **Metadata Format**

```json
{
  "signature_version": "1.0",
  "created_at": "2025-01-17T14:26:38+05:30",
  "total_models": 2,
  "signatures": [
    {
      "model_name": "character.obj",
      "signature": "abc123...",
      "artist_info": {
        "name": "Artist Name",
        "email": "artist@example.com"
      },
      "model_hash": "def456...",
      "timestamp": "2025-01-17T14:26:38+05:30"
    }
  ]
}
```

### **Integration Points**

- **3D Software**: Blender, Maya, Cinema 4D plugins
- **Video Players**: VLC, Media Player, browser players
- **Streaming Platforms**: YouTube, Netflix, Vimeo integration
- **Browser Extensions**: Universal web video verification

## File Format Compatibility

- **3D Models**: Currently supports `.obj` files. Future updates will include `.fbx`, `.stl`, and `.gltf`.
- **Videos**: Supports `.mp4`, `.avi`, `.mov`, `.mkv` with metadata capabilities.

## Use Cases

### **3D Model Protection**

- **Protect Intellectual Property**: Secure your 3D designs with tamper-evident signatures that can't be easily removed.
- **Ensure Authenticity**: Verify that 3D models haven't been modified since they were signed.
- **Secure Distribution**: Safely share 3D assets knowing they contain hidden authentication data.
- **Forensic Verification**: Detect unauthorized modifications to 3D models in professional workflows.
- **Artist Identification**: Identify the original creator of a 3D model even after multiple transfers.
- **Studio Management**: Maintain a database of artists and their signed works in a professional studio environment.

### **Video Content Protection**

- **Universal DRM**: Create a universal protocol for protecting 3D content in video streams.
- **Content Verification**: Verify that videos contain only authenticated 3D models before playback.
- **Piracy Prevention**: Detect and block videos containing unauthorized 3D content.
- **Platform Integration**: Enable streaming platforms to verify content authenticity automatically.
- **Production Pipeline**: Integrate authentication directly into 3D rendering workflows.

## UI/UX Highlights

- **3D Viewer:** Black background, white models, static (no auto-spin), with multiple enhanced light sources for crisp definition.
- **Security:**
  - Prevents duplicate artist names.
  - Prevents re-signing of already signed models (shows error with original artist info).
- **Immediate Feedback:** User-friendly error and success messages throughout the app.
- **Video Processing:** Streamlined workflow for creating and verifying authenticated videos.

## License

MIT License

---

For questions or contributions, please open an issue or pull request!
