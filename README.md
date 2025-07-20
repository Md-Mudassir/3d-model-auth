# 3D-Model-Auth

A robust tool for embedding and verifying digital signatures in `.obj` 3D model files using advanced steganography. Protect your 3D assets from piracy and unauthorized modifications using RSA cryptography and vertex-level steganographic techniques. This tool supports multiple artist identities, allowing creators to securely sign their work with unique digital signatures that can be verified later.

## Features

- **Artist Management**: Create and manage multiple artist profiles, each with their own unique cryptographic identity. Duplicate artist names are prevented for security and clarity.
- **Digital Signatures**: Generate RSA-based tamper-proof signatures for your 3D models. Signing is only allowed for unsigned models, preventing re-signing and preserving artist attribution.
- **Steganographic Embedding**: Hide signatures within the 3D model's geometry using vertex-level steganography, making them tamper-resistant and visually undetectable.
- **Artist Attribution**: Each signed model contains embedded, verifiable artist information.
- **Tamper-Resistant**: Signatures are distributed across multiple vertices, making them difficult to detect or remove.
- **Signature Verification**: Authenticate files, detect unauthorized modifications, and identify the original artist.
- **Preserves Visual Quality**: The steganographic approach makes imperceptible changes that don't affect the model's appearance.
- **Interactive UI**: Streamlit-based interface for managing artists, signing, and verifying models.
- **Modern 3D Viewer**: Black background, white static models (no auto-spin), and enhanced lighting for maximum clarity and contrast.
- **Database-Backed**: Artist profiles and keys are securely stored in a local SQLite database.
- **Modular Codebase**: Clean separation of concerns with `utils/crypto.py`, `utils/database.py`, and `utils/viewer.py`.

## Tech Stack

- **Python**: Core implementation
- **Streamlit**: Interactive web UI
- **Three.js (via Streamlit component)**: 3D model visualization
- **SQLite**: Local database for artist registry
- **cryptography**: RSA key generation and digital signatures

## Getting Started

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the app:**
   ```bash
   streamlit run app.py
   ```
3. **Open the app:**
   Visit the Streamlit URL shown in your terminal (usually `http://localhost:8501`).

## Project Structure

```
3d-model-auth/
├── app.py                # Main Streamlit app
├── utils/
│   ├── crypto.py         # Digital signature and steganography logic
│   ├── database.py       # Database setup and artist management
│   └── viewer.py         # 3D model viewer (Three.js via Streamlit)
├── data/                 # SQLite DB and uploaded files (auto-created)
├── .gitignore            # Ignores __pycache__ and other artifacts
├── requirements.txt      # Python dependencies
└── README.md             # This documentation
```

## UI/UX Highlights
- **3D Viewer:** Black background, white models, static (no auto-spin), with multiple enhanced light sources for crisp definition.
- **Security:**
  - Prevents duplicate artist names.
  - Prevents re-signing of already signed models (shows error with original artist info).
- **Immediate Feedback:** User-friendly error and success messages throughout the app.

## License
MIT License

---

For questions or contributions, please open an issue or pull request!
- **Streamlit**: Interactive UI.
- **Cryptography**: Secure RSA key generation and signature verification.
- **Steganography**: Custom implementation for embedding data in 3D geometry.
- **SQLite**: Local database for persistent artist profile storage.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/md-mudassir/3D-Model-Auth.git
cd 3D-Model-Auth
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
streamlit run app.py
```

## Usage

### Manage Artist Profiles

1. Navigate to the **Artist Management** tab.
2. Create a new artist profile by entering name, email, and optional website.
3. The system will generate a unique cryptographic key pair for the artist.
4. Artist profiles are saved to a local SQLite database for persistence between sessions.
5. Select an existing artist when you want to sign models as that artist.

### Sign a 3D Model

1. Select an artist from your artist profiles.
2. Upload your `.obj` file.
3. Click **Sign and Download** to generate and embed a digital signature using steganography.
4. The signature will include both authentication data and artist information.
5. Download the signed file for secure sharing.

### Verify a Signed 3D Model

1. Upload a signed `.obj` file.
2. Click **Verify Signature** to check authenticity.
3. The system will display the embedded artist information (name, email, website).
4. You'll see whether the file is authentic and who created it.

### How It Works

1. **Artist Registration**: Each artist gets a unique RSA key pair for signing their work, stored securely in a local database.
2. **Signature Generation**: The application creates a unique digital signature based on the file content using the artist's private key.
3. **Artist Attribution**: The artist's information is embedded alongside the signature.
4. **Steganographic Embedding**: Both signature and artist data are embedded by making imperceptible modifications to vertex coordinates in the 3D model.
5. **Verification**: When verifying, the application extracts the hidden signature and artist information, then validates the signature against the file content.
6. **Persistent Storage**: All artist profiles are saved in a SQLite database, ensuring they remain available across application restarts.

## File Format Compatibility

- Currently supports `.obj` files. Future updates will include other formats like `.fbx` and `.stl`.

## Use Cases

- **Protect Intellectual Property**: Secure your 3D designs with tamper-evident signatures that can't be easily removed.
- **Ensure Authenticity**: Verify that 3D models haven't been modified since they were signed.
- **Secure Distribution**: Safely share 3D assets knowing they contain hidden authentication data.
- **Forensic Verification**: Detect unauthorized modifications to 3D models in professional workflows.
- **Artist Identification**: Identify the original creator of a 3D model even after multiple transfers.
- **Studio Management**: Maintain a database of artists and their signed works in a professional studio environment.
