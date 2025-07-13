# 3D-Model-Auth

A robust tool for embedding and verifying digital signatures in `.obj` 3D model files using advanced steganography. Protect your 3D assets from piracy and unauthorized modifications using RSA cryptography and vertex-level steganographic techniques. This tool supports multiple artist identities, allowing creators to securely sign their work with unique digital signatures that can be verified later.

## Features

- **Artist Management**: Create and manage multiple artist profiles, each with their own unique cryptographic identity.
- **Generate Unique Digital Signatures**: Create RSA-based tamper-proof signatures for your 3D models.
- **Steganographic Embedding**: Hide signatures within the 3D model's geometry using vertex-level steganography.
- **Artist Attribution**: Each signed model contains embedded artist information that can be verified later.
- **Tamper-Resistant**: Signatures are distributed across multiple vertices, making them difficult to detect or remove.
- **Verify Signatures**: Authenticate files and detect unauthorized modifications while identifying the original artist.
- **Preserves Visual Quality**: The steganographic approach makes imperceptible changes that don't affect the model's appearance.
- **Interactive UI**: Easy-to-use Streamlit-based interface for managing artists, signing, and verifying models.

## Tech Stack

- **Python**: Core implementation.
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
