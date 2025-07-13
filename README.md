# 3D-Model-Auth

A robust tool for embedding and verifying digital signatures in `.obj` 3D model files using advanced steganography. Protect your 3D assets from piracy and unauthorized modifications using RSA cryptography and vertex-level steganographic techniques. This tool is lightweight, user-friendly, and seamlessly integrates into standard 3D workflows.

## Features

- **Generate Unique Digital Signatures**: Create RSA-based tamper-proof signatures for your 3D models.
- **Steganographic Embedding**: Hide signatures within the 3D model's geometry using vertex-level steganography.
- **Tamper-Resistant**: Signatures are distributed across multiple vertices, making them difficult to detect or remove.
- **Verify Signatures**: Authenticate files and detect unauthorized modifications.
- **Preserves Visual Quality**: The steganographic approach makes imperceptible changes that don't affect the model's appearance.
- **Interactive UI**: Easy-to-use Streamlit-based interface for signing and verifying models.

## Tech Stack

- **Python**: Core implementation.
- **Streamlit**: Interactive UI.
- **Cryptography**: Secure RSA key generation and signature verification.
- **Steganography**: Custom implementation for embedding data in 3D geometry.

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

### Sign a 3D Model

1. Upload your `.obj` file.
2. Click **Sign and Download** to generate and embed a digital signature using steganography.
3. Download the signed file for secure sharing.

### Verify a Signed 3D Model

1. Upload a signed `.obj` file.
2. Click **Verify Signature** to check authenticity.

### How It Works

1. **Signature Generation**: The application creates a unique digital signature based on the file content using RSA cryptography.
2. **Steganographic Embedding**: The signature is embedded by making imperceptible modifications to vertex coordinates in the 3D model.
3. **Verification**: When verifying, the application extracts the hidden signature and validates it against the file content.

## File Format Compatibility

- Currently supports `.obj` files. Future updates will include other formats like `.fbx` and `.stl`.

## Use Cases

- **Protect Intellectual Property**: Secure your 3D designs with tamper-evident signatures that can't be easily removed.
- **Ensure Authenticity**: Verify that 3D models haven't been modified since they were signed.
- **Secure Distribution**: Safely share 3D assets knowing they contain hidden authentication data.
- **Forensic Verification**: Detect unauthorized modifications to 3D models in professional workflows.
