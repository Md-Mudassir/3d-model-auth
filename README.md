# 3D-Model-Auth

A robust tool for embedding and verifying digital signatures in `.obj` 3D model files. Protect your 3D assets from piracy and unauthorized modifications using RSA cryptography. This tool is lightweight, user-friendly, and seamlessly integrates into standard 3D workflows.

## Features

- **Generate Unique Digital Signatures**: Create RSA-based tamper-proof signatures for your 3D models.
- **Embed Signatures**: Add signatures as metadata in `.obj` files without altering their structure.
- **Verify Signatures**: Authenticate files and detect unauthorized modifications.
- **Interactive UI**: Easy-to-use Streamlit-based interface for signing and verifying models.

## Tech Stack

- **Python**: Core implementation.
- **Streamlit**: Interactive UI.
- **Cryptography**: Secure RSA key generation and signature verification.

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
2. Click **Sign and Download** to generate and embed a digital signature.
3. Download the signed file for secure sharing.

### Verify a Signed 3D Model

1. Upload a signed `.obj` file.
2. Click **Verify Signature** to check authenticity.

## File Format Compatibility

- Currently supports `.obj` files. Future updates will include other formats like `.fbx` and `.stl`.

## Use Cases

- Protect intellectual property for 3D designers.
- Ensure authenticity in collaborative projects.
- Detect tampering in shared 3D assets.
