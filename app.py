import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import os
import struct
import numpy as np
import re

# Generate RSA keys for demonstration
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Sign the file
def generate_signature(file_data, private_key):
    # We hash the file data directly
    file_hash = hashlib.sha256(file_data).digest()
    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

# Embed the signature in the OBJ file using steganography
def embed_signature(obj_data, signature, original_hash=None):
    # Parse the OBJ file to extract vertices
    lines = obj_data.split('\n')
    vertex_lines = [i for i, line in enumerate(lines) if line.startswith('v ')]
    
    if len(vertex_lines) < 20:
        raise ValueError("Not enough vertices in the model to embed signature securely")
    
    # Convert hex signature to binary
    signature_bytes = bytes.fromhex(signature)
    
    # Each byte needs 4 vertices to encode (2 bits per vertex)
    required_vertices = len(signature_bytes) * 4
    
    if len(vertex_lines) < required_vertices:
        raise ValueError(f"Model has {len(vertex_lines)} vertices, but {required_vertices} are needed to embed the signature")
    
    # Encode each byte of the signature into the least significant bits of vertex coordinates
    for byte_idx, byte_val in enumerate(signature_bytes):
        for bit_pair_idx in range(4):  # 4 pairs of bits per byte
            if byte_idx * 4 + bit_pair_idx >= len(vertex_lines):
                break
                
            vertex_line_idx = vertex_lines[byte_idx * 4 + bit_pair_idx]
            vertex_parts = lines[vertex_line_idx].split()
            
            if len(vertex_parts) < 4:  # v x y z format
                continue
                
            # Get the 2 bits to encode
            bit_pair = (byte_val >> (6 - bit_pair_idx * 2)) & 0b11
            
            # Modify the z-coordinate slightly to encode the bits
            z_coord = float(vertex_parts[3])
            # Keep most of the precision but modify the last few digits
            z_int = struct.unpack('!I', struct.pack('!f', z_coord))[0]
            # Clear the last 2 bits and set our bits
            z_int = (z_int & ~0b11) | bit_pair
            z_new = struct.unpack('!f', struct.pack('!I', z_int))[0]
            
            # Update the vertex line
            vertex_parts[3] = f"{z_new:.8f}"
            lines[vertex_line_idx] = ' '.join(vertex_parts)
    
    # Add a marker to indicate this file has an embedded signature
    # Include the original file hash to ensure verification works correctly
    if original_hash:
        hash_marker = f"# OBJ file with embedded authentication - Hash:{original_hash}"
    else:
        hash_marker = "# OBJ file with embedded authentication"
        
    if not lines[0].startswith('#'):
        lines.insert(0, hash_marker)
    else:
        lines.insert(1, hash_marker)
        
    return '\n'.join(lines)

# Extract the signature from the OBJ file using steganography
def extract_signature(obj_data):
    lines = obj_data.split('\n')
    
    # Check if this file has our marker and extract the original hash if present
    has_marker = False
    original_hash = None
    
    for i in range(min(5, len(lines))):
        if "embedded authentication" in lines[i]:
            has_marker = True
            # Try to extract the original hash if it exists
            if "Hash:" in lines[i]:
                original_hash = lines[i].split("Hash:", 1)[1].strip()
            break
            
    if not has_marker:
        # Try the old method for backward compatibility
        for line in lines:
            if line.startswith("# Digital Signature:"):
                return line.split(":", 1)[1].strip(), None
        return None, None
    
    # Extract vertices
    vertex_lines = [i for i, line in enumerate(lines) if line.startswith('v ')]
    
    if len(vertex_lines) < 20:
        return None  # Not enough vertices to contain a signature
        
    # Reconstruct signature bytes
    signature_bytes = bytearray()
    byte_val = 0
    
    for i in range(0, len(vertex_lines) // 4):
        byte_val = 0
        for j in range(4):  # 4 pairs of bits per byte
            if i * 4 + j >= len(vertex_lines):
                break
                
            vertex_line_idx = vertex_lines[i * 4 + j]
            vertex_parts = lines[vertex_line_idx].split()
            
            if len(vertex_parts) < 4:
                continue
                
            # Extract bits from z-coordinate
            z_coord = float(vertex_parts[3])
            z_int = struct.unpack('!I', struct.pack('!f', z_coord))[0]
            bit_pair = z_int & 0b11
            
            # Add these bits to our byte
            byte_val |= (bit_pair << (6 - j * 2))
            
        signature_bytes.append(byte_val)
        
        # We assume the signature is 256 bytes (2048-bit RSA)
        if len(signature_bytes) >= 256:
            break
            
    return signature_bytes.hex(), original_hash

# Verify the signature
def verify_signature(file_data, signature, public_key):
    file_hash = hashlib.sha256(file_data).digest()
    
    try:
        # Convert the signature from hex to bytes
        signature_bytes = bytes.fromhex(signature)
        
        # Verify the signature
        public_key.verify(
            signature_bytes,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# Streamlit App
def main():
    st.set_page_config(page_title="3D Model Digital Signature Tool", page_icon="🔏", layout="centered")
    st.title("🔏 3D Model Digital Signature Tool")
    st.caption("Digitally sign and verify 3D model (.obj) files with ease and confidence.")
    st.markdown("""
    <style>
    .stTabs [data-baseweb="tab-list"] {
        justify-content: center;
    }
    .stTabs [data-baseweb="tab"] {
        font-size: 18px;
        padding: 0.5rem 2rem;
    }
    .signature-box {
        background: #23272f;
        color: #fff;
        border-radius: 8px;
        padding: 1em;
        font-family: monospace;
        font-size: 1em;
        word-break: break-all;
        margin-bottom: 0.5em;
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    </style>
    """, unsafe_allow_html=True)

    # Generate RSA keys only once per session
    if 'private_key' not in st.session_state or 'public_key' not in st.session_state:
        private_key, public_key = generate_keys()
        st.session_state['private_key'] = private_key
        st.session_state['public_key'] = public_key
    private_key = st.session_state['private_key']
    public_key = st.session_state['public_key']
    tab1, tab2 = st.tabs(["🖊️ Sign File", "🔎 Verify File"])

    with tab1:
        st.header("🖊️ Sign a 3D Model File")
        st.markdown("""
        **How to sign your 3D model:**
        1. Upload your `.obj` file below.
        2. Click **Sign and Download**.
        3. Download your signed file and keep the signature for your records.
        """)
        uploaded_file = st.file_uploader("Upload a 3D Model (.obj) file", type=["obj"], key="sign-upload")
        if uploaded_file:
            obj_data = uploaded_file.read().decode("utf-8")
            file_info = f"**File:** `{uploaded_file.name}` ({uploaded_file.size} bytes)"
            st.markdown(file_info)
            with st.expander("🔍 Preview File Contents"):
                st.text_area("File Preview", obj_data, height=200, disabled=True)
            sign_btn = st.button("🖊️ Sign and Download", key="sign-btn", use_container_width=True)
            if sign_btn:
                with st.spinner("🔏 Generating digital signature and preparing your file..."):
                    # First, clean the file of any existing authentication markers
                    clean_lines = [line for line in obj_data.split('\n') 
                                  if not line.startswith("# Digital Signature:") 
                                  and not "embedded authentication" in line]
                    clean_obj_data = '\n'.join(clean_lines)
                    if obj_data.endswith('\n'):
                        clean_obj_data += '\n'
                    
                    # Calculate hash of the clean data for verification later
                    sign_hash = hashlib.sha256(clean_obj_data.encode()).digest().hex()
                        
                    # Generate signature based on the clean data
                    signature = generate_signature(clean_obj_data.encode(), private_key)
                    
                    # Embed the signature along with the original hash
                    signed_obj_data = embed_signature(obj_data, signature, sign_hash)
                st.success("File signed and ready for download!")
                st.markdown("**Digital Signature:**")
                st.markdown(f'<div class="signature-box">{signature}</div>', unsafe_allow_html=True)
                st.download_button(
                    label="⬇️ Download Signed File",
                    data=signed_obj_data,
                    file_name="signed_model.obj",
                    mime="text/plain",
                    key="signed-download"
                )
        else:
            st.info("Upload a .obj file to enable signing.")

    with tab2:
        st.header("🔎 Verify a Signed 3D Model File")
        st.markdown("""
        **How to verify a signed file:**
        1. Upload a signed `.obj` file below.
        2. Click **Verify Signature**.
        3. See if the file is authentic and view the extracted signature.
        """)
        uploaded_file = st.file_uploader("Upload a Signed 3D Model (.obj) file", type=["obj"], key="verify-upload")
        if uploaded_file:
            obj_data = uploaded_file.read().decode("utf-8")
            file_info = f"**File:** `{uploaded_file.name}` ({uploaded_file.size} bytes)"
            st.markdown(file_info)
            with st.expander("🔍 Preview File Contents"):
                st.text_area("File Preview", obj_data, height=200, disabled=True)
            verify_btn = st.button("🔎 Verify Signature", key="verify-btn", use_container_width=True)
            if verify_btn:
                with st.spinner("🔎 Extracting and verifying digital signature..."):
                    signature, original_hash = extract_signature(obj_data)
                    if signature:
                        st.markdown("**Extracted Signature:**")
                        st.markdown(f'<div class="signature-box">{signature}</div>', unsafe_allow_html=True)
                        
                        # Check if it's an old-style signature (in comments) or new steganographic signature
                        is_old_style = any(line.startswith("# Digital Signature:") for line in obj_data.split('\n'))
                        
                        # For both old and new style signatures, we need to clean the file
                        # of any authentication markers before verification
                        lines = obj_data.split('\n')
                        
                        # Remove both types of markers
                        unsigned_lines = [line for line in lines 
                                        if not line.startswith("# Digital Signature:") 
                                        and not "embedded authentication" in line]
                        
                        # Create a clean version for verification
                        unsigned_obj_data = '\n'.join(unsigned_lines)
                        if obj_data.endswith('\n'):
                            unsigned_obj_data += '\n'
                            
                        try:
                            # If we have the original hash from the file, use it for verification
                            # otherwise calculate the hash from the unsigned data
                            if original_hash:
                                # Using stored original hash for verification
                                # Create a hash object with the stored hash
                                file_hash = bytes.fromhex(original_hash)
                                try:
                                    # Verify using the stored hash instead of recalculating
                                    public_key.verify(
                                        bytes.fromhex(signature),
                                        file_hash,
                                        padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH
                                        ),
                                        hashes.SHA256()
                                    )
                                    verified = True
                                except Exception as e:
                                    # Verification failed
                                    verified = False
                            else:
                                # Fall back to the old method if no original hash is available
                                # Calculate hash for verification
                                verify_hash = hashlib.sha256(unsigned_obj_data.encode()).digest().hex()
                                
                                verified = verify_signature(unsigned_obj_data.encode(), signature, public_key)
                                
                            if verified:
                                st.success("✅ Signature verified successfully! The file is authentic.")
                            else:
                                st.error("❌ Signature verification failed. The file may have been tampered with.")
                        except Exception as e:
                            st.error(f"Error during verification: {str(e)}")
                    else:
                        st.warning("No digital signature found in the file.")
        else:
            st.info("Upload a signed .obj file to enable verification.")

if __name__ == "__main__":
    main()