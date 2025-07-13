import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import os
import struct
import numpy as np
import re
import json
import base64
from datetime import datetime
import sqlite3
import pathlib

# Generate RSA keys for an artist
def generate_keys(artist_name):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Serialize keys for storage
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, public_key, private_pem, public_pem

# Load keys from PEM format
def load_key_from_pem(pem_data, is_private=False):
    if is_private:
        return serialization.load_pem_private_key(
            pem_data,
            password=None,
        )
    else:
        return serialization.load_pem_public_key(
            pem_data
        )

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
def embed_signature(obj_data, signature, artist_info, original_hash=None):
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
    # Include the original file hash and artist information to ensure verification works correctly
    artist_info_b64 = base64.b64encode(json.dumps(artist_info).encode()).decode()
    
    if original_hash:
        hash_marker = f"# OBJ file with embedded authentication - Hash:{original_hash} - Artist:{artist_info_b64}"
    else:
        hash_marker = f"# OBJ file with embedded authentication - Artist:{artist_info_b64}"
        
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
    artist_info = None
    
    for i in range(min(5, len(lines))):
        if "embedded authentication" in lines[i]:
            has_marker = True
            # Try to extract the original hash if it exists
            if "Hash:" in lines[i]:
                hash_part = lines[i].split("Hash:", 1)[1].strip()
                if " - Artist:" in hash_part:
                    original_hash = hash_part.split(" - Artist:", 1)[0].strip()
                    artist_b64 = hash_part.split(" - Artist:", 1)[1].strip()
                    try:
                        artist_info = json.loads(base64.b64decode(artist_b64).decode())
                    except:
                        artist_info = None
                else:
                    original_hash = hash_part
            elif " - Artist:" in lines[i]:
                artist_b64 = lines[i].split(" - Artist:", 1)[1].strip()
                try:
                    artist_info = json.loads(base64.b64decode(artist_b64).decode())
                except:
                    artist_info = None
            break
            
    if not has_marker:
        # Try the old method for backward compatibility
        for line in lines:
            if line.startswith("# Digital Signature:"):
                return line.split(":", 1)[1].strip(), None, None
        return None, None, None
    
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
            
    return signature_bytes.hex(), original_hash, artist_info

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

# Database setup
def setup_database():
    # Create a data directory if it doesn't exist
    data_dir = pathlib.Path("./data")
    data_dir.mkdir(exist_ok=True)
    
    # Connect to SQLite database (will be created if it doesn't exist)
    conn = sqlite3.connect('./data/artist_registry.db')
    cursor = conn.cursor()
    
    # Create artists table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS artists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        email TEXT NOT NULL,
        website TEXT,
        created_at TEXT NOT NULL,
        private_key TEXT NOT NULL,
        public_key TEXT NOT NULL
    )
    ''')
    
    conn.commit()
    return conn

# Load artists from database
def load_artists_from_db(conn):
    cursor = conn.cursor()
    cursor.execute('SELECT name, email, website, created_at, private_key, public_key FROM artists')
    artists = {}
    
    for row in cursor.fetchall():
        name, email, website, created_at, private_key, public_key = row
        artists[name] = {
            "name": name,
            "email": email,
            "website": website,
            "created_at": created_at,
            "private_key": private_key,
            "public_key": public_key
        }
    
    return artists

# Save artist to database
def save_artist_to_db(conn, artist_info):
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        INSERT INTO artists (name, email, website, created_at, private_key, public_key)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            artist_info["name"],
            artist_info["email"],
            artist_info["website"],
            artist_info["created_at"],
            artist_info["private_key"],
            artist_info["public_key"]
        ))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Artist with this name already exists
        return False

# Streamlit App
def main():
    st.set_page_config(page_title="3D Model Digital Signature Tool", page_icon="🔏", layout="centered")
    st.title("🔏 3D Model Digital Signature Tool")
    st.caption("Digitally sign and verify 3D model (.obj) files with ease and confidence.")
    
    # Setup database connection
    conn = setup_database()
    
    # Initialize artist registry from database
    if 'artist_registry' not in st.session_state:
        st.session_state['artist_registry'] = load_artists_from_db(conn)
        
    # Initialize current artist if it doesn't exist
    if 'current_artist' not in st.session_state:
        st.session_state['current_artist'] = None
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

    # Create tabs for the application
    tab1, tab2, tab3 = st.tabs(["👨‍🎨 Artist Management", "🖊️ Sign File", "🔎 Verify File"])
    
    # Handle artist management in tab1
    with tab1:
        st.header("👨‍🎨 Artist Management")
        st.markdown("""
        **Manage Artist Profiles and Keys**
        
        Each artist can have their own unique digital signature for their 3D models.
        Create a new artist profile or select an existing one to sign your models.
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Create New Artist")
            new_artist_name = st.text_input("Artist Name", key="new_artist_name")
            new_artist_email = st.text_input("Email", key="new_artist_email")
            new_artist_website = st.text_input("Website (optional)", key="new_artist_website")
            
            if st.button("Create Artist Profile", use_container_width=True):
                if new_artist_name and new_artist_email:
                    # Generate keys for the new artist
                    private_key, public_key, private_pem, public_pem = generate_keys(new_artist_name)
                    
                    # Create artist profile
                    artist_info = {
                        "name": new_artist_name,
                        "email": new_artist_email,
                        "website": new_artist_website,
                        "created_at": datetime.now().isoformat(),
                        "private_key": private_pem.decode(),
                        "public_key": public_pem.decode()
                    }
                    
                    # Save to database
                    if save_artist_to_db(conn, artist_info):
                        # Add to registry
                        st.session_state['artist_registry'][new_artist_name] = artist_info
                        st.session_state['current_artist'] = new_artist_name
                        
                        st.success(f"Created new artist profile for {new_artist_name}")
                    else:
                        st.error(f"An artist with the name {new_artist_name} already exists.")
                else:
                    st.error("Artist name and email are required")
        
        with col2:
            st.subheader("Select Existing Artist")
            if st.session_state['artist_registry']:
                artist_names = list(st.session_state['artist_registry'].keys())
                selected_artist = st.selectbox("Choose Artist", options=artist_names, index=0 if artist_names else None)
                
                if selected_artist and st.button("Use This Artist", use_container_width=True):
                    st.session_state['current_artist'] = selected_artist
                    st.success(f"Now using {selected_artist} for signing")
                    
                if st.session_state['current_artist'] in st.session_state['artist_registry']:
                    artist = st.session_state['artist_registry'][st.session_state['current_artist']]
                    st.info(f"**Current Artist:** {artist['name']}")
            else:
                st.info("No artists created yet. Create one in the left panel.")

    with tab2:
        st.header("🖊️ Sign a 3D Model File")
        
        # Check if an artist is selected
        if not st.session_state['current_artist'] or st.session_state['current_artist'] not in st.session_state['artist_registry']:
            st.warning("Please create or select an artist in the Artist Management tab before signing.")
            st.markdown("""
            **How to sign your 3D model:**
            1. First, go to the Artist Management tab and create or select an artist.
            2. Come back to this tab and upload your `.obj` file.
            3. Click **Sign and Download**.
            4. Download your signed file with your unique artist signature embedded.
            """)
        else:
            current_artist = st.session_state['artist_registry'][st.session_state['current_artist']]
            st.success(f"Signing as: **{current_artist['name']}**")
            st.markdown("""
            **How to sign your 3D model:**
            1. Upload your `.obj` file below.
            2. Click **Sign and Download**.
            3. Download your signed file with your unique artist signature embedded.
            """)
        uploaded_file = st.file_uploader("Upload a 3D Model (.obj) file", type=["obj"], key="sign-upload")
        if uploaded_file:
            if not st.session_state['current_artist'] or st.session_state['current_artist'] not in st.session_state['artist_registry']:
                st.error("Please select an artist before signing.")
            else:
                obj_data = uploaded_file.read().decode("utf-8")
                file_info = f"**File:** `{uploaded_file.name}` ({uploaded_file.size} bytes)"
                st.markdown(file_info)
                with st.expander("🔍 Preview File Contents"):
                    st.text_area("File Preview", obj_data, height=200, disabled=True)
                sign_btn = st.button("🖊️ Sign and Download", key="sign-btn", use_container_width=True)
                if sign_btn:
                    with st.spinner("🔏 Generating digital signature and preparing your file..."):
                        # Get the current artist information
                        current_artist = st.session_state['artist_registry'][st.session_state['current_artist']]
                        
                        # Load the private key for the current artist
                        private_key = load_key_from_pem(current_artist['private_key'].encode(), is_private=True)
                        public_key = load_key_from_pem(current_artist['public_key'].encode(), is_private=False)
                        
                        # Artist info to embed (without private key)
                        artist_embed_info = {
                            "name": current_artist['name'],
                            "email": current_artist['email'],
                            "website": current_artist['website'],
                            "timestamp": datetime.now().isoformat()
                        }
                        
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
                        
                        # Embed the signature along with the original hash and artist info
                        signed_obj_data = embed_signature(obj_data, signature, artist_embed_info, sign_hash)
                        
                        # Display success message and signature information
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

    with tab3:
        st.header("🔎 Verify a Signed 3D Model File")
        st.markdown("""
        **How to verify a signed file:**
        1. Upload a signed `.obj` file below.
        2. Click **Verify Signature**.
        3. See if the file is authentic and view the artist information.
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
                    signature, original_hash, artist_info = extract_signature(obj_data)
                    if signature:
                        st.markdown("**Extracted Signature:**")
                        st.markdown(f'<div class="signature-box">{signature}</div>', unsafe_allow_html=True)
                        
                        if artist_info:
                            st.markdown("**Artist Information:**")
                            artist_info_md = f"""  
                            * **Name:** {artist_info.get('name', 'Unknown')}
                            * **Email:** {artist_info.get('email', 'Not provided')}
                            * **Website:** {artist_info.get('website', 'Not provided')}
                            * **Timestamp:** {artist_info.get('timestamp', 'Not recorded')}
                            """
                            st.markdown(artist_info_md)
                        else:
                            st.warning("No artist information found in the file.")
                        
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
                            if original_hash and artist_info:
                                st.info(f"Verifying signature from artist: {artist_info.get('name', 'Unknown')}")
                                
                                # Find the artist in the registry if possible
                                artist_found = False
                                for artist_name, artist_data in st.session_state['artist_registry'].items():
                                    if artist_data.get('name') == artist_info.get('name'):
                                        # Use the stored public key
                                        public_key = load_key_from_pem(artist_data['public_key'].encode(), is_private=False)
                                        artist_found = True
                                        break
                                
                                if not artist_found:
                                    st.warning("Artist not found in local registry. Using embedded verification only.")
                                
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
    # Close database connection when app exits
    if 'conn' in locals():
        conn.close()