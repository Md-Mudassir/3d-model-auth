from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import struct
import numpy as np
import re
import json
import base64
from datetime import datetime

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

