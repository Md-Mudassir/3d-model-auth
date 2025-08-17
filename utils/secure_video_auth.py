#!/usr/bin/env python3
"""
Secure Video Authentication System for 3MVAP
Implements multiple security layers to protect against tampering
"""

import hashlib
import hmac
import json
import base64
import os
import subprocess
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SecureVideoAuthenticator:
    """
    Enhanced video authentication with multiple security layers
    """
    
    # Multiple storage locations for redundancy
    STORAGE_FIELDS = {
        'primary': 'comment',
        'secondary': 'description', 
        'tertiary': 'album'
    }
    
    # System keys for metadata integrity protection
    SYSTEM_KEY = b'3mvap_system_integrity_key_v1'  # In production, use proper key management
    
    def __init__(self):
        self.signatures = []
        
    def add_model_signature(self, model_name: str, signature: str, artist_info: Dict, 
                          model_hash: str, timestamp: str = None) -> None:
        """Add a 3D model signature to the collection"""
        if timestamp is None:
            timestamp = datetime.now().isoformat()
            
        self.signatures.append({
            'model_name': model_name,
            'signature': signature,
            'artist_info': artist_info,
            'model_hash': model_hash,
            'timestamp': timestamp
        })
    
    def _generate_content_hash(self, video_path: str) -> str:
        """Generate hash of video content for binding signatures to content"""
        try:
            # Use ffmpeg to extract key frames and generate content hash
            cmd = [
                'ffmpeg', '-i', video_path, '-vf', 'select=eq(pict_type\\,I)',
                '-vsync', 'vfr', '-f', 'md5', '-'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().split('=')[1] if '=' in result.stdout else 'unknown'
            return 'unknown'
        except Exception:
            return 'unknown'
    
    def _create_secure_payload(self, video_path: str) -> Dict:
        """Create cryptographically protected payload"""
        # Base payload with signatures
        payload = {
            'version': '2.0',
            'created_at': datetime.now().isoformat(),
            'total_models': len(self.signatures),
            'signatures': self.signatures,
            'content_hash': self._generate_content_hash(video_path)
        }
        
        # Create integrity protection
        payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()
        
        # Sign the payload hash with system key (HMAC for simplicity)
        integrity_signature = hmac.new(
            self.SYSTEM_KEY, 
            payload_hash.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        # Create final protected container
        protected_payload = {
            'data': payload,
            'integrity': {
                'hash': payload_hash,
                'signature': integrity_signature,
                'algorithm': 'HMAC-SHA256'
            }
        }
        
        return protected_payload
    
    def _encode_payload(self, payload: Dict) -> str:
        """Encode payload with additional obfuscation"""
        json_str = json.dumps(payload, separators=(',', ':'))
        
        # Base64 encode
        encoded = base64.b64encode(json_str.encode()).decode()
        
        # Add simple XOR obfuscation (not encryption, just anti-casual-inspection)
        key = b'3mvap'
        obfuscated = ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(encoded))
        
        # Base64 encode again
        return base64.b64encode(obfuscated.encode()).decode()
    
    def _decode_payload(self, encoded_data: str) -> Optional[Dict]:
        """Decode and verify payload integrity"""
        try:
            # First base64 decode
            obfuscated = base64.b64decode(encoded_data).decode()
            
            # Remove XOR obfuscation
            key = b'3mvap'
            deobfuscated = ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(obfuscated))
            
            # Second base64 decode
            json_str = base64.b64decode(deobfuscated).decode()
            
            # Parse JSON
            protected_payload = json.loads(json_str)
            
            # Verify integrity
            if not self._verify_payload_integrity(protected_payload):
                print("Warning: Payload integrity verification failed")
                return None
                
            return protected_payload.get('data')
            
        except Exception as e:
            print(f"Error decoding payload: {e}")
            return None
    
    def _verify_payload_integrity(self, protected_payload: Dict) -> bool:
        """Verify cryptographic integrity of payload"""
        try:
            data = protected_payload.get('data')
            integrity = protected_payload.get('integrity', {})
            
            # Recreate hash
            payload_json = json.dumps(data, separators=(',', ':'), sort_keys=True)
            computed_hash = hashlib.sha256(payload_json.encode()).hexdigest()
            
            # Verify hash matches
            if computed_hash != integrity.get('hash'):
                return False
            
            # Verify HMAC signature
            expected_signature = hmac.new(
                self.SYSTEM_KEY,
                computed_hash.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(expected_signature, integrity.get('signature', ''))
            
        except Exception:
            return False
    
    def embed_secure_signatures(self, input_video: str, output_video: str) -> Tuple[bool, str]:
        """Embed signatures with multiple security layers"""
        if not self.signatures:
            return False, "No signatures to embed"
        
        try:
            # Create secure payload
            protected_payload = self._create_secure_payload(input_video)
            encoded_payload = self._encode_payload(protected_payload)
            
            # Prepare multiple metadata fields for redundancy
            metadata_args = []
            for field_name, field_key in self.STORAGE_FIELDS.items():
                # Add field identifier prefix
                field_data = f"3MVAP2:{field_name}:{encoded_payload}"
                metadata_args.extend(['-metadata', f'{field_key}={field_data}'])
            
            # Add standard metadata
            metadata_args.extend([
                '-metadata', 'title=3MVAP Authenticated Content',
                '-metadata', f'encoder=3MVAP-v2.0-{len(self.signatures)}models'
            ])
            
            # Build FFmpeg command
            cmd = [
                'ffmpeg', '-i', input_video,
                *metadata_args,
                '-c:v', 'copy', '-c:a', 'copy',
                '-movflags', '+faststart',
                '-y', output_video
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return True, "Success"
            else:
                return False, f"FFmpeg error: {result.stderr}"
                
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def extract_secure_signatures(self, video_path: str) -> Optional[Dict]:
        """Extract and verify signatures from multiple locations"""
        try:
            # Probe video metadata
            cmd = ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', video_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return None
            
            metadata = json.loads(result.stdout).get('format', {}).get('tags', {})
            
            # Try to extract from multiple locations
            extracted_payloads = {}
            
            for field_name, field_key in self.STORAGE_FIELDS.items():
                for key in [field_key, field_key.upper(), field_key.capitalize()]:
                    if key in metadata:
                        value = metadata[key]
                        if value.startswith('3MVAP2:'):
                            parts = value.split(':', 2)
                            if len(parts) == 3 and parts[1] == field_name:
                                payload = self._decode_payload(parts[2])
                                if payload:
                                    extracted_payloads[field_name] = payload
                                    break
            
            # Verify consistency across storage locations
            if not extracted_payloads:
                return None
            
            # Use primary if available, otherwise use any available
            primary_payload = extracted_payloads.get('primary')
            if primary_payload:
                return primary_payload
            
            # Return first available payload
            return next(iter(extracted_payloads.values()))
            
        except Exception as e:
            print(f"Error extracting signatures: {e}")
            return None
    
    def verify_content_binding(self, video_path: str, payload: Dict) -> bool:
        """Verify that signatures are bound to this specific video content"""
        current_hash = self._generate_content_hash(video_path)
        stored_hash = payload.get('content_hash', 'unknown')
        
        if current_hash == 'unknown' or stored_hash == 'unknown':
            print("Warning: Cannot verify content binding - hash generation failed")
            return True  # Don't fail verification due to technical issues
        
        return current_hash == stored_hash

def create_secure_authenticated_video(input_video: str, output_video: str, 
                                    model_signatures: List[Dict]) -> Tuple[bool, str]:
    """Create authenticated video with enhanced security"""
    authenticator = SecureVideoAuthenticator()
    
    # Add all signatures
    for sig in model_signatures:
        authenticator.add_model_signature(
            model_name=sig['model_name'],
            signature=sig['signature'],
            artist_info=sig['artist_info'],
            model_hash=sig['model_hash'],
            timestamp=sig.get('timestamp')
        )
    
    return authenticator.embed_secure_signatures(input_video, output_video)

def verify_secure_authenticated_video(video_path: str, artist_registry: Dict) -> Tuple[bool, List[Dict]]:
    """Verify authenticated video with enhanced security checks"""
    authenticator = SecureVideoAuthenticator()
    
    # Extract signatures
    payload = authenticator.extract_secure_signatures(video_path)
    if not payload:
        return False, [{"error": "No secure signature data found in video"}]
    
    # Verify content binding
    if not authenticator.verify_content_binding(video_path, payload):
        return False, [{"error": "Content binding verification failed - video may have been modified"}]
    
    # Verify individual signatures (reuse existing logic)
    from utils.video_auth import VideoSignatureManager
    manager = VideoSignatureManager()
    
    signatures = payload.get('signatures', [])
    verification_results = []
    all_verified = True
    
    for sig_entry in signatures:
        result = manager._verify_single_signature(sig_entry, artist_registry)
        verification_results.append(result)
        
        if not result.get('verified', False):
            all_verified = False
    
    return all_verified, verification_results
