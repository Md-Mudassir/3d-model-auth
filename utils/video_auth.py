import json
import base64
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import hashlib
import subprocess
import shutil
import os

try:
    from moviepy.editor import VideoFileClip
    import ffmpeg
    FFMPEG_AVAILABLE = True
except ImportError:
    FFMPEG_AVAILABLE = False
    print("Warning: moviepy and ffmpeg-python not installed. Install with: pip install moviepy ffmpeg-python")

from .crypto import verify_signature, load_key_from_pem

def check_ffmpeg_installation():
    """Check if FFmpeg is installed and accessible"""
    try:
        # Check if ffmpeg command is available
        result = subprocess.run(['ffmpeg', '-version'], 
                              capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        return False

class VideoSignatureManager:
    """
    Manages embedding and verification of 3D model signatures in video metadata.
    Uses custom metadata fields to store signature information.
    """
    
    SIGNATURE_KEY = "comment"  # Use comment field for better MP4 compatibility
    VERSION_KEY = "signature_version"
    CURRENT_VERSION = "1.0"
    
    def __init__(self):
        self.signatures = []
        self.ffmpeg_available = check_ffmpeg_installation()
        
    def add_model_signature(self, model_name: str, signature: str, artist_info: Dict, 
                          model_hash: str, timestamp: str = None) -> None:
        """
        Add a 3D model signature to the collection.
        
        Args:
            model_name: Name/identifier of the 3D model
            signature: Digital signature of the model
            artist_info: Artist information (name, email, etc.)
            model_hash: Hash of the original model file
            timestamp: When the model was signed
        """
        if timestamp is None:
            timestamp = datetime.now().isoformat()
            
        signature_entry = {
            "model_name": model_name,
            "signature": signature,
            "artist_info": artist_info,
            "model_hash": model_hash,
            "timestamp": timestamp,
            "verified": False  # Will be set during verification
        }
        
        self.signatures.append(signature_entry)
    
    def generate_metadata_payload(self) -> str:
        """
        Generate the metadata payload to embed in video.
        
        Returns:
            Base64 encoded JSON string containing all signatures
        """
        payload = {
            self.VERSION_KEY: self.CURRENT_VERSION,
            "created_at": datetime.now().isoformat(),
            "total_models": len(self.signatures),
            "signatures": self.signatures
        }
        
        json_str = json.dumps(payload, separators=(',', ':'))
        return base64.b64encode(json_str.encode()).decode()
    
    def embed_signatures_in_video(self, input_video_path: str, output_video_path: str, 
                                metadata_payload: str) -> Tuple[bool, str]:
        """
        Embed signature metadata into video file using ffmpeg.
        
        Args:
            input_video_path: Path to input video file
            output_video_path: Path to output video with embedded metadata
            metadata_payload: Base64 encoded signature data
            
        Returns:
            Tuple of (success, error_message)
        """
        # Check if FFmpeg is available
        if not self.ffmpeg_available:
            return False, "FFmpeg is not installed or not accessible. Please install FFmpeg first."
        
        if not FFMPEG_AVAILABLE:
            return False, "ffmpeg-python library not installed. Run: pip install ffmpeg-python"
        
        # Check if input file exists
        if not os.path.exists(input_video_path):
            return False, f"Input video file not found: {input_video_path}"
        
        try:
            # Use ffmpeg to add custom metadata - try subprocess method for better compatibility
            import subprocess
            
            cmd = [
                'ffmpeg', '-i', input_video_path,
                '-metadata', f'comment={metadata_payload}',
                '-metadata', 'title=Authenticated 3D Content',
                '-c:v', 'copy', '-c:a', 'copy',  # Copy video and audio streams
                '-movflags', '+faststart',  # Optimize for web playback
                '-y', output_video_path  # Overwrite output
            ]
            
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return False, f"FFmpeg command failed: {result.stderr}"
            
            # Verify output file was created
            if os.path.exists(output_video_path):
                return True, "Success"
            else:
                return False, "Output file was not created"
                
        except Exception as e:
            return False, f"Error during video processing: {str(e)}"
    
    def embed_signatures_fallback(self, input_video_path: str, output_video_path: str, 
                                 metadata_payload: str) -> Tuple[bool, str]:
        """
        Fallback method using subprocess to call ffmpeg directly.
        """
        if not self.ffmpeg_available:
            return False, "FFmpeg is not installed. Please install FFmpeg first."
        
        try:
            cmd = [
                'ffmpeg', '-i', input_video_path,
                '-metadata', f'comment={metadata_payload}',
                '-metadata', 'title=Authenticated 3D Content',
                '-c', 'copy',  # Don't re-encode
                '-y',  # Overwrite output file
                output_video_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return True, "Success"
            else:
                return False, f"FFmpeg error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, "FFmpeg operation timed out"
        except Exception as e:
            return False, f"Subprocess error: {str(e)}"
    
    def extract_signatures_from_video(self, video_path: str) -> Optional[Dict]:
        """
        Extract 3D model signatures from video metadata.
        
        Args:
            video_path: Path to video file
            
        Returns:
            Dictionary containing signature data or None if not found
        """
        if not self.ffmpeg_available:
            print("Warning: FFmpeg not available, cannot extract metadata")
            return None
            
        try:
            # Use ffmpeg to probe metadata - try subprocess method first
            import subprocess
            import json
            
            cmd = ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', video_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"FFprobe failed: {result.stderr}")
                return None
            
            probe_data = json.loads(result.stdout)
            
            # Look for our signature metadata in format metadata
            metadata = probe_data.get('format', {}).get('tags', {})
            
            # Try different possible key formats (ffmpeg can be inconsistent)
            signature_data = None
            possible_keys = [
                self.SIGNATURE_KEY,
                self.SIGNATURE_KEY.upper(), 
                self.SIGNATURE_KEY.lower(),
                "COMMENT",
                "Comment"
            ]
            
            for key in possible_keys:
                if key in metadata:
                    signature_data = metadata[key]
                    break
            
            if not signature_data:
                # Debug: print all available metadata keys
                print(f"Debug: No signature found. Available metadata keys: {list(metadata.keys())}")
                for key, value in metadata.items():
                    print(f"  {key}: {value[:100]}...")
                return None
            
            
            # Decode base64 and parse JSON
            try:
                decoded_data = base64.b64decode(signature_data).decode()
                return json.loads(decoded_data)
            except Exception as e:
                print(f"Error decoding signature data: {e}")
                return None
                
        except Exception as e:
            print(f"Error extracting metadata: {e}")
            return None
    
    def verify_video_signatures(self, video_path: str, artist_registry: Dict) -> Tuple[bool, List[Dict]]:
        """
        Verify all 3D model signatures in a video file.
        
        Args:
            video_path: Path to video file
            artist_registry: Dictionary of artist information with public keys
            
        Returns:
            Tuple of (all_verified, verification_results)
        """
        signature_data = self.extract_signatures_from_video(video_path)
        
        if not signature_data:
            return False, [{"error": "No signature data found in video"}]
        
        signatures = signature_data.get('signatures', [])
        verification_results = []
        all_verified = True
        
        for sig_entry in signatures:
            result = self._verify_single_signature(sig_entry, artist_registry)
            verification_results.append(result)
            
            if not result.get('verified', False):
                all_verified = False
        
        return all_verified, verification_results
    
    def _verify_single_signature(self, sig_entry: Dict, artist_registry: Dict) -> Dict:
        """
        Verify a single 3D model signature.
        
        Args:
            sig_entry: Signature entry from metadata
            artist_registry: Artist registry with public keys
            
        Returns:
            Verification result dictionary
        """
        try:
            model_name = sig_entry.get('model_name', 'Unknown')
            signature = sig_entry.get('signature', '')
            artist_info = sig_entry.get('artist_info', {})
            model_hash = sig_entry.get('model_hash', '')
            
            artist_name = artist_info.get('name', 'Unknown')
            
            # Find artist in registry
            artist_data = None
            for name, data in artist_registry.items():
                if data.get('name') == artist_name:
                    artist_data = data
                    break
            
            if not artist_data:
                return {
                    'model_name': model_name,
                    'artist_name': artist_name,
                    'verified': False,
                    'error': f'Artist "{artist_name}" not found in registry'
                }
            
            # Load public key and verify signature
            public_key = load_key_from_pem(artist_data['public_key'].encode(), is_private=False)
            
            # Verify signature against model hash
            hash_bytes = bytes.fromhex(model_hash)
            
            try:
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.primitives import hashes
                
                public_key.verify(
                    bytes.fromhex(signature),
                    hash_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                return {
                    'model_name': model_name,
                    'artist_name': artist_name,
                    'artist_info': artist_info,
                    'verified': True,
                    'timestamp': sig_entry.get('timestamp', 'Unknown')
                }
                
            except Exception as e:
                return {
                    'model_name': model_name,
                    'artist_name': artist_name,
                    'verified': False,
                    'error': f'Signature verification failed: {str(e)}'
                }
                
        except Exception as e:
            return {
                'model_name': sig_entry.get('model_name', 'Unknown'),
                'verified': False,
                'error': f'Verification error: {str(e)}'
            }

def create_authenticated_video(input_video: str, output_video: str, 
                             model_signatures: List[Dict]) -> Tuple[bool, str]:
    """
    Convenience function to create an authenticated video with 3D model signatures.
    
    Args:
        input_video: Path to input video
        output_video: Path to output authenticated video
        model_signatures: List of signature dictionaries
        
    Returns:
        Tuple of (success, error_message)
    """
    manager = VideoSignatureManager()
    
    # Add all model signatures
    for sig in model_signatures:
        manager.add_model_signature(
            model_name=sig['model_name'],
            signature=sig['signature'],
            artist_info=sig['artist_info'],
            model_hash=sig['model_hash'],
            timestamp=sig.get('timestamp')
        )
    
    # Generate metadata payload
    payload = manager.generate_metadata_payload()
    
    # Try primary method first
    success, error = manager.embed_signatures_in_video(input_video, output_video, payload)
    
    # If primary method fails, try fallback
    if not success:
        success, fallback_error = manager.embed_signatures_fallback(input_video, output_video, payload)
        if not success:
            return False, f"Primary: {error}. Fallback: {fallback_error}"
    
    return success, error if not success else "Success"

def verify_authenticated_video(video_path: str, artist_registry: Dict) -> Tuple[bool, List[Dict]]:
    """
    Convenience function to verify an authenticated video.
    
    Args:
        video_path: Path to video file
        artist_registry: Artist registry with public keys
        
    Returns:
        Tuple of (all_verified, verification_results)
    """
    manager = VideoSignatureManager()
    return manager.verify_video_signatures(video_path, artist_registry)
