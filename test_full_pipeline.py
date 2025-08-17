#!/usr/bin/env python3
"""
Test the full video authentication pipeline
"""

import tempfile
import os
from utils.video_auth import VideoSignatureManager, create_authenticated_video
from utils.database import setup_database, load_artists_from_db
from utils.crypto import extract_signature

def test_full_pipeline():
    """Test creating and verifying an authenticated video"""
    
    print("=== Testing Full Video Authentication Pipeline ===\n")
    
    # Setup database and load artists
    conn = setup_database()
    artist_registry = load_artists_from_db(conn)
    print(f"Loaded {len(artist_registry)} artists from database")
    
    # Create a simple test video
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_input:
        input_path = temp_input.name
    
    with tempfile.NamedTemporaryFile(suffix="_auth.mp4", delete=False) as temp_output:
        output_path = temp_output.name
    
    try:
        # Create test video
        print("Creating test video...")
        import subprocess
        cmd = [
            'ffmpeg', '-f', 'lavfi', '-i', 'color=black:size=320x240:duration=1',
            '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-y', input_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Failed to create test video: {result.stderr}")
            return
        
        # Load a test model signature
        model_path = "objects/12140_Skull_v3_L2.obj"
        if os.path.exists(model_path):
            print(f"Loading model signature from {model_path}")
            
            # Read the OBJ file and extract signature
            with open(model_path, 'r') as f:
                obj_data = f.read()
            
            try:
                signature_hex, original_hash, artist_info = extract_signature(obj_data)
                if signature_hex and artist_info:
                    signature_data = {
                        'model_name': os.path.basename(model_path),
                        'signature': signature_hex,
                        'artist_info': artist_info,
                        'model_hash': original_hash,
                        'timestamp': '2024-01-01T00:00:00Z'
                    }
                    print(f"✅ Found signature for model: {signature_data.get('model_name', 'Unknown')}")
                    
                    # Create authenticated video
                    print("Creating authenticated video...")
                    success, error_msg = create_authenticated_video(input_path, output_path, [signature_data])
                else:
                    print("❌ No signature found in model file")
                    return
            except Exception as e:
                print(f"❌ Error extracting signature: {e}")
                return
            
            if success:
                print("✅ Authenticated video created successfully")
                
                # Test verification
                print("Testing verification...")
                video_manager = VideoSignatureManager()
                all_verified, results = video_manager.verify_video_signatures(output_path, artist_registry)
                
                print(f"Verification result - all_verified: {all_verified}")
                print(f"Results: {results}")
                
                if results and not results[0].get('error'):
                    print("✅ Video authentication verification successful!")
                    for result in results:
                        print(f"  - Model: {result.get('model_name', 'Unknown')}")
                        print(f"  - Verified: {result.get('verified', False)}")
                else:
                    print("❌ Video authentication verification failed")
                    if results:
                        print(f"Error: {results[0].get('error', 'Unknown error')}")
            else:
                print(f"❌ Failed to create authenticated video: {error_msg}")
        else:
            print(f"❌ Model file not found: {model_path}")
    
    finally:
        # Cleanup
        for path in [input_path, output_path]:
            if os.path.exists(path):
                os.unlink(path)

if __name__ == "__main__":
    test_full_pipeline()
