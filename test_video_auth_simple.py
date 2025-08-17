#!/usr/bin/env python3
"""
Simple test of video authentication with mock signature data
"""

import tempfile
import os
from utils.video_auth import VideoSignatureManager, create_authenticated_video
from utils.database import setup_database, load_artists_from_db

def test_video_auth_simple():
    """Test video authentication with mock signature data"""
    
    print("=== Simple Video Authentication Test ===\n")
    
    # Setup database and load artists
    conn = setup_database()
    artist_registry = load_artists_from_db(conn)
    print(f"Loaded {len(artist_registry)} artists from database")
    
    # Create mock signature data
    mock_signature = {
        'model_name': 'TestModel.obj',
        'signature': 'mock_signature_12345',
        'artist_info': {
            'name': 'Test Artist',
            'email': 'test@example.com'
        },
        'model_hash': 'mock_hash_67890',
        'timestamp': '2024-01-01T00:00:00Z'
    }
    
    # Create temporary files
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
        
        print("✅ Test video created")
        
        # Create authenticated video
        print("Creating authenticated video...")
        print(f"Debug: Mock signature data: {mock_signature}")
        success, error_msg = create_authenticated_video(input_path, output_path, [mock_signature])
        print(f"Debug: Creation result - success: {success}, error: {error_msg}")
        
        if success:
            print("✅ Authenticated video created successfully")
            
            # Test verification
            print("Testing verification...")
            video_manager = VideoSignatureManager()
            all_verified, results = video_manager.verify_video_signatures(output_path, artist_registry)
            
            print(f"Verification result - all_verified: {all_verified}")
            print(f"Results: {results}")
            
            if results and results[0].get('error') == "No signature data found in video":
                print("❌ No signature data found in video - metadata embedding failed")
            elif results and not results[0].get('error'):
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
    
    finally:
        # Cleanup
        for path in [input_path, output_path]:
            if os.path.exists(path):
                os.unlink(path)

if __name__ == "__main__":
    test_video_auth_simple()
