#!/usr/bin/env python3
"""
Debug script to test video authentication embedding and extraction
"""

import os
import tempfile
from utils.video_auth import VideoSignatureManager
from utils.database import setup_database, load_artists_from_db

def debug_video_authentication():
    """Debug the video authentication process step by step"""
    
    print("=== 3MVAP Video Authentication Debug ===\n")
    
    # Initialize components
    video_manager = VideoSignatureManager()
    
    # Setup database and load artists
    conn = setup_database()
    artist_registry = load_artists_from_db(conn)
    
    print(f"1. FFmpeg available: {video_manager.ffmpeg_available}")
    print(f"2. Artist registry loaded: {len(artist_registry)} artists")
    print(f"3. Signature key: {video_manager.SIGNATURE_KEY}\n")
    
    # Test with a sample video (you'll need to provide the path)
    test_video_path = input("Enter path to test video file: ").strip()
    
    if not os.path.exists(test_video_path):
        print(f"❌ Video file not found: {test_video_path}")
        return
    
    print(f"4. Testing video: {test_video_path}")
    
    # Test signature extraction first
    print("\n=== Testing Signature Extraction ===")
    try:
        signatures = video_manager.extract_signatures_from_video(test_video_path)
        if signatures:
            print(f"✅ Found signatures: {signatures}")
        else:
            print("❌ No signatures found")
            
            # Let's probe the video metadata manually
            print("\n=== Manual Metadata Probe ===")
            import ffmpeg
            try:
                probe = ffmpeg.probe(test_video_path)
                metadata = probe.get('format', {}).get('tags', {})
                print(f"All metadata keys: {list(metadata.keys())}")
                
                # Look for any keys containing our signature key
                signature_key = video_manager.SIGNATURE_KEY
                for key, value in metadata.items():
                    if signature_key.lower() in key.lower() or '3mvap' in key.lower():
                        print(f"Found potential signature key: {key} = {value[:100]}...")
                        
            except Exception as e:
                print(f"❌ FFmpeg probe failed: {e}")
                
    except Exception as e:
        print(f"❌ Signature extraction failed: {e}")
    
    # Test verification
    print("\n=== Testing Verification ===")
    try:
        all_verified, results = video_manager.verify_video_signatures(test_video_path, artist_registry)
        print(f"All verified: {all_verified}")
        print(f"Results: {results}")
    except Exception as e:
        print(f"❌ Verification failed: {e}")

if __name__ == "__main__":
    debug_video_authentication()
