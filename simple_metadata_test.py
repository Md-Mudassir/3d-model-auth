#!/usr/bin/env python3
"""
Simple metadata test using ffmpeg command line
"""

import subprocess
import tempfile
import os

def test_ffmpeg_metadata():
    """Test FFmpeg metadata handling with command line"""
    
    # Create temporary files
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_input:
        input_path = temp_input.name
    
    with tempfile.NamedTemporaryFile(suffix="_auth.mp4", delete=False) as temp_output:
        output_path = temp_output.name
    
    try:
        # Create a minimal test video using command line
        print("Creating test video...")
        cmd = [
            'ffmpeg', '-f', 'lavfi', '-i', 'color=black:size=320x240:duration=1',
            '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-y', input_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Failed to create test video: {result.stderr}")
            return
        
        # Add metadata using command line
        print("Adding metadata...")
        test_data = "test_signature_12345"
        cmd = [
            'ffmpeg', '-i', input_path,
            '-metadata', f'comment={test_data}',
            '-metadata', 'title=Test Video',
            '-c:v', 'copy', '-c:a', 'copy', '-map_metadata', '0',
            '-movflags', '+faststart', '-y', output_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Failed to add metadata: {result.stderr}")
            return
        
        # Read metadata back
        print("Reading metadata...")
        cmd = ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', output_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)
            tags = data.get('format', {}).get('tags', {})
            
            print(f"All metadata tags: {list(tags.keys())}")
            for key, value in tags.items():
                print(f"  {key}: {value}")
            
            # Check for our signature in comment field
            if 'comment' in tags:
                print(f"✅ Found signature in comment: {tags['comment']}")
            else:
                print("❌ Signature not found")
        else:
            print(f"Failed to read metadata: {result.stderr}")
    
    finally:
        # Cleanup
        for path in [input_path, output_path]:
            if os.path.exists(path):
                os.unlink(path)

if __name__ == "__main__":
    test_ffmpeg_metadata()
