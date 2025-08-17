#!/usr/bin/env python3
"""
Simple test to check metadata embedding and extraction
"""

import tempfile
import os
import ffmpeg

def test_metadata_roundtrip():
    """Test embedding and extracting metadata"""
    
    # Create a simple test video (1 second black video)
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_input:
        input_path = temp_input.name
    
    with tempfile.NamedTemporaryFile(suffix="_auth.mp4", delete=False) as temp_output:
        output_path = temp_output.name
    
    try:
        # Create a simple test video
        print("Creating test video...")
        (
            ffmpeg
            .input('color=black:size=320x240:duration=1', f='lavfi')
            .output(input_path, vcodec='libx264', pix_fmt='yuv420p')
            .overwrite_output()
            .run(quiet=True)
        )
        
        # Test metadata embedding
        test_metadata = "test_signature_data_12345"
        print(f"Embedding metadata: {test_metadata}")
        
        (
            ffmpeg
            .input(input_path)
            .output(
                output_path,
                **{
                    'metadata:3mvap_signatures': test_metadata,
                    'metadata:title': 'Test Video'
                },
                vcodec='copy',
                acodec='copy'
            )
            .overwrite_output()
            .run(quiet=True)
        )
        
        # Test metadata extraction
        print("Extracting metadata...")
        probe = ffmpeg.probe(output_path)
        metadata = probe.get('format', {}).get('tags', {})
        
        print(f"All metadata keys: {list(metadata.keys())}")
        for key, value in metadata.items():
            print(f"  {key}: {value}")
        
        # Look for our signature
        found_signature = None
        for key in ['3mvap_signatures', '3MVAP_SIGNATURES', 'MVAP_SIGNATURES']:
            if key in metadata:
                found_signature = metadata[key]
                print(f"✅ Found signature under key '{key}': {found_signature}")
                break
        
        if not found_signature:
            print("❌ Signature not found in metadata")
        
    finally:
        # Cleanup
        for path in [input_path, output_path]:
            if os.path.exists(path):
                os.unlink(path)

if __name__ == "__main__":
    test_metadata_roundtrip()
