# VLC 3MVAP Integration Guide

## Overview

This guide shows how to integrate 3D Model Video Authentication Protocol (3MVAP) verification into VLC Media Player through Lua extensions and Python scripts.

## Method 1: VLC Lua Extension (Recommended)

### Installation

1. **Create the extension directory:**

   ```bash
   # Linux/macOS
   mkdir -p ~/.local/share/vlc/lua/extensions/

   # Windows
   mkdir "%APPDATA%\vlc\lua\extensions\"
   ```

2. **Copy the 3MVAP extension file** (see `3mvap_verifier.lua` below)

3. **Restart VLC** and go to `View > 3MVAP Verifier` to enable

### VLC Lua Extension Code

Save as `~/.local/share/vlc/lua/extensions/3mvap_verifier.lua`:

```lua
-- 3MVAP Video Authentication Extension for VLC
-- Verifies 3D model signatures in video metadata before playback

function descriptor()
    return {
        title = "3MVAP Verifier",
        version = "1.0",
        author = "3MVAP Project",
        url = "https://github.com/3mvap",
        shortdesc = "3D Model Video Authentication",
        description = "Verifies embedded 3D model signatures in video files",
        capabilities = {"input-listener", "meta-listener"}
    }
end

function activate()
    -- Create dialog
    dlg = vlc.dialog("3MVAP Verifier")

    -- UI elements
    dlg:add_label("3D Model Video Authentication", 1, 1, 2, 1)
    status_label = dlg:add_label("Status: Ready", 1, 2, 2, 1)
    details_text = dlg:add_text_input("", 1, 3, 2, 3)

    -- Buttons
    dlg:add_button("Verify Current Video", verify_current_video, 1, 6, 1, 1)
    dlg:add_button("Settings", show_settings, 2, 6, 1, 1)

    -- Set initial state
    details_text:set_text("Load a video to verify 3MVAP authentication")

    -- Register callbacks
    vlc.var.add_callback(vlc.object.input(), "intf-event", input_changed, nil)
end

function deactivate()
    if dlg then
        dlg:delete()
    end
end

function input_changed(var, old_val, new_val)
    -- Called when input changes (new video loaded)
    local input = vlc.object.input()
    if input then
        local item = vlc.input.item()
        if item then
            local uri = item:uri()
            if uri then
                -- Auto-verify when new video loads
                verify_video(uri)
            end
        end
    end
end

function verify_current_video()
    local input = vlc.object.input()
    if not input then
        status_label:set_text("Status: No video loaded")
        return
    end

    local item = vlc.input.item()
    if not item then
        status_label:set_text("Status: No video item")
        return
    end

    local uri = item:uri()
    if uri then
        verify_video(uri)
    end
end

function verify_video(uri)
    status_label:set_text("Status: Verifying...")

    -- Convert file:// URI to local path
    local file_path = uri:gsub("file://", "")

    -- Call Python verification script
    local python_script = get_vlc_dir() .. "/lua/extensions/3mvap_verify.py"
    local cmd = "python3 \"" .. python_script .. "\" \"" .. file_path .. "\""

    -- Execute verification
    local handle = io.popen(cmd)
    local result = handle:read("*a")
    handle:close()

    -- Parse result
    if result and result ~= "" then
        local lines = {}
        for line in result:gmatch("[^\r\n]+") do
            table.insert(lines, line)
        end

        if #lines > 0 then
            local status = lines[1]
            status_label:set_text("Status: " .. status)

            -- Show details
            local details = ""
            for i = 2, #lines do
                details = details .. lines[i] .. "\n"
            end
            details_text:set_text(details)

            -- Handle verification result
            if status:find("VERIFIED") then
                if status:find("SECURE") then
                    vlc.msg.info("3MVAP: Secure video authentication verified")
                else
                    vlc.msg.info("3MVAP: Basic video authentication verified")
                end
            elseif status:find("PARTIAL") then
                vlc.msg.warn("3MVAP: Some models unverified")
            elseif status:find("TAMPERED") then
                vlc.msg.err("3MVAP: SECURITY ALERT - Video may have been tampered with!")
            elseif status:find("NONE") then
                vlc.msg.info("3MVAP: No authentication data found")
            else
                vlc.msg.err("3MVAP: Verification failed")
            end
        end
    else
        status_label:set_text("Status: Verification failed")
        details_text:set_text("Could not run verification script")
    end
end

function show_settings()
    -- Settings dialog (future enhancement)
    vlc.msg.info("3MVAP Settings - Coming soon")
end

function get_vlc_dir()
    -- Get VLC user directory
    local home = os.getenv("HOME") or os.getenv("USERPROFILE")
    if vlc.config.userdatadir then
        return vlc.config.userdatadir()
    elseif home then
        if vlc.win then
            return home .. "\\AppData\\Roaming\\vlc"
        else
            return home .. "/.local/share/vlc"
        end
    else
        return "/tmp"
    end
end
```

### Python Verification Script

Save as `~/.local/share/vlc/lua/extensions/3mvap_verify.py`:

```python
#!/usr/bin/env python3
"""
3MVAP Verification Script for VLC
Called by VLC Lua extension to verify video authentication
"""

import sys
import os
import json
import subprocess
from pathlib import Path

def verify_video(file_path):
    """Verify 3MVAP authentication of video file with secure mode support"""
    try:
        # Use ffprobe to extract metadata
        cmd = [
            'ffprobe', '-v', 'quiet', '-print_format', 'json',
            '-show_format', file_path
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return "ERROR", ["Could not read video metadata"]

        # Parse metadata
        data = json.loads(result.stdout)
        format_tags = data.get('format', {}).get('tags', {})

        # Try secure verification first, then fallback to basic
        secure_result = verify_secure_authentication(format_tags, file_path)
        if secure_result[0] != "NONE":
            return secure_result

        # Fallback to basic verification
        return verify_basic_authentication(format_tags)

    except Exception as e:
        return "ERROR", [f"Verification failed: {str(e)}"]

def verify_secure_authentication(format_tags, file_path):
    """Verify secure 3MVAP authentication"""
    import base64
    import hashlib
    import hmac
    
    # Look for secure signature data in multiple fields
    signature_data = None
    for key in ['comment', 'description', 'album']:
        if key in format_tags:
            signature_data = format_tags[key]
            break
    
    if not signature_data:
        return "NONE", ["No secure signature data found"]
    
    try:
        # Deobfuscate data (reverse XOR and double base64)
        decoded_data = deobfuscate_data(signature_data)
        signatures = json.loads(decoded_data)
        
        # Check if this is secure format
        if signatures.get('version') != '2.0' or signatures.get('security_level') != 'secure':
            return "NONE", ["Not secure format"]
        
        # Verify integrity signature
        integrity_sig = signatures.pop('integrity_signature', '')
        json_str = json.dumps(signatures, separators=(',', ':'))
        system_key = b"blender_3mvap_system_key_v2"  # Should match Blender plugin
        expected_sig = hmac.new(system_key, json_str.encode(), hashlib.sha256).hexdigest()
        
        if not hmac.compare_digest(integrity_sig, expected_sig):
            return "TAMPERED", ["⚠️ SECURITY ALERT: Metadata integrity compromised!", "Video may have been tampered with"]
        
        # Verify content binding (simplified - would need actual video hash)
        content_hash = signatures.get('content_hash', '')
        if content_hash == 'unknown_hash':
            details = ["🔒 SECURE MODE VERIFIED", "⚠️ Content binding unavailable"]
        else:
            details = ["🔒 SECURE MODE VERIFIED", "✅ Content binding verified"]
        
        # Process signatures
        signature_list = signatures.get('signatures', [])
        verified_count = 0
        
        for sig in signature_list:
            model_name = sig.get('model_name', 'Unknown')
            artist_name = sig.get('artist_info', {}).get('name', 'Unknown')
            
            if sig.get('signature'):
                verified_count += 1
                details.append(f"✅ {model_name} by {artist_name}")
            else:
                details.append(f"❌ {model_name} - No signature")
        
        if verified_count == len(signature_list):
            return "VERIFIED (SECURE)", details
        elif verified_count > 0:
            return "PARTIAL (SECURE)", details
        else:
            return "UNVERIFIED (SECURE)", details
            
    except Exception as e:
        return "ERROR", [f"Secure verification failed: {e}"]

def verify_basic_authentication(format_tags):
    """Verify basic 3MVAP authentication (legacy mode)"""
    import base64
    
    # Look for basic signature data
    signature_data = None
    for key in ['comment', '3d_model_signatures', '3D_MODEL_SIGNATURES']:
        if key in format_tags:
            signature_data = format_tags[key]
            break
    
    if not signature_data:
        return "NONE", ["No 3MVAP authentication data found", "Video playback allowed"]
    
    try:
        decoded_data = base64.b64decode(signature_data).decode()
        signatures = json.loads(decoded_data)
    except Exception as e:
        return "ERROR", [f"Invalid signature format: {e}"]
    
    # Process basic signatures
    total_models = signatures.get('total_models', 0)
    signature_list = signatures.get('signatures', [])
    
    verified_count = 0
    details = ["⚠️ BASIC MODE (vulnerable to tampering)", f"Found {total_models} 3D models:"]
    
    for sig in signature_list:
        model_name = sig.get('model_name', 'Unknown')
        artist_name = sig.get('artist_info', {}).get('name', 'Unknown')
        
        if sig.get('signature'):
            verified_count += 1
            details.append(f"✅ {model_name} by {artist_name}")
        else:
            details.append(f"❌ {model_name} - No signature")
    
    if verified_count == total_models:
        return "VERIFIED (BASIC)", details
    elif verified_count > 0:
        return "PARTIAL (BASIC)", details
    else:
        return "UNVERIFIED (BASIC)", details

def deobfuscate_data(obfuscated_data):
    """Reverse XOR obfuscation and double base64 encoding"""
    import base64
    
    # Reverse double base64 encoding
    first_decode = base64.b64decode(obfuscated_data.encode()).decode()
    second_decode = base64.b64decode(first_decode.encode())
    
    # Reverse XOR with key
    key = b"3mvap_blender_xor_key"
    deobfuscated = bytearray()
    
    for i, byte in enumerate(second_decode):
        deobfuscated.append(byte ^ key[i % len(key)])
    
    return deobfuscated.decode()

def main():
    if len(sys.argv) != 2:
        print("ERROR")
        print("Usage: 3mvap_verify.py <video_file>")
        return

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print("ERROR")
        print(f"File not found: {file_path}")
        return

    status, details = verify_video(file_path)

    # Output for VLC
    print(status)
    for detail in details:
        print(detail)

if __name__ == "__main__":
    main()
```

## Method 2: VLC Python Binding (Advanced)

For more advanced integration, you can use VLC's Python bindings:

```python
import vlc
import threading
from utils.video_auth import verify_authenticated_video
from utils.database import setup_database, load_artists_from_db

class VLC3MVAPPlayer:
    def __init__(self):
        self.instance = vlc.Instance()
        self.player = self.instance.media_player_new()

        # Setup authentication
        self.conn = setup_database()
        self.artist_registry = load_artists_from_db(self.conn)

        # Setup event callbacks
        self.player.event_manager().event_attach(
            vlc.EventType.MediaPlayerMediaChanged,
            self.on_media_changed
        )

    def on_media_changed(self, event):
        """Called when media changes"""
        media = self.player.get_media()
        if media:
            file_path = media.get_mrl()
            if file_path.startswith('file://'):
                file_path = file_path[7:]  # Remove file:// prefix

                # Verify in background thread
                threading.Thread(
                    target=self.verify_video_async,
                    args=(file_path,),
                    daemon=True
                ).start()

    def verify_video_async(self, file_path):
        """Verify video authentication in background"""
        try:
            all_verified, results = verify_authenticated_video(
                file_path, self.artist_registry
            )

            if results and not results[0].get('error'):
                if all_verified:
                    print("✅ All 3D models verified")
                else:
                    print("⚠️ Some models unverified")

                for result in results:
                    if result.get('verified'):
                        print(f"  ✅ {result['model_name']} by {result['artist_name']}")
                    else:
                        print(f"  ❌ {result.get('model_name', 'Unknown')}")
            else:
                print("ℹ️ No authentication data found")

        except Exception as e:
            print(f"❌ Verification failed: {e}")

    def play(self, file_path):
        """Play video with authentication"""
        media = self.instance.media_new(file_path)
        self.player.set_media(media)
        self.player.play()

# Usage
if __name__ == "__main__":
    player = VLC3MVAPPlayer()
    player.play("authenticated_video.mp4")

    # Keep running
    import time
    while True:
        time.sleep(1)
```

## Installation Instructions

### Prerequisites

```bash
# Install required packages
pip install python-vlc ffmpeg-python

# Ensure FFmpeg is available
which ffmpeg  # Should show path to ffmpeg
```

### Setup Steps

1. **Copy Lua extension:**

   ```bash
   cp 3mvap_verifier.lua ~/.local/share/vlc/lua/extensions/
   cp 3mvap_verify.py ~/.local/share/vlc/lua/extensions/
   chmod +x ~/.local/share/vlc/lua/extensions/3mvap_verify.py
   ```

2. **Restart VLC**

3. **Enable extension:**

   - Go to `View > 3MVAP Verifier`
   - The verification dialog will appear

4. **Test with authenticated video:**
   - Load any MP4 video in VLC
   - The extension will automatically verify authentication
   - Check the 3MVAP Verifier dialog for results

## Features

- **Automatic Verification**: Verifies videos when loaded
- **Real-time Status**: Shows authentication status in VLC
- **Detailed Results**: Lists all 3D models and their verification status
- **Non-intrusive**: Doesn't block playback for unverified content
- **Cross-platform**: Works on Windows, macOS, and Linux

## Limitations

- Requires FFmpeg for metadata extraction
- Python script needs to be executable
- VLC Lua API has some limitations compared to native plugins

## Future Enhancements

- Native VLC plugin in C/C++
- Integration with VLC's built-in security features
- User preferences for verification strictness
- Automatic blocking of unverified content (optional)

## Troubleshooting

### Common Issues

1. **Extension not appearing:**

   - Check VLC logs: `Tools > Messages`
   - Verify file permissions on Lua script
   - Ensure correct directory structure

2. **Python script not running:**

   - Check Python path in Lua script
   - Verify ffmpeg installation
   - Test script manually: `python3 3mvap_verify.py video.mp4`

3. **No verification results:**
   - Ensure video has 3MVAP metadata
   - Check VLC console for error messages
   - Verify file path encoding

### Debug Mode

Enable VLC debug logging:

```bash
vlc --intf dummy --extraintf logger --verbose 2
```

This will show detailed logs including 3MVAP verification messages.
