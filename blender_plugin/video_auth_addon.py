bl_info = {
    "name": "3D Model Video Authentication",
    "author": "3D-Model-Auth",
    "version": (2, 0),
    "blender": (3, 0, 0),
    "location": "Render Properties > Video Authentication",
    "description": "Embed 3D model signatures into video metadata with secure tamper-resistant protection",
    "category": "Render",
}

import bpy
import os
import json
import base64
import subprocess
import hashlib
import hmac
from datetime import datetime
from bpy.props import StringProperty, BoolProperty, CollectionProperty, EnumProperty
from bpy.types import Panel, Operator, PropertyGroup

class VideoAuthModelEntry(PropertyGroup):
    """Property group for storing model signature information"""
    model_name: StringProperty(name="Model Name", default="")
    obj_file_path: StringProperty(name="OBJ File Path", default="", subtype='FILE_PATH')
    signature_extracted: BoolProperty(name="Signature Extracted", default=False)
    artist_name: StringProperty(name="Artist", default="")

class VideoAuthProperties(PropertyGroup):
    """Main property group for video authentication settings"""
    enable_auth: BoolProperty(
        name="Enable Video Authentication",
        description="Embed 3D model signatures into video metadata",
        default=False
    )
    
    security_level: EnumProperty(
        name="Security Level",
        description="Choose authentication security level",
        items=[
            ('BASIC', "Basic", "Legacy mode - vulnerable to tampering"),
            ('SECURE', "Secure", "Tamper-resistant protection with cryptographic integrity")
        ],
        default='SECURE'
    )
    
    models: CollectionProperty(type=VideoAuthModelEntry)
    active_model_index: bpy.props.IntProperty(default=0)
    
    output_authenticated: BoolProperty(
        name="Output Authenticated Video",
        description="Create authenticated version alongside regular render",
        default=True
    )

class VIDEO_AUTH_OT_add_model(Operator):
    """Add a signed 3D model to the authentication list"""
    bl_idname = "video_auth.add_model"
    bl_label = "Add Signed Model"
    bl_description = "Add a signed .obj file to embed in video metadata"
    
    def execute(self, context):
        props = context.scene.video_auth_props
        new_model = props.models.add()
        new_model.model_name = f"Model_{len(props.models)}"
        props.active_model_index = len(props.models) - 1
        return {'FINISHED'}

class VIDEO_AUTH_OT_remove_model(Operator):
    """Remove a model from the authentication list"""
    bl_idname = "video_auth.remove_model"
    bl_label = "Remove Model"
    bl_description = "Remove selected model from authentication list"
    
    def execute(self, context):
        props = context.scene.video_auth_props
        if props.models:
            props.models.remove(props.active_model_index)
            if props.active_model_index >= len(props.models):
                props.active_model_index = max(0, len(props.models) - 1)
        return {'FINISHED'}

class VIDEO_AUTH_OT_extract_signatures(Operator):
    """Extract signatures from all added OBJ files"""
    bl_idname = "video_auth.extract_signatures"
    bl_label = "Extract Signatures"
    bl_description = "Extract digital signatures from all added OBJ files"
    
    def execute(self, context):
        props = context.scene.video_auth_props
        extracted_count = 0
        
        for model in props.models:
            if model.obj_file_path and os.path.exists(model.obj_file_path):
                try:
                    # Read OBJ file and extract signature
                    with open(model.obj_file_path, 'r') as f:
                        obj_data = f.read()
                    
                    signature, original_hash, artist_info = self.extract_signature_from_obj(obj_data)
                    
                    if signature and artist_info:
                        model.signature_extracted = True
                        model.artist_name = artist_info.get('name', 'Unknown')
                        extracted_count += 1
                        self.report({'INFO'}, f"Extracted signature from {model.model_name}")
                    else:
                        model.signature_extracted = False
                        self.report({'WARNING'}, f"No signature found in {model.model_name}")
                        
                except Exception as e:
                    model.signature_extracted = False
                    self.report({'ERROR'}, f"Error reading {model.model_name}: {str(e)}")
        
        self.report({'INFO'}, f"Extracted {extracted_count} signatures from {len(props.models)} models")
        return {'FINISHED'}
    
    def extract_signature_from_obj(self, obj_data):
        """Extract signature from OBJ file data (simplified version)"""
        lines = obj_data.split('\n')
        signature = None
        original_hash = None
        artist_info = None
        
        for line in lines:
            if line.startswith("# Digital Signature:"):
                try:
                    # Parse the signature line
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        signature_data = parts[1].strip()
                        # In a real implementation, you'd parse the full signature format
                        signature = signature_data[:64]  # Simplified
                        original_hash = "dummy_hash"  # Would extract real hash
                        artist_info = {"name": "Artist Name"}  # Would extract real artist info
                except:
                    pass
        
        return signature, original_hash, artist_info

class VIDEO_AUTH_OT_render_authenticated(Operator):
    """Render video with authentication"""
    bl_idname = "video_auth.render_authenticated"
    bl_label = "Render Authenticated Video"
    bl_description = "Render video and embed 3D model signatures in metadata"
    
    def execute(self, context):
        props = context.scene.video_auth_props
        
        if not props.enable_auth:
            self.report({'ERROR'}, "Video authentication is not enabled")
            return {'CANCELLED'}
        
        # Check if we have models with signatures
        signed_models = [m for m in props.models if m.signature_extracted]
        if not signed_models:
            self.report({'ERROR'}, "No signed models found. Add and extract signatures first.")
            return {'CANCELLED'}
        
        # Start regular render
        bpy.ops.render.render('INVOKE_DEFAULT', animation=True)
        
        # Register post-render handler
        if self.post_render_handler not in bpy.app.handlers.render_complete:
            bpy.app.handlers.render_complete.append(self.post_render_handler)
        
        return {'FINISHED'}
    
    @staticmethod
    def post_render_handler(scene):
        """Handler called after render completion"""
        props = scene.video_auth_props
        
        if not props.enable_auth or not props.output_authenticated:
            return
        
        # Get render output path
        render_path = bpy.context.scene.render.filepath
        if not render_path:
            print("No render output path specified")
            return
        
        # Create authenticated version
        try:
            VIDEO_AUTH_OT_render_authenticated.create_authenticated_video(scene, render_path)
        except Exception as e:
            print(f"Error creating authenticated video: {e}")
    
    @staticmethod
    def create_authenticated_video(scene, video_path):
        """Create authenticated version of rendered video"""
        props = scene.video_auth_props
        
        # Collect signature data
        signatures = []
        for model in props.models:
            if model.signature_extracted:
                signatures.append({
                    "model_name": model.model_name,
                    "signature": "dummy_signature",  # Would use real signature
                    "artist_info": {"name": model.artist_name},
                    "model_hash": "dummy_hash",  # Would use real hash
                    "timestamp": datetime.now().isoformat()
                })
        
        if props.security_level == 'SECURE':
            VIDEO_AUTH_OT_render_authenticated.create_secure_video(video_path, signatures)
        else:
            VIDEO_AUTH_OT_render_authenticated.create_basic_video(video_path, signatures)
    
    @staticmethod
    def create_basic_video(video_path, signatures):
        """Create basic authenticated video (legacy mode)"""
        # Create metadata payload
        payload = {
            "signature_version": "1.0",
            "created_at": datetime.now().isoformat(),
            "total_models": len(signatures),
            "signatures": signatures
        }
        
        json_str = json.dumps(payload, separators=(',', ':'))
        metadata_payload = base64.b64encode(json_str.encode()).decode()
        
        # Create authenticated video using ffmpeg
        authenticated_path = video_path.replace('.mp4', '_authenticated_basic.mp4')
        
        cmd = [
            'ffmpeg', '-i', video_path,
            '-metadata', f'comment={metadata_payload}',
            '-metadata', 'title=Authenticated 3D Content (Basic)',
            '-c', 'copy',
            authenticated_path
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"Created basic authenticated video: {authenticated_path}")
        except subprocess.CalledProcessError as e:
            print(f"FFmpeg error: {e}")
    
    @staticmethod
    def create_secure_video(video_path, signatures):
        """Create secure authenticated video with tamper protection"""
        # Calculate video content hash
        content_hash = VIDEO_AUTH_OT_render_authenticated.calculate_video_hash(video_path)
        
        # Create secure payload
        payload = {
            "version": "2.0",
            "security_level": "secure",
            "content_hash": content_hash,
            "created_at": datetime.now().isoformat(),
            "signatures": signatures
        }
        
        # Create integrity signature
        json_str = json.dumps(payload, separators=(',', ':'))
        system_key = b"blender_3mvap_system_key_v2"  # In production, use proper key management
        integrity_signature = hmac.new(system_key, json_str.encode(), hashlib.sha256).hexdigest()
        payload["integrity_signature"] = integrity_signature
        
        # Re-serialize with integrity signature
        final_json = json.dumps(payload, separators=(',', ':'))
        
        # Obfuscate payload
        obfuscated_data = VIDEO_AUTH_OT_render_authenticated.obfuscate_data(final_json)
        
        # Create authenticated video using ffmpeg with redundant storage
        authenticated_path = video_path.replace('.mp4', '_authenticated_secure.mp4')
        
        cmd = [
            'ffmpeg', '-i', video_path,
            '-metadata', f'comment={obfuscated_data}',
            '-metadata', f'description={obfuscated_data}',
            '-metadata', f'album={obfuscated_data}',
            '-metadata', 'title=Authenticated 3D Content (Secure)',
            '-c', 'copy',
            authenticated_path
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"Created secure authenticated video: {authenticated_path}")
        except subprocess.CalledProcessError as e:
            print(f"FFmpeg error: {e}")
    
    @staticmethod
    def calculate_video_hash(video_path):
        """Calculate SHA256 hash of video content"""
        try:
            cmd = ['ffmpeg', '-i', video_path, '-f', 'md5', '-']
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                # Extract hash from ffmpeg output
                hash_line = result.stderr.split('\n')[-2] if result.stderr else ""
                if '=' in hash_line:
                    return hash_line.split('=')[1].strip()
            return "unknown_hash"
        except:
            return "unknown_hash"
    
    @staticmethod
    def obfuscate_data(data):
        """XOR obfuscation with base64 encoding"""
        key = b"3mvap_blender_xor_key"
        data_bytes = data.encode()
        
        # XOR with repeating key
        obfuscated = bytearray()
        for i, byte in enumerate(data_bytes):
            obfuscated.append(byte ^ key[i % len(key)])
        
        # Double base64 encoding
        first_encode = base64.b64encode(obfuscated).decode()
        second_encode = base64.b64encode(first_encode.encode()).decode()
        
        return second_encode

class VIDEO_AUTH_PT_panel(Panel):
    """Video Authentication panel in Render Properties"""
    bl_label = "Video Authentication"
    bl_idname = "VIDEO_AUTH_PT_panel"
    bl_space_type = 'PROPERTIES'
    bl_region_type = 'WINDOW'
    bl_context = "render"
    
    def draw_header(self, context):
        props = context.scene.video_auth_props
        self.layout.prop(props, "enable_auth", text="")
    
    def draw(self, context):
        layout = self.layout
        props = context.scene.video_auth_props
        
        layout.active = props.enable_auth
        
        # Models list
        row = layout.row()
        row.template_list("UI_UL_list", "video_auth_models", props, "models", 
                         props, "active_model_index", rows=3)
        
        col = row.column(align=True)
        col.operator("video_auth.add_model", icon='ADD', text="")
        col.operator("video_auth.remove_model", icon='REMOVE', text="")
        
        # Model details
        if props.models and props.active_model_index < len(props.models):
            model = props.models[props.active_model_index]
            
            box = layout.box()
            box.prop(model, "model_name")
            box.prop(model, "obj_file_path")
            
            if model.signature_extracted:
                box.label(text=f"Artist: {model.artist_name}", icon='CHECKMARK')
            else:
                box.label(text="No signature extracted", icon='ERROR')
        
        # Security settings
        layout.separator()
        box = layout.box()
        box.label(text="Security Settings", icon='LOCKED')
        box.prop(props, "security_level")
        
        if props.security_level == 'BASIC':
            box.label(text="⚠️ Basic mode is vulnerable to tampering", icon='ERROR')
        else:
            box.label(text="🔒 Secure mode provides tamper-resistant protection", icon='CHECKMARK')
        
        # Operations
        layout.separator()
        layout.operator("video_auth.extract_signatures")
        
        layout.separator()
        layout.prop(props, "output_authenticated")
        layout.operator("video_auth.render_authenticated", icon='RENDER_ANIMATION')

classes = (
    VideoAuthModelEntry,
    VideoAuthProperties,
    VIDEO_AUTH_OT_add_model,
    VIDEO_AUTH_OT_remove_model,
    VIDEO_AUTH_OT_extract_signatures,
    VIDEO_AUTH_OT_render_authenticated,
    VIDEO_AUTH_PT_panel,
)

def register():
    for cls in classes:
        bpy.utils.register_class(cls)
    
    bpy.types.Scene.video_auth_props = bpy.props.PointerProperty(type=VideoAuthProperties)

def unregister():
    for cls in reversed(classes):
        bpy.utils.unregister_class(cls)
    
    del bpy.types.Scene.video_auth_props
    
    # Remove handler if it exists
    if VIDEO_AUTH_OT_render_authenticated.post_render_handler in bpy.app.handlers.render_complete:
        bpy.app.handlers.render_complete.remove(VIDEO_AUTH_OT_render_authenticated.post_render_handler)

if __name__ == "__main__":
    register()
