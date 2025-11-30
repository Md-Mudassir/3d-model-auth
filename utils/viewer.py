import base64
import streamlit.components.v1 as components


# 3D Model Viewer Component
def render_3d_model(obj_content, height=400):
    """Render a 3D OBJ model using Three.js in Streamlit"""
    
    # Encode OBJ content as Base64 to safely pass to JavaScript
    obj_content_b64 = base64.b64encode(obj_content.encode('utf-8')).decode('ascii')
    
    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/OBJLoader.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
        <style>
            body {{
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                font-family: Arial, sans-serif;
            }}
            #container {{
                width: 100%;
                height: {height}px;
                position: relative;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            }}
            #info {{
                position: absolute;
                top: 10px;
                left: 10px;
                color: white;
                background: rgba(0,0,0,0.7);
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 12px;
                z-index: 100;
            }}
            #loading {{
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                color: white;
                font-size: 18px;
                z-index: 100;
            }}
        </style>
    </head>
    <body>
        <div id="container">
            <div id="loading">Loading 3D Model...</div>
            <div id="info">🖱️ Click and drag to rotate • 🔄 Scroll to zoom</div>
        </div>
        
        <script>
            let scene, camera, renderer, controls;
            let model;
            
            function init() {{
                // Create scene
                scene = new THREE.Scene();
                scene.background = new THREE.Color(0x000000); // Black background
                
                // Create camera
                camera = new THREE.PerspectiveCamera(75, window.innerWidth / {height}, 0.1, 1000);
                camera.position.set(0, 0, 5);
                
                // Create renderer
                renderer = new THREE.WebGLRenderer({{ antialias: true }});
                renderer.setSize(window.innerWidth, {height});
                renderer.shadowMap.enabled = true;
                renderer.shadowMap.type = THREE.PCFSoftShadowMap;
                document.getElementById('container').appendChild(renderer.domElement);
                
                // Add lights - enhanced for black background and white model
                const ambientLight = new THREE.AmbientLight(0x404040, 0.4); // Dimmer ambient light
                scene.add(ambientLight);
                
                // Main directional light from front-top
                const directionalLight = new THREE.DirectionalLight(0xffffff, 0.7);
                directionalLight.position.set(0, 10, 10);
                directionalLight.castShadow = true;
                scene.add(directionalLight);
                
                // Side light for better definition
                const pointLight1 = new THREE.PointLight(0xccccff, 0.4); // Slight blue tint
                pointLight1.position.set(-10, 0, 5);
                scene.add(pointLight1);
                
                // Bottom rim light
                const pointLight2 = new THREE.PointLight(0xffffcc, 0.3); // Slight warm tint
                pointLight2.position.set(5, -10, -5);
                scene.add(pointLight2);
                
                // Add orbit controls
                controls = new THREE.OrbitControls(camera, renderer.domElement);
                controls.enableDamping = true;
                controls.dampingFactor = 0.05;
                controls.enableZoom = true;
                controls.enablePan = true;
                
                // Load OBJ model
                loadModel();
            }}
            
            function loadModel() {{
                const loader = new THREE.OBJLoader();
                
                try {{
                    // Decode Base64 OBJ content
                    const objContentB64 = "{obj_content_b64}";
                    const objContent = atob(objContentB64);
                    const object = loader.parse(objContent);
                    
                    // Apply material to the model with better appearance
                    const material = new THREE.MeshPhongMaterial({{
                        color: 0xffffff, // White color for the object
                        shininess: 40,
                        specular: 0x444444, // Slightly lighter specular for white material
                        transparent: false,
                        opacity: 1.0
                    }});
                    
                    object.traverse(function(child) {{
                        if (child instanceof THREE.Mesh) {{
                            child.material = material;
                            child.castShadow = true;
                            child.receiveShadow = true;
                        }}
                    }});
                    
                    // Center and scale the model
                    const box = new THREE.Box3().setFromObject(object);
                    const center = box.getCenter(new THREE.Vector3());
                    const size = box.getSize(new THREE.Vector3());
                    
                    const maxDim = Math.max(size.x, size.y, size.z);
                    const scale = 2 / maxDim;
                    
                    object.scale.setScalar(scale);
                    object.position.sub(center.multiplyScalar(scale));
                    
                    scene.add(object);
                    model = object;
                    
                    // Hide loading message
                    document.getElementById('loading').style.display = 'none';
                    
                }} catch (error) {{
                    console.error('Error loading model:', error);
                    document.getElementById('loading').innerHTML = 'Error loading 3D model';
                }}
            }}
            
            function animate() {{
                requestAnimationFrame(animate);
                
                if (controls) {{
                    controls.update();
                }}
                
                // Model stays static - user can manually rotate with mouse
                
                renderer.render(scene, camera);
            }}
            
            // Handle window resize
            window.addEventListener('resize', function() {{
                camera.aspect = window.innerWidth / {height};
                camera.updateProjectionMatrix();
                renderer.setSize(window.innerWidth, {height});
            }});
            
            // Initialize when page loads
            init();
            animate();
        </script>
    </body>
    </html>
    """
    
    components.html(html_code, height=height)


def render_distortion_heatmap(original_obj: str, modified_obj: str, height=400):
    """Render a 3D model with distortion heatmap showing where changes occurred"""
    import numpy as np
    
    # Parse vertices from both models
    orig_vertices = []
    mod_vertices = []
    
    for line in original_obj.split('\n'):
        if line.startswith('v '):
            parts = line.split()
            if len(parts) >= 4:
                orig_vertices.append([float(parts[1]), float(parts[2]), float(parts[3])])
    
    for line in modified_obj.split('\n'):
        if line.startswith('v '):
            parts = line.split()
            if len(parts) >= 4:
                mod_vertices.append([float(parts[1]), float(parts[2]), float(parts[3])])
    
    # Calculate distortions
    orig_arr = np.array(orig_vertices)
    mod_arr = np.array(mod_vertices[:len(orig_vertices)])
    
    # Calculate per-vertex distortion (Euclidean distance)
    distortions = np.sqrt(np.sum((orig_arr - mod_arr) ** 2, axis=1))
    
    # Normalize distortions for color mapping (amplify for visibility)
    if distortions.max() > 0:
        norm_distortions = distortions / distortions.max()
    else:
        norm_distortions = distortions
    
    # Create color array (blue = no change, red = max change)
    colors = []
    for d in norm_distortions:
        r = min(1.0, d * 2)  # Red increases with distortion
        g = 0.2
        b = max(0, 1.0 - d * 2)  # Blue decreases with distortion
        colors.append(f"{r:.3f},{g:.3f},{b:.3f}")
    
    colors_str = ";".join(colors)
    
    # Encode OBJ content
    obj_content_b64 = base64.b64encode(modified_obj.encode('utf-8')).decode('ascii')
    
    # Count changed vertices
    changed_count = np.sum(distortions > 0)
    max_dist = distortions.max()
    
    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/OBJLoader.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
        <style>
            body {{
                margin: 0;
                padding: 0;
                background: #1a1a2e;
                font-family: Arial, sans-serif;
            }}
            #container {{
                width: 100%;
                height: {height}px;
                position: relative;
                border-radius: 8px;
                overflow: hidden;
            }}
            #legend {{
                position: absolute;
                top: 10px;
                right: 10px;
                background: rgba(0,0,0,0.8);
                padding: 10px;
                border-radius: 6px;
                color: white;
                font-size: 12px;
                z-index: 100;
            }}
            .legend-gradient {{
                width: 120px;
                height: 15px;
                background: linear-gradient(to right, #0066ff, #ff0000);
                border-radius: 3px;
                margin: 5px 0;
            }}
            #stats {{
                position: absolute;
                bottom: 10px;
                left: 10px;
                background: rgba(0,0,0,0.8);
                padding: 10px;
                border-radius: 6px;
                color: white;
                font-size: 11px;
                z-index: 100;
            }}
            #info {{
                position: absolute;
                top: 10px;
                left: 10px;
                color: white;
                background: rgba(0,0,0,0.7);
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 12px;
                z-index: 100;
            }}
        </style>
    </head>
    <body>
        <div id="container">
            <div id="info">🔥 Distortion Heatmap (Colors Amplified)</div>
            <div id="legend">
                <div><strong>Distortion Level</strong></div>
                <div class="legend-gradient"></div>
                <div style="display:flex;justify-content:space-between;font-size:10px;">
                    <span>None</span>
                    <span>Max</span>
                </div>
            </div>
            <div id="stats">
                📊 Changed: <strong>{int(changed_count)}</strong> vertices<br>
                📏 Max Δ: <strong>{max_dist:.2e}</strong>
            </div>
        </div>
        
        <script>
            const objData = atob("{obj_content_b64}");
            const colorData = "{colors_str}".split(";");
            
            let scene, camera, renderer, controls;
            
            function init() {{
                scene = new THREE.Scene();
                scene.background = new THREE.Color(0x1a1a2e);
                
                camera = new THREE.PerspectiveCamera(75, window.innerWidth / {height}, 0.1, 1000);
                camera.position.set(0, 0, 5);
                
                renderer = new THREE.WebGLRenderer({{ antialias: true }});
                renderer.setSize(window.innerWidth, {height});
                document.getElementById('container').appendChild(renderer.domElement);
                
                // Lights
                const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
                scene.add(ambientLight);
                
                const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
                directionalLight.position.set(0, 10, 10);
                scene.add(directionalLight);
                
                // Load model with vertex colors
                const loader = new THREE.OBJLoader();
                const obj = loader.parse(objData);
                
                obj.traverse(function(child) {{
                    if (child instanceof THREE.Mesh) {{
                        const geometry = child.geometry;
                        const positionAttr = geometry.attributes.position;
                        const colors = new Float32Array(positionAttr.count * 3);
                        
                        for (let i = 0; i < positionAttr.count && i < colorData.length; i++) {{
                            const rgb = colorData[i].split(',');
                            colors[i * 3] = parseFloat(rgb[0]);
                            colors[i * 3 + 1] = parseFloat(rgb[1]);
                            colors[i * 3 + 2] = parseFloat(rgb[2]);
                        }}
                        
                        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
                        
                        child.material = new THREE.MeshLambertMaterial({{
                            vertexColors: true,
                            side: THREE.DoubleSide
                        }});
                    }}
                }});
                
                // Center and scale
                const box = new THREE.Box3().setFromObject(obj);
                const center = box.getCenter(new THREE.Vector3());
                const size = box.getSize(new THREE.Vector3());
                const maxDim = Math.max(size.x, size.y, size.z);
                const scale = 3 / maxDim;
                
                obj.position.sub(center);
                obj.scale.set(scale, scale, scale);
                scene.add(obj);
                
                // Controls
                controls = new THREE.OrbitControls(camera, renderer.domElement);
                controls.enableDamping = true;
                controls.dampingFactor = 0.05;
            }}
            
            function animate() {{
                requestAnimationFrame(animate);
                controls.update();
                renderer.render(scene, camera);
            }}
            
            init();
            animate();
        </script>
    </body>
    </html>
    """
    
    components.html(html_code, height=height)


def show_vertex_changes(original_obj: str, modified_obj: str):
    """Display a table of vertex changes"""
    import streamlit as st
    import numpy as np
    import pandas as pd
    
    # Parse vertices
    orig_vertices = []
    mod_vertices = []
    
    for line in original_obj.split('\n'):
        if line.startswith('v '):
            parts = line.split()
            if len(parts) >= 4:
                orig_vertices.append([float(parts[1]), float(parts[2]), float(parts[3])])
    
    for line in modified_obj.split('\n'):
        if line.startswith('v '):
            parts = line.split()
            if len(parts) >= 4:
                mod_vertices.append([float(parts[1]), float(parts[2]), float(parts[3])])
    
    # Find changed vertices
    changes = []
    for i, (orig, mod) in enumerate(zip(orig_vertices, mod_vertices)):
        if orig != mod:
            dist = np.sqrt(sum((a - b) ** 2 for a, b in zip(orig, mod)))
            changes.append({
                'Vertex #': i,
                'Original Z': f"{orig[2]:.10f}",
                'Modified Z': f"{mod[2]:.10f}",
                'Δ (Change)': f"{mod[2] - orig[2]:.2e}",
                'Distance': f"{dist:.2e}"
            })
    
    if changes:
        st.write(f"**{len(changes)} vertices modified** out of {len(orig_vertices)} total")
        
        # Show first 50 changes
        df = pd.DataFrame(changes[:50])
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        if len(changes) > 50:
            st.caption(f"Showing first 50 of {len(changes)} changes")
    else:
        st.write("No vertex changes detected")
