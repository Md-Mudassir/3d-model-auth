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
