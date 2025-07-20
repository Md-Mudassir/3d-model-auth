import streamlit as st
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib
from datetime import datetime

from utils.viewer import render_3d_model
from utils.database import setup_database, load_artists_from_db, save_artist_to_db
from utils.crypto import generate_keys, load_key_from_pem, generate_signature, embed_signature, extract_signature, verify_signature


# Streamlit App
def main():
    st.set_page_config(page_title="3D Model Digital Signature Tool", page_icon="🔏", layout="centered")
    st.title("🔏 3D Model Digital Signature Tool")
    st.caption("Digitally sign and verify 3D model (.obj) files with ease and confidence.")
    
    # Setup database connection
    conn = setup_database()
    
    # Initialize artist registry from database
    if 'artist_registry' not in st.session_state:
        st.session_state['artist_registry'] = load_artists_from_db(conn)
        
    # Initialize current artist if it doesn't exist
    if 'current_artist' not in st.session_state:
        st.session_state['current_artist'] = None
    st.markdown("""
    <style>
    .stTabs [data-baseweb="tab-list"] {
        justify-content: center;
    }
    .stTabs [data-baseweb="tab"] {
        font-size: 18px;
        padding: 0.5rem 2rem;
    }
    .signature-box {
        background: #23272f;
        color: #fff;
        border-radius: 8px;
        padding: 1em;
        font-family: monospace;
        font-size: 1em;
        word-break: break-all;
        margin-bottom: 0.5em;
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    </style>
    """, unsafe_allow_html=True)

    # Create tabs for the application
    tab1, tab2, tab3 = st.tabs(["👨‍🎨 Artist Management", "🖊️ Sign File", "🔎 Verify File"])
    
    # Handle artist management in tab1
    with tab1:
        st.header("👨‍🎨 Artist Management")
        st.markdown("""
        **Manage Artist Profiles and Keys**
        
        Each artist can have their own unique digital signature for their 3D models.
        Create a new artist profile or select an existing one to sign your models.
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Create New Artist")
            new_artist_name = st.text_input("Artist Name", key="new_artist_name")
            new_artist_email = st.text_input("Email", key="new_artist_email")
            new_artist_website = st.text_input("Website (optional)", key="new_artist_website")
            
            if st.button("Create Artist Profile", use_container_width=True):
                if new_artist_name and new_artist_email:
                    # Check if artist name already exists in the registry
                    if new_artist_name in st.session_state['artist_registry']:
                        st.error(f"An artist with the name '{new_artist_name}' already exists.")
                    else:
                        # Generate keys for the new artist
                        private_key, public_key, private_pem, public_pem = generate_keys(new_artist_name)
                    
                        # Create artist profile
                        artist_info = {
                            "name": new_artist_name,
                            "email": new_artist_email,
                            "website": new_artist_website,
                            "created_at": datetime.now().isoformat(),
                            "private_key": private_pem.decode(),
                            "public_key": public_pem.decode()
                        }
                        
                        # Save to database
                        if save_artist_to_db(conn, artist_info):
                            # Add to registry
                            st.session_state['artist_registry'][new_artist_name] = artist_info
                            st.session_state['current_artist'] = new_artist_name
                            
                            st.success(f"Created new artist profile for {new_artist_name}")
                        else:
                            st.error(f"An artist with the name {new_artist_name} already exists.")
                else:
                    st.error("Artist name and email are required")
        
        with col2:
            st.subheader("Select Existing Artist")
            if st.session_state['artist_registry']:
                artist_names = list(st.session_state['artist_registry'].keys())
                selected_artist = st.selectbox("Choose Artist", options=artist_names, index=0 if artist_names else None)
                
                if selected_artist and st.button("Use This Artist", use_container_width=True):
                    st.session_state['current_artist'] = selected_artist
                    st.success(f"Now using {selected_artist} for signing")
                    
                if st.session_state['current_artist'] in st.session_state['artist_registry']:
                    artist = st.session_state['artist_registry'][st.session_state['current_artist']]
                    st.info(f"**Current Artist:** {artist['name']}")
            else:
                st.info("No artists created yet. Create one in the left panel.")

    with tab2:
        st.header("🖊️ Sign a 3D Model File")
        
        # Check if an artist is selected
        if not st.session_state['current_artist'] or st.session_state['current_artist'] not in st.session_state['artist_registry']:
            st.warning("Please create or select an artist in the Artist Management tab before signing.")
            st.markdown("""
            **How to sign your 3D model:**
            1. First, go to the Artist Management tab and create or select an artist.
            2. Come back to this tab and upload your `.obj` file.
            3. Click **Sign and Download**.
            4. Download your signed file with your unique artist signature embedded.
            """)
        else:
            current_artist = st.session_state['artist_registry'][st.session_state['current_artist']]
            st.success(f"Signing as: **{current_artist['name']}**")
            st.markdown("""
            **How to sign your 3D model:**
            1. Upload your `.obj` file below.
            2. Click **Sign and Download**.
            3. Download your signed file with your unique artist signature embedded.
            """)
        uploaded_file = st.file_uploader("Upload a 3D Model (.obj) file", type=["obj"], key="sign-upload")
        if uploaded_file:
            if not st.session_state['current_artist'] or st.session_state['current_artist'] not in st.session_state['artist_registry']:
                st.error("Please select an artist before signing.")
            else:
                obj_data = uploaded_file.read().decode("utf-8")
                file_info = f"**File:** `{uploaded_file.name}` ({uploaded_file.size} bytes)"
                st.markdown(file_info)
                
                # Display 3D model instead of text preview
                st.markdown("### 🎨 3D Model Preview")
                render_3d_model(obj_data, height=400)
                sign_btn = st.button("🖊️ Sign and Download", key="sign-btn", use_container_width=True)
                if sign_btn:
                    with st.spinner("🔏 Checking and preparing your file..."):
                        # First check if the file is already signed
                        signature, original_hash, existing_artist_info = extract_signature(obj_data)
                        
                        if signature:
                            st.error("🚫 This model is already signed by artist: **" + 
                                   (existing_artist_info.get('name', 'Unknown') if existing_artist_info else 'Unknown') + 
                                   "**. Cannot override an existing signature.")
                            return
                            
                        # Get the current artist information
                        current_artist = st.session_state['artist_registry'][st.session_state['current_artist']]
                        
                        # Load the private key for the current artist
                        private_key = load_key_from_pem(current_artist['private_key'].encode(), is_private=True)
                        public_key = load_key_from_pem(current_artist['public_key'].encode(), is_private=False)
                        
                        # Artist info to embed (without private key)
                        artist_embed_info = {
                            "name": current_artist['name'],
                            "email": current_artist['email'],
                            "website": current_artist['website'],
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        # First, clean the file of any existing authentication markers
                        clean_lines = [line for line in obj_data.split('\n') 
                                      if not line.startswith("# Digital Signature:") 
                                      and not "embedded authentication" in line]
                        clean_obj_data = '\n'.join(clean_lines)
                        if obj_data.endswith('\n'):
                            clean_obj_data += '\n'
                        
                        # Calculate hash of the clean data for verification later
                        sign_hash = hashlib.sha256(clean_obj_data.encode()).digest().hex()
                            
                        # Generate signature based on the clean data
                        signature = generate_signature(clean_obj_data.encode(), private_key)
                        
                        # Embed the signature along with the original hash and artist info
                        signed_obj_data = embed_signature(obj_data, signature, artist_embed_info, sign_hash)
                        
                        # Display success message and signature information
                        st.success("File signed and ready for download!")
                        st.markdown("**Digital Signature:**")
                        st.markdown(f'<div class="signature-box">{signature}</div>', unsafe_allow_html=True)
                        st.download_button(
                            label="⬇️ Download Signed File",
                            data=signed_obj_data,
                    file_name="signed_model.obj",
                    mime="text/plain",
                    key="signed-download"
                )
        else:
            st.info("Upload a .obj file to enable signing.")

    with tab3:
        st.header("🔎 Verify a Signed 3D Model File")
        st.markdown("""
        **How to verify a signed file:**
        1. Upload a signed `.obj` file below.
        2. Click **Verify Signature**.
        3. See if the file is authentic and view the artist information.
        """)
        uploaded_file = st.file_uploader("Upload a Signed 3D Model (.obj) file", type=["obj"], key="verify-upload")
        if uploaded_file:
            obj_data = uploaded_file.read().decode("utf-8")
            file_info = f"**File:** `{uploaded_file.name}` ({uploaded_file.size} bytes)"
            st.markdown(file_info)
            
            # Display 3D model instead of text preview
            st.markdown("### 🎨 3D Model Preview")
            render_3d_model(obj_data, height=400)
            verify_btn = st.button("🔎 Verify Signature", key="verify-btn", use_container_width=True)
            if verify_btn:
                with st.spinner("🔎 Extracting and verifying digital signature..."):
                    signature, original_hash, artist_info = extract_signature(obj_data)
                    if signature:
                        st.markdown("**Extracted Signature:**")
                        st.markdown(f'<div class="signature-box">{signature}</div>', unsafe_allow_html=True)
                        
                        if artist_info:
                            st.markdown("**Artist Information:**")
                            artist_info_md = f"""  
                            * **Name:** {artist_info.get('name', 'Unknown')}
                            * **Email:** {artist_info.get('email', 'Not provided')}
                            * **Website:** {artist_info.get('website', 'Not provided')}
                            * **Timestamp:** {artist_info.get('timestamp', 'Not recorded')}
                            """
                            st.markdown(artist_info_md)
                        else:
                            st.warning("No artist information found in the file.")
                        
                        # For both old and new style signatures, we need to clean the file
                        # of any authentication markers before verification
                        lines = obj_data.split('\n')
                        
                        # Remove both types of markers
                        unsigned_lines = [line for line in lines 
                                        if not line.startswith("# Digital Signature:") 
                                        and not "embedded authentication" in line]
                        
                        # Create a clean version for verification
                        unsigned_obj_data = '\n'.join(unsigned_lines)
                        if obj_data.endswith('\n'):
                            unsigned_obj_data += '\n'
                            
                        try:
                            # If we have the original hash from the file, use it for verification
                            # otherwise calculate the hash from the unsigned data
                            if original_hash and artist_info:
                                st.info(f"Verifying signature from artist: {artist_info.get('name', 'Unknown')}")
                                
                                # Find the artist in the registry if possible
                                artist_found = False
                                for artist_name, artist_data in st.session_state['artist_registry'].items():
                                    if artist_data.get('name') == artist_info.get('name'):
                                        # Use the stored public key
                                        public_key = load_key_from_pem(artist_data['public_key'].encode(), is_private=False)
                                        artist_found = True
                                        break
                                
                                if not artist_found:
                                    st.warning("Artist not found in local registry. Using embedded verification only.")
                                
                                # Create a hash object with the stored hash
                                file_hash = bytes.fromhex(original_hash)
                                try:
                                    # Verify using the stored hash instead of recalculating
                                    public_key.verify(
                                        bytes.fromhex(signature),
                                        file_hash,
                                        padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH
                                        ),
                                        hashes.SHA256()
                                    )
                                    verified = True
                                except Exception as e:
                                    # Verification failed
                                    verified = False
                            else:
                                # Fall back to the old method if no original hash is available
                                verified = verify_signature(unsigned_obj_data.encode(), signature, public_key)
                                
                            if verified:
                                st.success("✅ Signature verified successfully! The file is authentic.")
                            else:
                                st.error("❌ Signature verification failed. The file may have been tampered with.")
                        except Exception as e:
                            st.error(f"Error during verification: {str(e)}")
                    else:
                        st.warning("No digital signature found in the file.")
        else:
            st.info("Upload a signed .obj file to enable verification.")

if __name__ == "__main__":
    main()
    # Close database connection when app exits
    if 'conn' in locals():
        conn.close()