import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import os

# Generate RSA keys for demonstration
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Sign the file
def generate_signature(file_data, private_key):
    file_hash = hashlib.sha256(file_data).digest()
    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

# Embed the signature in the OBJ file
def embed_signature(obj_data, signature):
    # Remove any existing signature line using split('\n') to preserve empty lines and trailing newlines
    lines = obj_data.split('\n')
    lines = [line for line in lines if not line.startswith("# Digital Signature:")]
    new_obj_data = '\n'.join(lines)
    # Ensure exactly one trailing newline
    if not new_obj_data.endswith('\n'):
        new_obj_data += '\n'
    new_obj_data += f"# Digital Signature: {signature}\n"
    return new_obj_data

# Extract the signature from the OBJ file
def extract_signature(obj_data):
    lines = obj_data.splitlines()
    for line in lines:
        if line.startswith("# Digital Signature:"):
            return line.split(":", 1)[1].strip()
    return None

# Verify the signature
def verify_signature(file_data, signature, public_key):
    file_hash = hashlib.sha256(file_data).digest()
    try:
        public_key.verify(
            bytes.fromhex(signature),
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# Streamlit App
def main():
    st.set_page_config(page_title="3D Model Digital Signature Tool", page_icon="🔏", layout="centered")
    st.title("🔏 3D Model Digital Signature Tool")
    st.caption("Digitally sign and verify 3D model (.obj) files with ease and confidence.")
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

    # Generate RSA keys only once per session
    if 'private_key' not in st.session_state or 'public_key' not in st.session_state:
        private_key, public_key = generate_keys()
        st.session_state['private_key'] = private_key
        st.session_state['public_key'] = public_key
    private_key = st.session_state['private_key']
    public_key = st.session_state['public_key']
    tab1, tab2 = st.tabs(["🖊️ Sign File", "🔎 Verify File"])

    with tab1:
        st.header("🖊️ Sign a 3D Model File")
        st.markdown("""
        **How to sign your 3D model:**
        1. Upload your `.obj` file below.
        2. Click **Sign and Download**.
        3. Download your signed file and keep the signature for your records.
        """)
        uploaded_file = st.file_uploader("Upload a 3D Model (.obj) file", type=["obj"], key="sign-upload")
        if uploaded_file:
            obj_data = uploaded_file.read().decode("utf-8")
            file_info = f"**File:** `{uploaded_file.name}` ({uploaded_file.size} bytes)"
            st.markdown(file_info)
            with st.expander("🔍 Preview File Contents"):
                st.text_area("File Preview", obj_data, height=200, disabled=True)
            sign_btn = st.button("🖊️ Sign and Download", key="sign-btn", use_container_width=True)
            if sign_btn:
                with st.spinner("🔏 Generating digital signature and preparing your file..."):
                    signature = generate_signature(obj_data.encode(), private_key)
                    signed_obj_data = embed_signature(obj_data, signature)
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

    with tab2:
        st.header("🔎 Verify a Signed 3D Model File")
        st.markdown("""
        **How to verify a signed file:**
        1. Upload a signed `.obj` file below.
        2. Click **Verify Signature**.
        3. See if the file is authentic and view the extracted signature.
        """)
        uploaded_file = st.file_uploader("Upload a Signed 3D Model (.obj) file", type=["obj"], key="verify-upload")
        if uploaded_file:
            obj_data = uploaded_file.read().decode("utf-8")
            file_info = f"**File:** `{uploaded_file.name}` ({uploaded_file.size} bytes)"
            st.markdown(file_info)
            with st.expander("🔍 Preview File Contents"):
                st.text_area("File Preview", obj_data, height=200, disabled=True)
            verify_btn = st.button("🔎 Verify Signature", key="verify-btn", use_container_width=True)
            if verify_btn:
                with st.spinner("🔎 Extracting and verifying digital signature..."):
                    signature = extract_signature(obj_data)
                    if signature:
                        st.markdown("**Extracted Signature:**")
                        st.markdown(f'<div class="signature-box">{signature}</div>', unsafe_allow_html=True)
                        # Remove only the signature line, preserve all other lines and newlines exactly
                        lines = obj_data.split('\n')
                        if lines and lines[-1] == '':  # Handle trailing newline
                            lines = lines[:-1]
                        if lines and lines[-1].startswith("# Digital Signature:"):
                            unsigned_lines = lines[:-1]
                        else:
                            unsigned_lines = lines
                        unsigned_obj_data = '\n'.join(unsigned_lines)
                        # If original data ended with a newline, preserve it
                        if obj_data.endswith('\n'):
                            unsigned_obj_data += '\n'
                        verified = verify_signature(unsigned_obj_data.encode(), signature, public_key)
                        if verified:
                            st.success("✅ Signature verified successfully! The file is authentic.")
                        else:
                            st.error("❌ Signature verification failed. The file may have been tampered with.")
                    else:
                        st.warning("No digital signature found in the file.")
        else:
            st.info("Upload a signed .obj file to enable verification.")

if __name__ == "__main__":
    main()