import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from Crypto.Cipher import Blowfish
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

st.set_page_config(page_title='FortiCrypt', page_icon='ca.png', layout="centered", initial_sidebar_state="auto",
                   menu_items=None)


hide_streamlit_style = """
    <style>
    footer {visibility: hidden;}
    </style>
    """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)




def e1():
    def encrypt(text, shift):
        encrypted_text = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                encrypted_text += encrypted_char
            else:
                encrypted_text += char
        return encrypted_text

    def decrypt(text, shift):
        decrypted_text = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                decrypted_text += decrypted_char
            else:
                decrypted_text += char
        return decrypted_text

    def main():
        st.markdown(
            "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 32px;'>Encryption and "
            "Decryption</h1></center>",
            unsafe_allow_html=True)

        text = st.text_area("Enter the text:")

        mode = st.radio("Choose a mode:", ("Encryption", "Decryption"))

        shift = st.slider("Shift value:", min_value=1, max_value=25, value=1)

        if st.button("Process"):
            result = ""
            if mode == "Encryption":
                result = encrypt(text, shift)
            else:
                result = decrypt(text, shift)

            st.success(f"{mode} Result:")
            st.code(result)

    if __name__ == "__main__":
        main()


def e2():
    def encrypt(plaintext, key):
        cipher = AES.new(key.encode(), AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        encrypted = b64encode(ciphertext).decode('utf-8')
        return iv + encrypted

    def decrypt(ciphertext, key):
        iv = b64decode(ciphertext[:24])
        ciphertext = b64decode(ciphertext[24:])
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode('utf-8')

    def main():
        st.markdown(
            "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 32px;'>Encryption and "
            "Decryption</h1></center>",
            unsafe_allow_html=True)

        mode = st.radio("Mode", ["Encrypt", "Decrypt"])

        if mode == "Encrypt":
            text_label = "Plain text"
            key = st.text_input("Key", value="", key="encrypt_key")
        else:
            text_label = "Encrypted text"
            key = st.text_input("Key", value="", key="decrypt_key")

        text = st.text_area(text_label)

        if st.button("Process"):
            if key and text:
                if len(key) not in [16, 24, 32]:
                    st.warning("Please provide a key of length 16, 24, or 32.")
                else:
                    if mode == "Encrypt":
                        encrypted_text = encrypt(text, key)
                        st.success("Encrypted Text")
                        st.code(encrypted_text, language="plaintext")
                    elif mode == "Decrypt":
                        decrypted_text = decrypt(text, key)
                        st.success("Decrypted Text")
                        st.text_area("", value=decrypted_text)
            else:
                st.error("Please provide a key and text.")

    if __name__ == "__main__":
        main()


def e3():
    def generate_key():
        return Fernet.generate_key()

    def encrypt_message(key, message):
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode())
        return encrypted_message

    def decrypt_message(key, encrypted_message):
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode()

    st.markdown(
        "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 32px;'>Encryption and "
        "Decryption</h1></center>",
        unsafe_allow_html=True
    )

    option = st.selectbox("Choose an action", ("Generate Key", "Encrypt", "Decrypt"))

    if option == "Generate Key":
        key = generate_key()
        st.warning("Your OTP")
        st.code(key.decode())

    if option == "Encrypt":
        message = st.text_input("Enter the message to encrypt:")
        key = st.text_input("Enter the OTP:")
        if st.button("Encrypt"):
            if not message or not key:
                st.error("Please fill in all the required fields.")
            else:
                encrypted_message = encrypt_message(key.encode(), message)
                st.success("Encrypted Message Successfully")
                st.code(encrypted_message.decode())

    if option == "Decrypt":
        encrypted_message = st.text_input("Enter the encrypted message:")
        key = st.text_input("Enter the OTP:")
        if st.button("Decrypt"):
            if not encrypted_message or not key:
                st.error("Please fill in all the required fields.")
            else:
                try:
                    decrypted_message = decrypt_message(key.encode(), encrypted_message.encode())
                    st.success("Decrypted Message Successfully")
                    st.code(decrypted_message)
                except:
                    st.error("Error occurred during decryption. Please check your inputs.")


def e4():
    def encrypt(key, plaintext):
        cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
        padded_plaintext = pad(plaintext.encode(), Blowfish.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext.hex()

    def decrypt(key, ciphertext):
        cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
        decrypted_text = cipher.decrypt(bytes.fromhex(ciphertext))
        plaintext = unpad(decrypted_text, Blowfish.block_size).decode()
        return plaintext

    st.markdown(
        "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 32px;'>Encryption and "
        "Decryption</h1></center>",
        unsafe_allow_html=True)

    action = st.selectbox("Choose an action", ("Please choose one", "Encrypt", "Decrypt"))

    if action == "Encrypt":
        st.markdown(
            "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: "
            "32px;'>Encryption</h1></center>",
            unsafe_allow_html=True)
        plaintext = st.text_input("Enter the plaintext to encrypt")
        key_encrypt = st.text_input("Enter the encryption key")

        if st.button("Encrypt"):
            if plaintext and key_encrypt:
                if len(key_encrypt) < 4:
                    st.warning("Encryption key must be at least 4 characters long.")
                else:
                    encrypted_text = encrypt(key_encrypt, plaintext)
                    st.success("Encrypted text:")
                    st.code(encrypted_text)
            else:
                st.warning("Please enter both plaintext and key for encryption.")



    elif action == "Decrypt":

        st.markdown(

            "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: "

            "32px;'>Decryption</h1></center>",

            unsafe_allow_html=True)

        ciphertext = st.text_input("Enter the ciphertext to decrypt")

        key_decrypt = st.text_input("Enter the decryption key")

        if st.button("Decrypt"):

            if ciphertext and key_decrypt:

                try:

                    decrypted_text = decrypt(key_decrypt, ciphertext)

                    st.success("Decrypted text:")

                    st.code(decrypted_text)

                except ValueError:

                    st.warning("Incorrect decryption key.")

            else:

                st.warning("Please enter both ciphertext and key for decryption.")


def e5():
    def generate_keys():
        key = RSA.generate(2048)
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()
        return private_key, public_key

    def encrypt_message(public_key, message):
        recipient_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_chunks = []
        chunk_size = 214  # Adjust the chunk size as needed
        for i in range(0, len(message), chunk_size):
            chunk = message[i:i + chunk_size]
            encrypted_chunk = cipher_rsa.encrypt(chunk.encode('utf-8'))
            encrypted_chunks.append(encrypted_chunk)
        return b''.join(encrypted_chunks)

    def decrypt_message(private_key, encrypted_message):
        key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        decrypted_chunks = []
        chunk_size = 256  # Adjust the chunk size as needed
        for i in range(0, len(encrypted_message), chunk_size):
            chunk = encrypted_message[i:i + chunk_size]
            decrypted_chunk = cipher_rsa.decrypt(chunk)
            decrypted_chunks.append(decrypted_chunk)
        return b''.join(decrypted_chunks).decode('utf-8')

    st.markdown(
        "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 32px;'>Encryption and "
        "Decryption</h1></center>",
        unsafe_allow_html=True)

    option = st.selectbox("Choose an option",
                          ("Please Select One", "Generate Keys", "Encrypt Message", "Decrypt Message"))

    if option == "Generate Keys":
        st.markdown(
            "<h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 24px;'>Generate Keys</h1></center>",
            unsafe_allow_html=True)
        if st.button("Generate"):
            with st.spinner("Generating keys..."):
                private_key, public_key = generate_keys()
            st.success("Key generation complete!This is Your **OTP.....**")
            st.markdown(
                "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 24px;'>Public "
                "Key</h1></center>",
                unsafe_allow_html=True)
            st.code(public_key, language="python")
            st.markdown(
                "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 24px;'>Private "
                "Key</h1></center>",
                unsafe_allow_html=True)
            st.code(private_key, language="python")

    elif option == "Encrypt Message":
        st.markdown(
            "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 24px;'>Encrypt "
            "Message</h1></center>",
            unsafe_allow_html=True)
        public_key = st.text_area("Enter the recipient's public key")
        message = st.text_area("Enter the message to encrypt", height=300)
        if st.button("Encrypt"):
            encrypted_message = encrypt_message(public_key, message)
            st.markdown(
                "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 24px;'>Encrypted "
                "Message</h1></center>",
                unsafe_allow_html=True)
            st.code(encrypted_message.hex(), language="python")

    elif option == "Decrypt Message":
        st.markdown(
            "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 24px;'>Decrypt "
            "Message</h1></center>",
            unsafe_allow_html=True)
        private_key = st.text_area("Enter your private key")
        encrypted_message = st.text_area("Enter the encrypted Key", height=200)
        if st.button("Decrypt"):
            encrypted_message_bytes = bytes.fromhex(encrypted_message)
            decrypted_message = decrypt_message(private_key, encrypted_message_bytes)
            st.markdown(
                "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 24px;'>Decrypted "
                "Message</h1></center>",
                unsafe_allow_html=True)
            st.text_area("The decrypted message", value=decrypted_message, height=250)


def e6():
    def generate_hash(algorithm, message):
        if algorithm == "MD5":
            hash_object = hashlib.md5(message.encode('utf-8'))
        elif algorithm == "SHA-1":
            hash_object = hashlib.sha1(message.encode('utf-8'))
        elif algorithm == "SHA-256":
            hash_object = hashlib.sha256(message.encode('utf-8'))
        elif algorithm == "SHA-384":
            hash_object = hashlib.sha384(message.encode('utf-8'))
        elif algorithm == "SHA-512":
            hash_object = hashlib.sha512(message.encode('utf-8'))
        else:
            return None

        return hash_object.hexdigest()

    def main():
        st.markdown(
            "<center><h1 style='font-family: Comic Sans MS; font-weight: 300; font-size: 32px;'>Hash "
            "Generator</h1></center>",
            unsafe_allow_html=True)

        algorithms = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]
        algorithm = st.selectbox("Select a hashing algorithm", algorithms)

        message = st.text_input("Enter the message to generate the hash")
        if st.button("Generate Hash"):
            if message:
                hash_value = generate_hash(algorithm, message)
                st.info(f"You Use **{algorithm}** Algorithm")
                st.code(f"{hash_value}")
            else:
                st.error("Please enter a message to generate the hash.")

    if __name__ == "__main__":
        main()


st.sidebar.markdown("""
            <style>
                .sidebar-text {
                    text-align: center;
                    font-size: 32px;
                    font-family: 'Comic Sans MS', cursive;
                }
            </style>
            <p class="sidebar-text">CodeArmor</p>
            <br/>
        """, unsafe_allow_html=True)
st.markdown(
    """
    <style>
    .sidebar .sidebar-content {
        width: 50%;
        margin-left: auto;
        margin-right: auto;
    }
    </style>
    """,
    unsafe_allow_html=True
)
st.sidebar.image("https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTYw76pUzWfgewbH2ORHk4tzpA8Qu-PbIteaQ&usqp=CAU")
sidebar_options = {
    "Simple Text": e1,
    "AES": e2,
    "Fernet": e3,
    "BlowFish": e4,
    "RSA": e5,
    "Hash": e6
}

selected_option = st.sidebar.radio("Please Select One:", list(sidebar_options.keys()))

st.session_state.prev_option = selected_option
sidebar_options[selected_option]()
