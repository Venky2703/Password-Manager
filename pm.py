import base64
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets

class PasswordManager:
    def __init__(self):
        self.salt = b'\x00' * 16 
        self.key = self.derive_key()
        self.data_file = "passwords.json"
        if not os.path.exists(self.data_file):
            with open(self.data_file, 'w') as f:
                json.dump({}, f)
        self.ensure_json_valid()

    def ensure_json_valid(self):
        try:
            with open(self.data_file, 'r') as f:
                json.load(f)
        except json.JSONDecodeError:
            with open(self.data_file, 'w') as f:
                json.dump({}, f)

    def derive_key(self):
        password = b'super_secret_key'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)

    def encrypt_password(self, plain_password: str) -> str:
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        encrypted_password = encryptor.update(plain_password.encode()) + encryptor.finalize()
        return base64.urlsafe_b64encode(iv + encryptor.tag + encrypted_password).decode()

    def decrypt_password(self, encrypted_password: str) -> str:
        encrypted_data = base64.urlsafe_b64decode(encrypted_password)
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        encrypted_password = encrypted_data[28:]
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        return (decryptor.update(encrypted_password) + decryptor.finalize()).decode()

    def generate_secure_password(self, length: int = 16) -> str:
        return ''.join(secrets.choice(
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+'
        ) for _ in range(length))

    def save_password(self, website: str, username: str, password: str):
        with open(self.data_file, 'r+') as f:
            data = json.load(f)
            data[website] = {"username": username, "password": self.encrypt_password(password)}
            f.seek(0)
            json.dump(data, f, indent=4)

    def retrieve_password(self, website: str):
        with open(self.data_file, 'r') as f:
            data = json.load(f)
            if website in data:
                username = data[website]["username"]
                password = self.decrypt_password(data[website]["password"])
                return username, password
            else:
                return None, None
import streamlit as st

def main():
    st.title("Password Manager")
    
    st.sidebar.title("Navigate")
    option = st.sidebar.selectbox("Choose an action", ["Store Password", "Retrieve Password", "Generate Secure Password"])

    pm = PasswordManager()

    if option == "Store Password":
        website = st.text_input("Website")
        username = st.text_input("Username")
        plain_password = st.text_input("Password", type="password")
        if st.button("Store"):
            if website and username and plain_password:
                pm.save_password(website, username, plain_password)
                st.success("Password stored successfully")
            else:
                st.error("Please fill all the fields")

    elif option == "Retrieve Password":
        website = st.text_input("Website to retrieve password for")
        if st.button("Retrieve"):
            if website:
                username, password = pm.retrieve_password(website)
                if username and password:
                    st.success(f"Username: {username}\nPassword: {password}")
                else:
                    st.error("No data found for this website")
            else:
                st.error("Please enter the website")

    elif option == "Generate Secure Password":
        length = st.slider("Select the length of the password", 8, 32, 16)
        if st.button("Generate"):
            secure_password = pm.generate_secure_password(length)
            st.success(f"Secure Password: {secure_password}")

if __name__ == "__main__":
    main()
