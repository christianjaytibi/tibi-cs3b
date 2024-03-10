import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="XOR Cipher"
)

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""

    data = {
        "plaintext_bytes": [],
        "key_bytes": [],
        "cipher_bytes": []
    }
    
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        cipher_byte = plaintext_byte ^ key_byte 
        ciphertext.append(cipher_byte)

        data["plaintext_bytes"].append(f"{plaintext_byte:08b} = {chr(plaintext_byte)}")
        data["key_bytes"].append(f"{key_byte:08b} = {chr(key_byte)}")
        data["cipher_bytes"].append(f"{cipher_byte:08b} = {chr(cipher_byte)}")

        # st.write(f"Plaintext byte: {plaintext_byte:08b} = {chr(plaintext_byte)}")
        # st.write(f"Key byte:       {key_byte:08b} = {chr(key_byte)}")
        # st.write(f"XOR result:     {cipher_byte:08b} = {chr(cipher_byte)}")
        # st.write("-" * 20)

    st.dataframe(
        data,
        column_config= {
            "plaintext_bytes": "Plaintext Bytes",
            "key_bytes": "Key Bytes",
            "cipher_bytes": "Cipher Bytes"
        },
        use_container_width=True
    )
    return ciphertext


def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)


def encrypt_decrypt(plaintext, key) -> None: 
    if plaintext == key:
        st.error("Plaintext and key should not be the same.")
    elif len(plaintext) < len(key):
        st.error("The length of plaintext should be greater than or equal to the length of key.")
    else:
        ciphertext = xor_encrypt(plaintext, key)
        st.write(f"Ciphertext: {ciphertext.decode()}")
        decrypted = xor_decrypt(ciphertext, key)
        st.write(f"Decrypted: {decrypted.decode()}")


if __name__ == "__main__":
    st.title("_XOR_ Cipher :lock:")
    plaintext = bytes(st.text_area(label="Plaintext", value="Insert text here.").encode())
    key = bytes(st.text_input(label="Key", value="key").encode())

    if st.button("Encrypt"):
        encrypt_decrypt(plaintext, key)
