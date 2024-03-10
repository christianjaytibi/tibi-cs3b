import streamlit as st

st.set_page_config(
    page_title="XOR Cipher"
)

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""

    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        cipher_byte = plaintext_byte ^ key_byte 
        ciphertext.append(cipher_byte)
        
        st.write(f"Plaintext byte: {plaintext_byte:08b} = {chr(plaintext_byte)}")
        st.write(f"Key byte:       {key_byte:08b} = {chr(key_byte)}")
        st.write(f"XOR result:     {cipher_byte:08b} = {chr(cipher_byte)}")
        st.write("-" * 20)

    return ciphertext


def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)


def encrypt_decrypt(plaintext, key) -> None:
    if plaintext == key:
        st.write("Plaintext should not be equal to the key.")
    elif len(plaintext) < len(key):
        st.write("Plaintext length should be equal or greater than the length of key.")
    else:   
        ciphertext = xor_encrypt(plaintext, key)
        st.write(f"Ciphertext: {ciphertext.decode()}")
        decrypted = xor_decrypt(ciphertext, key)
        st.write(f"Decrypted: {decrypted.decode()}")


if __name__ == "__main__":
    st.title("_XOR_ Cipher :lock:")
    plaintext = bytes(st.text_area(label="Plaintext").encode())
    key = bytes(st.text_input(label="Key").encode())

    if st.button("Encrypt"):
        encrypt_decrypt(plaintext, key)
