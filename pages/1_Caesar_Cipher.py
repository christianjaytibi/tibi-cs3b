import streamlit as st


def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """
    Encrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: flag if decrypt or encrypt
    Returns:
        A string containing the encrypted text if encrypt and plain text if decrypt
    """
    text = bytes(text.encode())
    result = ''
    for i, char in enumerate(text):
        shift_key = shift_keys[i % len(shift_keys)]
        if ifdecrypt:
            shift_key = -shift_key
        shifted = chr((char + shift_key - 32 + 94) % 94 + 32)
        st.write(f"{i} {chr(char)} {shift_keys[i % len(shift_keys)]} {shifted}")
        result += shifted

    st.write('-' * 10)
    return result
    
if __name__ == '__main__':
    st.title("_Caesar_ Cipher :lock:")
    text = st.text_area(label="Plaintext")
    shift_keys = list(map(int, st.text_input(label="Shift keys").split()))
    
    if st.button("Encrypt"):
        encrypted = encrypt_decrypt(text, shift_keys, ifdecrypt=False)
        decrypted = encrypt_decrypt(encrypted, shift_keys, ifdecrypt= True)
        
        st.write(f'Text: {text}')
        st.write('Shift keys:', *[str(key) for key in shift_keys])
        st.write(f'Cipher: {encrypted}')
        st.write(f'Decrypted text: {decrypted}')