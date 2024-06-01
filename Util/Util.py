import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets


def sha_256_int(number: str) -> bytes:
    """
    Applies the SHA-256 hash function to the given number.
    :param number: number to hash.
    :return: hashed number.
    """
    number_str = str(number)
    hash_object = hashlib.sha256()
    hash_object.update(number_str.encode('utf-8'))

    return hash_object.digest()


def aes_encrypt_str(text: str, key: bytes) -> bytes:
    """
    Applies the AES encryption function to the given text.
    :param text: The text to be encrypted.
    :param key: Key used to encrypt the text.
    :return: Encrypted text as bytes.
    """
    # Convert the text to bytes
    text = text.encode('utf-8')

    # Generates a initialization vector (16 bytes for AES)
    iv = secrets.token_bytes(16)

    # Pad the text to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(text) + padder.finalize()

    # Encrypt the message
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()

    return iv + ciphertext


def aes_decrypt_to_str(crypted_text: bytes, key: bytes) -> str:
    """
    Applies the AES decryption function to the given text.
    :param crypted_text: The text to be decrypted.
    :param key: Key used to decrypt the text.
    :return: Decrypted text.
    """
    # Extract the initialization vector & encrypted text
    iv = crypted_text[:16]
    text = crypted_text[16:]

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_text = decryptor.update(text) + decryptor.finalize()

    # Unpad the text
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain_text = unpadder.update(padded_text) + unpadder.finalize()

    return plain_text.decode("utf-8")