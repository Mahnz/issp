# Encrypt the communication between Alice and Bob using the AES block cipher in CBC mode.
#
# Hint: Have a look at the cryprography.hazmat.primitives.ciphers module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from issp import Actor, Channel, log, AES

BLOCK_SIZE = 128


def encrypt(message: bytes, key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    message = padder.update(message) + padder.finalize()
    return encryptor.update(message) + encryptor.finalize(message)


def decrypt(message: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    message = decryptor.update(message) + decryptor.finalize()
    return unpadder.update(message) + unpadder.finalize()


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    message = b"Hello, Bob! - Alice"
    log.info("Alice wants to send: %s", message)

    # Encrypt the message here.
    key = os.urandom(32)
    iv_size = BLOCK_SIZE // 8
    iv = os.urandom(iv_size)

    cipher = AES(key)
    message_encrypted = iv + cipher.encrypt(message, iv)

    alice.send(channel, message_encrypted)

    mallory.receive(channel)
    message_received = bob.receive(channel)
    iv_received = message_received[:iv_size]
    message_received = message_received[iv_size:]

    # Decrypt the message here.
    message_decrypted = cipher.decrypt(message_received, iv_received)
    log.info("Bob decrypted: %s", message_decrypted)


if __name__ == "__main__":
    main()
