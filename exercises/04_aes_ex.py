# Refactor the AES exercise to use the SymmetricCipher and EncryptionLayer classes
# from the issp module.

import os
from email.utils import decode_rfc2231

from issp import Actor, Channel, EncryptionLayer, SymmetricCipher
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AES(SymmetricCipher):
    iv_size = 16

    def encrypt(self, message: bytes, iv: bytes | None) -> bytes:
        # Implement encryption here.

        encryptor = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        padder = padding.PKCS7(self.iv_size * 8).padder()
        message = padder.update(message) + padder.finalize()
        return encryptor.update(message) + encryptor.finalize()

    def decrypt(self, message: bytes, iv: bytes | None) -> bytes:
        # Implement decryption here.
        decryptor = Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
        unpadder = padding.PKCS7(self.iv_size * 8).unpadder()
        message = decryptor.update(message) + decryptor.finalize()
        return unpadder.update(message) + unpadder.finalize()


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)

    channel = Channel()
    alice_bob_layer = EncryptionLayer(channel, AES(os.urandom(32)))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
