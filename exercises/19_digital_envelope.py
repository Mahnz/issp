# Encrypt the communication between Alice and Bob using a digital envelope that uses
# AES to encrypt the message, and RSA to encrypt the symmetric key.
#
# Note: You may use the AES class from the issp library. You must implement RSA encryption
# using the cryptography library only.

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from issp import Actor, Channel, AES, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    channel = Channel()

    symmetric_key_size = rsa_key_size = 2048
    cipher = AES()

    # BOB - Generates his pair of keys (RSA)
    bob_sk = rsa.generate_private_key(public_exponent=65537, key_size=rsa_key_size)
    bob_pk = bob_sk.public_key()
    rsa_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    # ALICE - Generate a symmetric key
    iv = os.urandom(cipher.iv_size)

    message = b"Hello, Bob! - Alice"
    message_encrypted = cipher.encrypt(message, iv)

    # ALICE - Encrypts the symmetric key with BOB's public key
    key_encrypted = bob_pk.encrypt(cipher.key, rsa_padding)

    # ALICE - Sends: iv + symmetric key encrypted + message encrypted
    alice.send(channel, iv + key_encrypted + message_encrypted)

    print()

    # mallory = Actor("Mallory", quiet=False)
    # mallory.receive(channel)

    # BOB - Receives the message
    received = bob.receive(channel)
    iv_rcv = received[: cipher.iv_size]
    received = received[cipher.iv_size:]
    encrypted_key_rcv = received[: symmetric_key_size // 8]
    message_rcv = received[rsa_key_size // 8:]

    # test = "message" + "key"
    # print(test[3:])

    print()

    key_rcv = bob_sk.decrypt(encrypted_key_rcv, rsa_padding)
    message_decrypted = cipher.decrypt(message_rcv, iv_rcv)

    log.info("Bob received: %s", message)

if __name__ == "__main__":
    main()
