# Encrypt the communication between Alice and Bob using the OTP algorithm.
#
# Hint: Use the os.urandom function to generate a random key.

import os

from issp import Actor, Channel, log


def xor(message: bytes, key: bytes) -> bytes:
    length = len(message)
    return bytes(message[i] ^ key[i] for i in range(length))


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    message = b"Hello, Bob! - Alice"
    log.info("Alice wants to send: %s", message)

    # Encrypt the message here.
    key = os.urandom(256)
    message_encrypted = xor(message, key)
    alice.send(channel, message_encrypted)

    mallory.receive(channel)
    message_received = bob.receive(channel)

    # Decrypt the message here.
    message_decrypted = xor(message_received, key)
    log.info("Bob decrypted: %s", message_decrypted)


if __name__ == "__main__":
    main()
