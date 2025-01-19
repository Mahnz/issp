# Verify the authenticity and integrity of messages exchanged between Alice and Bob using
# the keyed hash scheme discussed in the lecture, using SHA256 as the underlying hash function.

import os

from cryptography.hazmat.primitives import hashes

from issp import Actor, AuthenticationLayer, Authenticator, Channel


class KeyedSHA256(Authenticator):
    def __init__(self, key: bytes) -> None:
        self._key = key

    def compute_code(self, message: bytes) -> bytes:
        # Implement.
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self._key + message + self._key)

        return digest.finalize()


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()
    alice_bob_layer = AuthenticationLayer(channel, KeyedSHA256(os.urandom(32)))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)

    print()

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    bob.receive(alice_bob_layer)

    print()

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    mallory_layer = AuthenticationLayer(channel, KeyedSHA256(os.urandom(32)))
    mallory.send(mallory_layer, b"#!%* you, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
