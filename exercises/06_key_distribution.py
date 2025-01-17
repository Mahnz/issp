# Implement the symmetric key distribution scheme that we have discussed in the lectures.
#
# Hint: You can use the pre-implemented ciphers from the issp module (e.g. AES or ChaCha).
import logging
import os

from issp import Actor, Channel, EncryptionLayer, AES


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    kdc = Actor("KDC")
    channel = Channel()

    alice_kdc_layer = EncryptionLayer(channel, AES())
    bob_kdc_layer = EncryptionLayer(channel, AES())

    # Alice --> KDC
    alice.send(alice_kdc_layer, b"Hello, KDC. I'm Alice.")
    kdc.receive(alice_kdc_layer)

    # KDC
    key = os.urandom(32)

    # KDC --> Alice
    kdc.send(alice_kdc_layer, key)
    alice_bob_key = alice.receive(alice_kdc_layer)

    # KDC --> Bob
    kdc.send(bob_kdc_layer, key)
    bob_alice_key = alice.receive(bob_kdc_layer)

    # Alice <--> Bob
    alice_bob_layer = EncryptionLayer(channel, AES(alice_bob_key))
    bob_alice_layer = EncryptionLayer(channel, AES(bob_alice_key))

    alice.send(alice_bob_layer, b"Hello, Bob. I'm Alice.")
    bob.receive(bob_alice_layer)


if __name__ == "__main__":
    main()
