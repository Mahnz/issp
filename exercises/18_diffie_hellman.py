# Implement the Diffie-Hellman key exchange scheme.
#
# Hint: Have a look at the cryprography.hazmat.primitives.asymmetric module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh


from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from issp import Actor, Channel, log, EncryptionLayer, AES


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    channel = Channel()

    # DH - Exchange the parameters.
    log.info(" > Generating the parameters...")
    parameters = dh.generate_parameters(generator=2, key_size=1024)

    log.info(" > Generating the keys...")
    alice_sk = parameters.generate_private_key()
    bob_sk = parameters.generate_private_key()

    # ALICE - Sends her public key to Bob.
    message = alice_sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    alice.send(channel, message)

    # BOB - Receives the public key.
    received = bob.receive(channel)
    bob_alice_public_key = serialization.load_pem_public_key(received)
    bob_alice_shared_key = bob_sk.exchange(bob_alice_public_key)

    # BOB - Sends his public key to Alice.
    message = bob_sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    bob.send(channel, message)

    # ALICE - Receives Bob's public key
    alice_bob_public_key = serialization.load_pem_public_key(alice.receive(channel))
    alice_bob_shared_key = alice_sk.exchange(alice_bob_public_key)

    if alice_bob_shared_key == bob_alice_shared_key:
        log.info("The keys are equal!")
    else:
        log.info("The keys are different!")

    # Since the key is too long for AES, we derive a shorter version...
    key_derivator = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None)
    alice_bob_shared_key = key_derivator.derive(alice_bob_shared_key)

    key_derivator = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None)
    bob_alice_shared_key = key_derivator.derive(bob_alice_shared_key)

    # Alice and Bob can now communicate securely.
    alice_bob_channel = EncryptionLayer(channel, AES(alice_bob_shared_key))
    bob_alice_channel = EncryptionLayer(channel, AES(bob_alice_shared_key))

    alice.send(alice_bob_channel, b"Hello, Bob! - Alice")
    bob.receive(bob_alice_channel)


if __name__ == "__main__":
    main()
