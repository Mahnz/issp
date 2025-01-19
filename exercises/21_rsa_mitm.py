# Help Mallory perform a successful man-in-the-middle attack on the encrypted communication
# between Alice and Bob. Mallory should be able to eavesdrop on the messages between Alice
# and Bob, and tamper with the communication.

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from issp import Actor, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    rsa_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    # BOB - Sends his public key to Alice.
    bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    message = bob_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    bob.send(channel, message)
    print()

    # MALLORY - Intercepts the public key of BOB
    pk_intercepted = mallory.receive(channel)
    mallory_bob_pk = serialization.load_pem_public_key(pk_intercepted)
    mallory_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = mallory_sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print()
    mallory.send(channel, message)
    print()

    # Alice receives Bob's public key, and uses it to encrypt a message.
    alice_bob_public_key = serialization.load_pem_public_key(alice.receive(channel))
    print()
    alice.send(channel, alice_bob_public_key.encrypt(b"Hello, Bob! - Alice", rsa_padding))
    print()

    # MALLORY - Eavesdrops the message sent by ALICE
    message = mallory.receive(channel)
    print()
    log.info("Mallory decrypted: %s", mallory_sk.decrypt(message, rsa_padding))
    print()
    mallory.send(channel, mallory_bob_pk.encrypt(b"Fuck you, Bob - Alice", rsa_padding))

    print()

    # Bob receives Alice's message and decrypts it.
    received_message = bob.receive(channel)
    print()
    log.info("Bob decrypted: %s", bob_private_key.decrypt(received_message, rsa_padding))


if __name__ == "__main__":
    main()
