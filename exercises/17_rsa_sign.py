# Verify the authenticity, integrity, and non-repudiation of messages exchanged
# between Alice and Bob using RSA signatures.
#
# Hint: Have a look at the cryprography.hazmat.primitives.asymmetric module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from issp import Actor, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    rsa_padding = padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )

    key_size = 2048
    alice_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alice_pk = alice_sk.public_key()

    # ALICE - Sign the message here.
    message = b"Hello, Bob! - Alice"
    signature = alice_sk.sign(message, rsa_padding, hashes.SHA256())

    alice.send(channel, message + signature)

    print()

    # mallory.send(channel, mallory.receive(channel)[8:])

    # BOB - Receive the message and verify.
    received = bob.receive(channel)
    message_received = received[:-key_size // 8]
    signature_received = received[-key_size // 8:]

    # Verify the signature here.
    alice_pk.verify(
        signature=signature_received,
        data=message_received,
        padding=rsa_padding,
        algorithm=hashes.SHA256()
    )

    print()

    try:
        alice_pk.verify(signature, message, rsa_padding, hashes.SHA256())
        log.info("Bob successfully verified the signature")
    except InvalidSignature:
        log.info("Signature verification failed")


if __name__ == "__main__":
    main()
