# Verify the authenticity, integrity, and non-repudiation of messages exchanged
# between Alice and Bob using RSA signatures.
#
# Hint: Have a look at the cryprography.hazmat.primitives.asymmetric module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from issp import Actor, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    rsa_padding = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )

    # Alice generates a public/private key pair. The public key is shared with all participants.
    # Note: for RSA, the key size is equal to the size of the signature.
    key_size = 2048
    alice_private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    alice_public_key = alice_private_key.public_key()

    # Alice signs the message using her private key.
    message = b"Hello, Bob! - Alice"
    signature = alice_private_key.sign(message, rsa_padding, hashes.SHA256())

    # Alice sends the message and its signature.
    alice.send(channel, message + signature)

    # Uncomment the next line to let Mallory tamper with the message.
    # mallory.send(channel, mallory.receive(channel)[8:])

    # Bob splits the received message into the plaintext and the signature.
    message = bob.receive(channel)
    signature = message[-key_size // 8:]
    message = message[: -key_size // 8]

    # Bob verifies the signature using Alice's public key.
    log.info("Bob received: %s", message)
    try:
        alice_public_key.verify(signature, message, rsa_padding, hashes.SHA256())
        log.info("Bob successfully verified the signature")
    except InvalidSignature:
        log.info("Signature verification failed")


if __name__ == "__main__":
    main()
