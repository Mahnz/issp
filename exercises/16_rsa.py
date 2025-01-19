# Encrypt the communication between Alice and Bob using the RSA asymmetric cipher.
#
# Hint: Have a look at the cryprography.hazmat.primitives.asymmetric module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa


from issp import Actor, Channel, log
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    rsa_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    bob_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bob_pk = bob_sk.public_key()

    message = b"Hello, Bob! - Alice"
    message_encrypted = bob_pk.encrypt(message, rsa_padding)
    alice.send(channel, message_encrypted)

    print()

    mallory.receive(channel)

    print()

    received = bob.receive(channel)
    message_decrypted = bob_sk.decrypt(received, rsa_padding)
    print()
    log.info(f"Bob received: {message_decrypted}")


if __name__ == "__main__":
    main()
