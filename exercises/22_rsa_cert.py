# Fix the man-in-the-middle vulnerability by introducing public key certificates.
# Assume that there is a certificate authority (CA) known to all parties
# that can sign the certificates.
#
# Hint: The certificate should contain Bob's public key and his name.

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from issp import Actor, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    hash_func = hashes.SHA256()
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hash_func),
        algorithm=hash_func,
        label=None,
    )
    pss_padding = padding.PSS(mgf=padding.MGF1(hash_func), salt_length=padding.PSS.MAX_LENGTH)

    # Certificate authority (CA) keys.
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_public_key = ca_private_key.public_key()

    # Prepare a CSR (unsigned certificate), sign it with the CA's private key, and send it to Alice.
    bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bob_unsigned_crt = (
            bob_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            + bob.name.encode()
    )

    ca_signature = ca_private_key.sign(bob_unsigned_crt, pss_padding, hash_func)
    bob_signed_crt = bob_unsigned_crt + ca_signature

    # BOB - Sends his certificate to ALICE
    bob.send(channel, bob_signed_crt)

    # mallory.receive(channel)

    # ALICE - Receives BOB's certificate
    certificate_rcv = alice.receive(channel)
    ca_signature_rcv = certificate_rcv[-ca_public_key.key_size // 8:]
    certificate_rcv = certificate_rcv[:-ca_public_key.key_size // 8]

    # Verify that the received certificate is signed by the CA
    ca_public_key.verify(ca_signature_rcv, certificate_rcv, pss_padding, hash_func)

    # ALICE extracts BOB's public key from the certificate
    bob_public_key = serialization.load_pem_public_key(certificate_rcv)
    alice.send(channel, bob_public_key.encrypt(
        b"I received the certificate. All good!", oaep_padding
    ))

    # BOB - Receives ALICE's message and decrypts it
    received_message = bob.receive(channel)
    log.info("Bob decrypted: %s", bob_private_key.decrypt(received_message, oaep_padding))


if __name__ == "__main__":
    main()
