# Verify the integrity of messages exchanged between Alice and Bob using SHA256 hash digests.
#
# Hint: Have a look at the cryprography.hazmat.primitives.hashes module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes


from issp import Actor, Channel, log
from cryptography.hazmat.primitives.hashes import SHA256, Hash

DIGEST_SIZE = SHA256().digest_size


def compute_sha256(data: bytes) -> bytes:
    digest = Hash(SHA256())
    digest.update(data)
    return digest.finalize()


def check_sha256(data: bytes):
    print(data)

    digest_received = data[-DIGEST_SIZE:]
    message = data[:-DIGEST_SIZE]

    print(message)

    # Compute the digest
    digest_computed = compute_sha256(message)

    # Check the digest
    if digest_received == digest_computed:
        log.info("Digest verified correctly.")
    else:
        log.warning("The message has been compromised!")


def main() -> None:
    abc = "test"
    print(abc[:2])

    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()

    message = b"Hello, Bob! - Alice"

    # Compute and append the digest of the message.
    digest = compute_sha256(message)
    alice.send(channel, message + digest)

    mallory.receive(channel)

    # Verify the digest of the received message.
    received = bob.receive(channel)
    check_sha256(received)

    # Compute and append the digest of the message.
    alice.send(channel, message)
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    # Verify the digest of the received message.

    message = b"Hello, Bob! - Alice"
    # Compute and append the digest of the message.
    alice.send(channel, message)
    mallory.receive(channel)
    message = b"#!%* you, Bob! - Alice"
    # Compute and append the digest of the message.
    mallory.send(channel, message)
    # Verify the digest of the received message.


if __name__ == "__main__":
    main()
