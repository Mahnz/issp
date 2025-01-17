# Refactor the hash digest exercise to use the Authenticator and AuthenticationLayer classes
# from the issp module.


from issp import Actor, AuthenticationLayer, Authenticator, Channel
from cryptography.hazmat.primitives import hashes


class SHA256(Authenticator):
    size = 32

    def compute_code(self, message: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        return digest.finalize()


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()
    alice_bob_layer = AuthenticationLayer(channel, SHA256())

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    mallory_layer = AuthenticationLayer(channel, SHA256())
    mallory.send(mallory_layer, b"#!%* you, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
