# Implement a PRNG based on AES in counter mode, and use it to generate a key
# to encrypt the messages between Alice and Bob.
#
# Hint: You can use either the AES class from the issp module or implement your own.
#       In both cases, it is a good idea to omit the PKCS7 padding to ensure that the output
#       is always the same size as the input.

from issp import AES, RNG, Actor, Channel, EncryptionLayer, log


class CounterRNG(RNG):
    def __init__(self) -> None:
        self._counter = 0
        self._cipher = AES()
        self._cipher.apply_padding = False

    def set_seed(self, seed: bytes) -> None:
        # Implement.
        self._cipher.key = seed

    def next_value(self) -> bytes:
        # Implement.
        self._counter += 1
        return self._cipher.encrypt(self._counter.to_bytes(self._cipher.block_size))


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")

    channel = Channel()
    rng = CounterRNG()
    key = rng.generate(32)
    log.info("Key: %s", key)
    alice_bob_layer = EncryptionLayer(channel, AES(key))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
