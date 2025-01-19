# Implement a simple Linear Congruential Generator (LCG) and use it to generate a key
# to encrypt the messages between Alice and Bob.
import time

from issp import AES, RNG, Actor, Channel, EncryptionLayer, log


class LCG(RNG):
    M = 2 ** 31 - 1
    A = 16807
    C = 0

    def __init__(self):
        self._state = time.time_ns() % self.M

    def set_seed(self, seed: int) -> None:
        # Implement.
        self._state = seed % self.M

    def next_value(self) -> int:
        self._state = (self.A * self._state + self.C) % self.M
        return self._state


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")

    channel = Channel()
    rng = LCG()
    key = rng.generate(32)
    log.info("Key: %s", key)
    alice_bob_layer = EncryptionLayer(channel, AES(key))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
