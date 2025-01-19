# Implement a variation of the ANSI X9.17 PRNG using AES as the underlying block cipher,
# and use it to generate a key to encrypt the messages between Alice and Bob.
#
# Hint: Avoiding padding is particularly important in this case to preserve the
#       size of the internal state of the PRNG.
import os
import time

from issp import AES, RNG, Actor, Channel, EncryptionLayer, log, xor


class ANSIx917(RNG):
    def __init__(self) -> None:
        self._cipher = AES()
        self._cipher.apply_padding = False
        self._state = self._cipher.encrypt(os.urandom(self._cipher.block_size))

    def set_seed(self, seed: bytes) -> None:
        self._cipher.key = seed

    def next_value(self) -> bytes:
        date = time.time_ns().to_bytes(self._cipher.block_size)
        temp = self._cipher.encrypt(date)
        output = self._cipher.encrypt(xor(self._state, temp))
        self._state = self._cipher.encrypt(xor(output, temp))
        return output


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")

    channel = Channel()
    rng = ANSIx917()
    key = rng.generate(32)
    log.info("Key: %s", key)
    alice_bob_layer = EncryptionLayer(channel, AES(key))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
