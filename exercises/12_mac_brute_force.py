# Help Mallory perform a brute-force attack on the MAC key used by Alice and Bob.
#
# Hint: Have a look at the itertools.product function.
import os
from itertools import product

from issp import HMAC, Actor, AuthenticationLayer, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()

    key = bytes(30) + os.urandom(2)
    digest = HMAC(key)
    alice_bob_layer = AuthenticationLayer(channel, digest)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")

    message = mallory.receive(channel)
    mac = message[-digest.code_size :]
    message = message[: -digest.code_size]

    found_key = b""

    # Find the key through brute-force.
    for _try in product(range(256), repeat=digest.code_size):
        found_key = bytes(_try)

        if HMAC(found_key).verify(message, mac):
            log.info("I'VE FOUND YOU!")
            break
        else:
            log.info("Not this time, MF!")


    mallory_layer = AuthenticationLayer(channel, HMAC(found_key))
    mallory.send(mallory_layer, b"#!%* you, Bob! - Alice")

    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
