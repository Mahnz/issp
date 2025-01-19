# Help Mallory perform two attacks on the encrypted XOR hash scheme used by Alice and Bob:
#
# 1. Corrupt the message sent by Alice to Bob by scrambling the bytes, but keeping the MAC intact.
# 2. Forge a message from Alice to Bob, again keeping the MAC intact.

import os

from issp import AES, XOR, Actor, AuthenticationLayer, Channel, EncryptedHashMAC, zero_pad, xor


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    xor_digest = XOR()
    mac = EncryptedHashMAC(xor_digest, AES(os.urandom(32)))
    alice_bob_layer = AuthenticationLayer(channel, mac)

    # Attack 1.
    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message_mallory = mallory.receive(channel)
    block_1 = message_mallory[0: xor_digest.code_size]
    block_2 = message_mallory[xor_digest.code_size: 2 * xor_digest.code_size]
    remainder = message_mallory[2 * xor_digest.code_size:]

    message_mallory = block_2 + block_1 + remainder
    mallory.send(channel, message_mallory)
    bob.receive(alice_bob_layer)

    print()

    # Attack 2.
    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")

    received = mallory.receive(channel)
    original_message = received[:-mac.code_size]
    original_mac = received[-mac.code_size:]
    original_digest = xor_digest.compute_code(original_message)

    new_message = b"Kys, Bob! - Alice"
    new_message = zero_pad(new_message, xor_digest.code_size)
    new_digest = xor_digest.compute_code(new_message)

    new_message += xor(new_digest, original_digest)
    new_message += original_mac

    mallory.send(channel, new_message)

    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
