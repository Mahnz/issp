# Secure the communication between Alice and Bob by adding a stack of security layers
# made up of digital envelope encryption digitally signed through RSA.
# Inspect the output of each layer after sending a message from Alice to Bob.
#
# Hint: You can use the DigitalEnvelope and RSASigner classes from the issp library.


from issp import Actor, Channel, DigitalEnvelope, RSASigner, AuthenticationLayer, EncryptionLayer, AES, RSA


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    auth_layer = AuthenticationLayer(channel, RSASigner())
    enc_layer = EncryptionLayer(auth_layer, DigitalEnvelope(
        message_cipher=AES(),
        key_cipher=RSA()
    ))

    # ALICE - Sends the message
    alice.send(enc_layer, b"Hello, Bob! - Alice")

    print()

    # MALLORY - Tamper the message
    mallory.receive(channel)
    print()
    mallory.send(channel, bytes(8) + mallory.receive(channel)[8:])

    print()

    # BOB - Receives the encrypted message
    bob.receive(enc_layer)

    print()


if __name__ == "__main__":
    main()
