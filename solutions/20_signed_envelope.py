# Secure the communication between Alice and Bob by adding a stack of security layers
# made up of digital envelope encryption digitally signed through RSA.
# Inspect the output of each layer after sending a message from Alice to Bob.
#
# Hint: You can use the DigitalEnvelope and RSASigner classes from the issp library.

from issp import AES, RSA, Actor, AuthenticationLayer, Channel, DigitalEnvelope, EncryptionLayer, RSASigner, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()
    auth_layer = AuthenticationLayer(channel, RSASigner())
    enc_layer = EncryptionLayer(auth_layer, DigitalEnvelope(AES(), RSA()))

    alice.send(enc_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    # Uncomment the next line to let Mallory tamper with the message.
    # mallory.send(channel, bytes(8) + mallory.receive(channel)[8:])

    try:
        log.info("Encryption output: %s", auth_layer.receive())
        log.info("Authentication output: %s", channel.receive())
    except ValueError:
        pass

    bob.receive(enc_layer)


if __name__ == "__main__":
    main()
