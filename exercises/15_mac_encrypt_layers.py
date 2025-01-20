# Secure the communication between Alice and Bob by adding a stack of security layers
# made up of an AES encryption layer and an HMAC digest layer.
# Inspect the output of each layer after sending a message from Alice to Bob.
#
# Hint: The output of each layer can be retrieved by calling the receive() method
#       on the subsequent layer.


from issp import Actor, Channel, AuthenticationLayer, HMAC, EncryptionLayer, AES


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    auth_layer = AuthenticationLayer(channel, HMAC())
    encrypt_layer = EncryptionLayer(auth_layer, AES())

    alice.send(encrypt_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)

    message = message[8:]

    mallory.send(channel, message)

    bob.receive(encrypt_layer)


if __name__ == "__main__":
    main()
