# 1) Implement a password-based challenge-response protocol. The server should store the password
#    hashed and salted using a slow hash function. Use the same hash function to compute the
#    challenge-response token.
#
# 2) Help Mallory attack the protocol by replaying Alice's transaction requests.
#    Is the attack successful? Why?


from issp import (
    AES,
    Actor,
    AuthenticationLayer,
    BankServer,
    Channel,
    EncryptionLayer,
    JSONMessage,
    RSASigner,
)


class Server(BankServer):
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self.handlers["request_transaction"] = self.send_challenge

    def register(self, msg: JSONMessage) -> bool:
        # Implement.
        return False

    def send_challenge(self, msg: JSONMessage) -> JSONMessage:
        # Implement by returning the challenge and stored salt.
        return {"challenge": None, "salt": None}

    def authenticate(self, msg: JSONMessage) -> bool:
        # Implement.
        return False


def main() -> None:
    alice = Actor("Alice")
    mallory = Actor("Mallory")
    server = Server("Server")
    channel = Channel()
    secure_channel = EncryptionLayer(cipher=AES()) | AuthenticationLayer(auth=RSASigner()) | channel

    # Registration.
    message = {
        "action": "register",
        "user": mallory.name,
        "password": "s3cr3t",
        "balance": 1000.0,
    }
    mallory.send(channel, message)
    server.handle_request(channel)

    alice_password = "p4ssw0rd"
    message = {
        "action": "register",
        "user": alice.name,
        "password": alice_password,
        "balance": 100000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    # Transaction request.
    message = {
        "action": "request_transaction",
        "user": alice.name,
    }
    alice.send(secure_channel, message)

    # Challenge.
    server.handle_request(secure_channel)
    message = alice.receive(secure_channel)

    # Authenticated transaction.
    token = b""  # Implement the response to the challenge.
    message = {
        "action": "perform_transaction",
        "user": alice.name,
        "token": token,
        "recipient": "Mallory",
        "amount": 1000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    # Replay an authentication sequence.


if __name__ == "__main__":
    main()
