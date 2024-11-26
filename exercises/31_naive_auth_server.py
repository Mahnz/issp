# 1) Implement a naive authentication protocol where the user authenticates by sending
#    a username and password to the server. The server should store the password hashed
#    and salted using a slow hash function.
#
# 2) Help Mallory attack the protocol by replaying Alice's transaction request.


from issp import (
    AES,
    Actor,
    AuthenticationLayer,
    BankServer,
    Channel,
    EncryptionLayer,
    JSONMessage,
    RSASigner,
    log,
)


class Server(BankServer):
    def register(self, msg: JSONMessage) -> bool:
        # Implement. Return True if the registration was successful, False otherwise.
        return False

    def authenticate(self, msg: JSONMessage) -> bool:
        # Implement. Return True if the authentication was successful, False otherwise.
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
        "password": "p4ssw0rd",
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

    # Authenticated transaction.
    message = {
        "action": "perform_transaction",
        "user": alice.name,
        "password": alice_password,
        "recipient": "Mallory",
        "amount": 1000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    # Replay an authenticated transaction request.
    log.info("Replaying authenticated transaction request...")


if __name__ == "__main__":
    main()
