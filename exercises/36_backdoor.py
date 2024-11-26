# Help Mallory implement a backdoor in the server that allows them to authenticate as any user.
# Test the backdoor by performing a transaction on behalf of Alice.

import os

from issp import (
    AES,
    Actor,
    AntiReplayLayer,
    AuthenticationLayer,
    BankServer,
    Channel,
    EncryptionLayer,
    JSONMessage,
    RSASigner,
    scrypt,
)


class Server(BankServer):
    def register(self, msg: JSONMessage) -> bool:
        user = msg["user"]

        if user in self.db:
            return False

        self.db[user] = {
            "salt": (salt := os.urandom(16)),
            "password": scrypt(msg["password"], salt=salt),
            "balance": msg["balance"],
        }
        return True

    def authenticate(self, msg: JSONMessage) -> bool:
        if (record := self.db.get(msg["user"])) is None:
            return False

        # Implement a backdoor.

        return scrypt(msg["password"], salt=record["salt"]) == record["password"]


def main() -> None:
    alice = Actor("Alice")
    mallory = Actor("Mallory")
    server = Server("Server")
    channel = Channel()
    secure_channel = (
        AntiReplayLayer()
        | EncryptionLayer(cipher=AES())
        | AuthenticationLayer(auth=RSASigner())
        | channel
    )

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

    # Send a message that enables Mallory to perform a transaction on behalf of Alice.
    message = {}
    mallory.send(channel, message)
    server.handle_request(channel)


if __name__ == "__main__":
    main()
