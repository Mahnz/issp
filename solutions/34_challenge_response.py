# 1) Implement a password-based challenge-response protocol. The server should store the password
#    hashed and salted using a slow hash function. Use the same hash function to compute the
#    challenge-response token.
#
# 2) Help Mallory attack the protocol by replaying Alice's transaction requests.
#    Is the attack successful? Why?

import os

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
    scrypt,
)


class Server(BankServer):
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self.handlers["request_transaction"] = self.send_challenge

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

    def send_challenge(self, msg: JSONMessage) -> JSONMessage:
        record = self.db[msg["user"]]
        record["challenge"] = os.urandom(16)
        return {"challenge": record["challenge"], "salt": record["salt"]}

    def authenticate(self, msg: JSONMessage) -> bool:
        if (record := self.db.get(msg["user"])) is None:
            return False
        return scrypt(record.pop("challenge") + record["password"]) == msg["token"]


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
    replay_msg_1 = mallory.receive(channel)

    # Challenge.
    server.handle_request(secure_channel)
    message = alice.receive(secure_channel)

    # Authenticated transaction.
    token = scrypt(message["challenge"] + scrypt(alice_password, salt=message["salt"]))
    message = {
        "action": "perform_transaction",
        "user": alice.name,
        "token": token,
        "recipient": "Mallory",
        "amount": 1000.0,
    }
    alice.send(secure_channel, message)
    replay_msg_2 = mallory.receive(channel)
    server.handle_request(secure_channel)

    # Replay an authentication sequence.
    log.info("Replaying authentication sequence...")
    mallory.send(channel, replay_msg_1)
    server.handle_request(secure_channel)
    mallory.send(channel, replay_msg_2)
    server.handle_request(secure_channel)


if __name__ == "__main__":
    main()
