# 1) Implement a two-factor authentication protocol where the user authenticates by sending
#    a username, password, and HMAC-based One-Time Password (HOTP) to the server.
#    The HOTP should be 6 digits long.
#
# 2) Help Mallory attack the protocol by replaying Alice's transaction request.
#    Is the attack successful? Why?
#
# Hint: you can use the hmac_sha1 function from the issp module to compute the HMAC.
#       To compute the truncate() function, you can extract the least significant 31 bits
#       of the HMAC value (value & 0x7FFFFFFF).

import os
import time

from issp import (
    AES,
    Actor,
    AuthenticationLayer,
    BankServer,
    Channel,
    EncryptionLayer,
    JSONMessage,
    RSASigner,
    hmac_sha1,
    log,
    scrypt,
)


class HOTP:
    DIGITS = 6

    def __init__(self, key: bytes) -> None:
        self.key = key
        self._counter = 0

    def get_otp(self) -> int:
        self._counter += 1
        mac = hmac_sha1(self._counter.to_bytes(8), self.key)
        return (int.from_bytes(mac) & 0x7FFFFFFF) % 10**self.DIGITS


class Server(BankServer):
    def register(self, msg: JSONMessage) -> bool:
        user = msg["user"]

        if user in self.db:
            return False

        self.db[user] = {
            "salt": (salt := os.urandom(16)),
            "password": scrypt(msg["password"], salt=salt),
            "otp": HOTP(msg["otp_key"]),
            "balance": msg["balance"],
        }
        return True

    def authenticate(self, msg: JSONMessage) -> bool:
        if (record := self.db.get(msg["user"])) is None:
            return False

        # First factor: password.
        if scrypt(msg["password"], salt=record["salt"]) != record["password"]:
            return False

        # Second factor: OTP.
        otp: HOTP = record["otp"]
        return otp.get_otp() == int(msg["otp"])


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
        "otp_key": os.urandom(16),
        "balance": 1000.0,
    }
    mallory.send(channel, message)
    server.handle_request(channel)

    alice_password = "p4ssw0rd"
    alice_otp = HOTP(os.urandom(16))
    message = {
        "action": "register",
        "user": alice.name,
        "password": alice_password,
        "otp_key": alice_otp.key,
        "balance": 100000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    # Authenticated transactions.
    transaction_count = 10
    for i in range(transaction_count):
        time.sleep(1)
        log.info("Transaction %d", i + 1)
        message = {
            "action": "perform_transaction",
            "user": alice.name,
            "password": alice_password,
            "otp": alice_otp.get_otp(),
            "recipient": "Mallory",
            "amount": 1000.0,
        }
        alice.send(secure_channel, message)
        if i == transaction_count - 1:
            # Capture the last transaction request.
            captured_request = mallory.receive(channel)
        server.handle_request(secure_channel)

    # Replay an authenticated transaction request.
    log.info("Replaying authenticated transaction request...")
    mallory.send(channel, captured_request)
    server.handle_request(secure_channel)


if __name__ == "__main__":
    main()
