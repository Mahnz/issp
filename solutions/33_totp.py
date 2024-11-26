# 1) Implement a two-factor authentication protocol where the user authenticates by sending
#    a username, password, and Time-based One-Time Password (TOTP) to the server.
#    The TOTP should be 6 digits long, and it should change every 2 seconds.
#
# 2) Help Mallory attack the protocol by replaying Alice's transaction request.
#    Is the attack successful? Why?
#
# 3) Fix the vulnerability in the protocol by disallowing the reuse of OTPs.

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


class TOTP:
    DIGITS = 6
    PERIOD = 2
    EPOCH = 0

    def __init__(self, key: bytes) -> None:
        self.key = key

    def get_otp(self) -> int:
        counter = int((time.time() - self.EPOCH) / self.PERIOD)
        mac = hmac_sha1(counter.to_bytes(8), self.key)
        return (int.from_bytes(mac) & 0x7FFFFFFF) % 10**self.DIGITS


class Server(BankServer):
    def register(self, msg: JSONMessage) -> bool:
        user = msg["user"]

        if user in self.db:
            return False

        self.db[user] = {
            "salt": (salt := os.urandom(16)),
            "password": scrypt(msg["password"], salt=salt),
            "otp": TOTP(msg["otp_key"]),
            "balance": msg["balance"],
        }
        return True

    def _authenticate_vulnerable(self, msg: JSONMessage) -> bool:
        if (record := self.db.get(msg["user"])) is None:
            return False

        # First factor: password.
        if scrypt(msg["password"], salt=record["salt"]) != record["password"]:
            return False

        # Second factor: OTP.
        otp: TOTP = record["otp"]
        return otp.get_otp() == int(msg["otp"])

    def _authenticate_secure(self, msg: JSONMessage) -> bool:
        if (record := self.db.get(msg["user"])) is None:
            return False

        # First factor: password.
        if scrypt(msg["password"], salt=record["salt"]) != record["password"]:
            return False

        # Second factor: OTP.
        otp: TOTP = record["otp"]
        received_otp = int(msg["otp"])

        if received_otp == record.get("last_otp") or received_otp != otp.get_otp():
            return False

        record["last_otp"] = received_otp
        return True

    def authenticate(self, msg: JSONMessage) -> bool:
        return self._authenticate_secure(msg)


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
    alice_otp = TOTP(os.urandom(16))
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
