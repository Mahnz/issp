# 1) Implement a biometric challenge-response protocol. The server should store the biometric
#    template of each user. The similarity measure should be based on the Euclidean distance
#    between biometric templates. The threshold for successful authentication should be 0.95.
#
# 2) Help Mallory attack the protocol by replaying Alice's transaction requests.
#    Is the attack successful? Why?
#
# 3) Additionally, implement a biometric identification service.
#
# Hint: The similarity of two biometric templates can be computed as
#       1.0 / (1.0 + euclidean_distance(template1, template2)).


from issp import (
    AES,
    Actor,
    AuthenticationLayer,
    BankServer,
    Channel,
    EncryptionLayer,
    JSONMessage,
    RSASigner,
    biometric_template,
)


class Server(BankServer):
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self.handlers["request_transaction"] = self.send_challenge
        self.handlers["identify"] = self.identify

    def register(self, msg: JSONMessage) -> bool:
        # Implement.
        return False

    def send_challenge(self, msg: JSONMessage) -> JSONMessage:
        # Implement by returning the challenge.
        return {"challenge": None}

    def authenticate(self, msg: JSONMessage) -> bool:
        # Implement.
        return False

    def identify(self, msg: JSONMessage) -> JSONMessage:
        # Implement by returning the user that matches the received biometric template.
        matched = None
        return {"status": "success", "user": matched} if matched else {"status": "no match"}


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory")
    server = Server("Server")
    channel = Channel()
    secure_channel = EncryptionLayer(cipher=AES()) | AuthenticationLayer(auth=RSASigner()) | channel

    # Registration.
    message = {
        "action": "register",
        "user": mallory.name,
        "template": biometric_template(mallory),
        "balance": 1000.0,
    }
    mallory.send(channel, message)
    server.handle_request(channel)

    message = {
        "action": "register",
        "user": alice.name,
        "template": biometric_template(alice),
        "balance": 100000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    # Identification.
    message = {
        "action": "identify",
        "template": biometric_template(alice),
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    message = {
        "action": "identify",
        "template": biometric_template(mallory),
    }
    mallory.send(channel, message)
    server.handle_request(channel)

    message = {
        "action": "identify",
        "template": biometric_template(bob),
    }
    bob.send(channel, message)
    server.handle_request(channel)

    # Transaction request.
    message = {
        "action": "request_transaction",
        "user": alice.name,
    }
    alice.send(secure_channel, message)

    # Challenge.
    server.handle_request(secure_channel)
    message = alice.receive(secure_channel)

    # Response.
    token = b""  # Implement the response to the challenge.
    message = {
        "action": "perform_transaction",
        "user": alice.name,
        "template": biometric_template(alice),
        "token": token,
        "recipient": "Mallory",
        "amount": 1000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    # Replay an authentication sequence.


if __name__ == "__main__":
    main()
