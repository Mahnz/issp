# Implement a Mandatory Access Control (MAC) policy based on the Bell-LaPadula model. Directives:
#
# - Assume that all users are already authenticated.
# - Alice, Bob, and Carl are users with different security clearances. Bob has clearance
#   for confidential files, Carl for secret files, while Alice does not have an explicit clearance.
# - You must implement the ss-property and the *-property.
# - Make sure to implement reasonable defaults.

import itertools

from issp import Actor, Channel, FileServer, log


class Server(FileServer):
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self.file_data["public.txt"] = b"This is a public file."
        self.file_data["confidential.txt"] = b"This is a confidential file."
        self.file_data["secret.txt"] = b"This is a secret file."

        # Add any necessary state.

    def authorize(self, user: str, file: str, action: str) -> bool:
        # Implement.
        return False


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    carl = Actor("Carl")
    server = Server("Server")
    channel = Channel()

    users = (alice, bob, carl)
    paths = ("public.txt", "confidential.txt", "secret.txt")

    for user, path in itertools.product(users, paths):
        log.info("--- %s reads %s ---", user.name, path)
        message = {"user": user.name, "action": "read", "path": path}
        server.exchange(channel, user, message)

    for user, path in itertools.product(users, paths):
        log.info("--- %s writes %s ---", user.name, path)
        message = {
            "user": user.name,
            "action": "write",
            "data": f" Written by {user.name}.",
            "path": path,
        }
        server.exchange(channel, user, message)


if __name__ == "__main__":
    main()
