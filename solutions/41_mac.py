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
    _DEFAULT_LABEL = 2
    _DEFAULT_CLEARANCE = 0

    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self.file_data["public.txt"] = b"This is a public file."
        self.file_data["confidential.txt"] = b"This is a confidential file."
        self.file_data["secret.txt"] = b"This is a secret file."

        self.label = {
            "public.txt": 0,
            "confidential.txt": 1,
            "secret.txt": 2,
        }

        self.clearance = {
            "Bob": 1,
            "Carl": 2,
        }

    def authorize(self, user: str, file: str, action: str) -> bool:
        # Default values: lowest clearance and highest label.
        label = self.label.get(file, self._DEFAULT_LABEL)
        clearance = self.clearance.get(user, self._DEFAULT_CLEARANCE)

        if action == "read":
            # ss-property
            return label <= clearance

        if action == "write":
            # *-property
            return label >= clearance

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
