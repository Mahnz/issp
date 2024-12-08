# Implement a Discretionary Access Control (DAC) scheme. Directives:
#
# - Assume that all users are already authenticated.
# - The scheme should support the concept of file ownership.
# - The owner of a file implicitly has read and write permissions, and can grant
#   (and revoke) read and write access to other users.
# - Alice, Bob, and Carl are the owners of files "file_a.txt", "file_b.txt",
#   and "file_c.txt", respectively.
# - Make sure to implement reasonable defaults.

import itertools

from issp import Actor, Channel, FileServer, JSONMessage, log


class Server(FileServer):
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self.handlers["change_permissions"] = self.change_permissions

        self.file_data["file_a.txt"] = b"This file belongs to Alice."
        self.file_data["file_b.txt"] = b"This file belongs to Bob."
        self.file_data["file_c.txt"] = b"This file belongs to Carl."

        # Add any necessary state.

    def authorize(self, user: str, file: str, action: str) -> bool:
        # Implement.
        return False

    def change_permissions(self, msg: JSONMessage) -> JSONMessage:
        # Implement.
        return {"status": "success"}


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    carl = Actor("Carl")
    server = Server("Server")
    channel = Channel()

    users = (alice, bob, carl)
    paths = ("file_a.txt", "file_b.txt", "file_c.txt")

    # At this point, only the owner should be able to read the file.
    for user, path in itertools.product(users, paths):
        log.info("--- %s reads %s ---", user.name, path)
        message = {"user": user.name, "action": "read", "path": path}
        server.exchange(channel, user, message)

    # At this point, only the owner should be able to write to the file.
    for user, path in itertools.product(users, paths):
        log.info("--- %s writes %s ---", user.name, path)
        message = {
            "user": user.name,
            "action": "write",
            "data": f" Written by {user.name}.",
            "path": path,
        }
        server.exchange(channel, user, message)

    # Alice should be able to grant write access to Bob over file_a.txt only.
    for path in paths:
        log.info("--- %s gives write access over %s to %s ---", alice.name, path, bob.name)
        message = {
            "user": alice.name,
            "action": "change_permissions",
            "path": path,
            "target": bob.name,
            "permissions": ["write"],
        }
        server.exchange(channel, alice, message)

    path = "file_a.txt"

    # Alice should be able to grant read access over file_a.txt.
    log.info("--- %s gives read access over %s to %s ---", alice.name, path, carl.name)
    message = {
        "user": alice.name,
        "action": "change_permissions",
        "path": path,
        "target": carl.name,
        "permissions": ["read"],
    }
    server.exchange(channel, alice, message)

    # Bob should be able to write to file_a.txt.
    log.info("--- %s writes %s ---", bob.name, path)
    message = {
        "user": bob.name,
        "action": "write",
        "data": f" Written by {bob.name}.",
        "path": path,
    }
    server.exchange(channel, bob, message)

    # Carl should be able to read from file_a.txt.
    log.info("--- %s reads %s ---", carl.name, path)
    message = {
        "user": carl.name,
        "action": "read",
        "path": path,
    }
    server.exchange(channel, carl, message)


if __name__ == "__main__":
    main()
