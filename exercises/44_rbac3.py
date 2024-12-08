# Implement a Role-Based Access Control (RBAC) scheme with role hierarchies and prerequisite roles.
# Directives:
#
# - Assume that all users are already authenticated.
# - The scheme should support the concept of roles, role assignments, and sessions.
# - Users may have multiple roles.
# - No explicit access rights are required to start and end sessions: anyone can do it.
# - Roles are as follows:
#   - "reader" can read the log file.
#   - "writer" can write to the log file.
#   - "editor" inherits from "reader" and "writer" and has no additional rights.
#   - "admin" inherits from "editor", and can assign and unassign any role.
# - The rule on role prerequisites is as follows:
#   - A role can only be assigned if all of its parent roles are already assigned to the user.
#   - A role can only be unassigned if the user has none of its child roles assigned.
# - Initial role assignments are as follows:
#   - Admin: admin, editor, writer, reader
#   - Service A: writer
#   - Service B: reader
# - Make sure to implement reasonable defaults.
#
# Hint: start from the implementation of the previous exercise and add the necessary new features.

from __future__ import annotations

from issp import Actor, Channel, FileServer, JSONMessage, log


class Role:
    @property
    def rights(self) -> set[str]:
        rights = set(self.own_rights)
        for parent in self.parents:
            rights |= parent.rights
        return rights

    def __init__(
        self,
        name: str,
        rights: set[str] | None = None,
        parents: set[Role] | None = None,
    ) -> None:
        self.name = name
        self.own_rights = rights or set()
        self.parents = parents or set()
        self.children: set[Role] = set()

        for parent in self.parents:
            parent.children.add(self)


class Server(FileServer):
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self.handlers["start_session"] = self.start_session
        self.handlers["end_session"] = self.end_session
        self.handlers["assign_role"] = self.assign_role
        self.handlers["unassign_role"] = self.unassign_role

        self.file_data["logfile.txt"] = b"This is the log file."

        # Add any necessary state.

    def authorize(self, user: str, file: str, action: str) -> bool:
        # Implement.
        return False

    def start_session(self, msg: JSONMessage) -> JSONMessage:
        # Implement.
        return {"status": "success"}

    def end_session(self, msg: JSONMessage) -> JSONMessage:
        # Implement.
        return {"status": "success"}

    def assign_role(self, msg: JSONMessage) -> JSONMessage:
        # Implement.
        return {"status": "success"}

    def unassign_role(self, msg: JSONMessage) -> JSONMessage:
        # Implement.
        return {"status": "success"}


def main() -> None:
    admin = Actor("Admin")
    service_a = Actor("Service A")
    service_b = Actor("Service B")
    server = Server("Server")
    channel = Channel()

    # Session creation.

    for client, roles in (
        (admin, ["admin"]),  # This should succeed.
        (service_a, ["editor"]),  # This should fail.
        (service_a, ["writer"]),  # This should succeed.
        (service_b, ["reader"]),  # This should succeed.
    ):
        log.info("--- %s creates session ---", client)
        message = {"action": "start_session", "user": client.name, "roles": roles}
        server.exchange(channel, client, message)

    # Role assignment.

    # Only Admin should be able to assign roles, though in this case
    # role assignment should fail due to a prerequisite failure.
    for client in (service_a, admin):
        log.info("--- %s assigns role ---", client)
        message = {
            "action": "assign_role",
            "user": client.name,
            "target": service_b.name,
            "role": "editor",
        }
        server.exchange(channel, client, message)

    # The following role assignments should succeed.
    for role in ("writer", "editor"):
        log.info("--- %s assigns role ---", admin)
        message = {
            "action": "assign_role",
            "user": admin.name,
            "target": service_b.name,
            "role": role,
        }
        server.exchange(channel, admin, message)

    # Drop privileges.

    log.info("--- %s starts session ---", admin)
    message = {"action": "start_session", "user": admin.name, "roles": ["editor"]}
    server.exchange(channel, admin, message)

    # The following role assignment should fail.
    log.info("--- %s assigns role ---", admin)
    message = {
        "action": "assign_role",
        "user": admin.name,
        "target": service_a.name,
        "role": "editor",
    }
    server.exchange(channel, admin, message)

    # Read and write operations.
    # These should respect session roles.

    path = "logfile.txt"
    clients = (admin, service_a, service_b)

    for client in clients:
        log.info("--- %s writes ---", client)
        message = {
            "user": client.name,
            "action": "write",
            "data": f" Written by {client}.",
            "path": path,
        }
        server.exchange(channel, client, message)

    for client in clients:
        log.info("--- %s reads ---", client)
        message = {"user": client.name, "action": "read", "path": path}
        server.exchange(channel, client, message)


if __name__ == "__main__":
    main()
