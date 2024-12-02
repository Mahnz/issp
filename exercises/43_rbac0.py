# Implement a basic Role-Based Access Control (RBAC) scheme. Directives:
#
# - Assume that all users are already authenticated.
# - The scheme should support the concept of roles, role assignments, and sessions.
# - Users may have multiple roles.
# - No explicit access rights are required to start and end sessions: anyone can do it.
# - Roles are as follows: "reader" can read the log file, "writer" can write to it,
#   "admin" can assign and unassign the "reader" and "writer" roles.
# - Initial role assignments are as follows:
#   - Admin: admin, writer, reader
#   - Service A: writer, reader
#   - Service B: reader
# - Make sure to implement reasonable defaults.

from issp import Actor, Channel, FileServer, JSONMessage, log


class Role:
    def __init__(self, name: str, rights: set[str]) -> None:
        self.name = name
        self.rights = rights


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
        (admin, ["admin", "writer", "reader"]),
        (service_a, ["writer", "reader"]),
        (service_b, ["reader"]),
    ):
        log.info("--- %s creates session ---", client)
        message = {"action": "start_session", "user": client.name, "roles": roles}
        server.exchange(channel, client, message)

    # Read and write operations.

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

    # Role assignment.

    for client in (service_a, admin):
        log.info("--- %s assigns role ---", client)
        message = {
            "action": "assign_role",
            "user": client.name,
            "target": service_b.name,
            "role": "writer",
        }
        server.exchange(channel, client, message)

    # Check if Service B can read / write.

    log.info("--- %s creates session ---", service_b.name)
    message = {"action": "start_session", "user": service_b.name, "roles": ["writer"]}
    server.exchange(channel, service_b, message)

    log.info("--- %s writes ---", service_b)
    message = {
        "user": service_b.name,
        "action": "write",
        "data": f" Written by {service_b}.",
        "path": path,
    }
    server.exchange(channel, service_b, message)

    log.info("--- %s reads ---", service_b.name)
    message = {"user": service_b.name, "action": "read", "path": path}
    server.exchange(channel, service_b, message)


if __name__ == "__main__":
    main()
