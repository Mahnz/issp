# Implement a signature-based malware scanner. Directives:
#
# - The scanner must be able to detect all the malware variants created in the previous exercises.
# - Detected malware should be quarantined by moving it to the "/quarantine" directory.
# - To avoid overwriting infected files with identical names, the quarantine directory
#   should mirror the structure of the root directory.
#
# Hint: use the re module to search for malware signatures using regular expressions.
# Hint: it is a good idea to avoid scanning the quarantine directory and the scanner itself.
#
# Note: follow the instructions in "utils/create_fs.py"

import re

from issp import Path, System, log


def main() -> None:
    system = System()
    quarantine_dir = system.path("/quarantine")

    # Malware variant -> signature.
    signatures = {
        "FileDeleterStorageWorm": re.compile(b"DeleteFiles().*StorageWorm()"),
        "ScarewarePyVirus": re.compile(b"Scareware().*PyVirus()"),
        "RansomwareStorageWorm": re.compile(b"Ransomware().*StorageWorm()"),
    }

    # Path -> malware variant.
    detections: dict[Path, str] = {}

    for path in system.path("/").walk():
        # Skip quarantine dir.
        if path.starts_with(quarantine_dir):
            continue

        # Skip non-Python files.
        if not (path.is_file() and path.name.endswith(".py")):
            continue

        # Skip self.
        if path == system.own_path:
            continue

        # Check for malware signatures.
        code = path.read_bytes()
        for name, signature in signatures.items():
            if signature.search(code):
                detections[path] = name
                break

    if not detections:
        log.info("No malware detected.")
        return

    log.info("Malware detected:")
    quarantine_dir.mkdir()

    for path, name in detections.items():
        log.info("%s: %s", name, path)
        quarantine_path = quarantine_dir / path
        quarantine_path.parent.mkdir()
        path.move(quarantine_path)


if __name__ == "__main__":
    main()
