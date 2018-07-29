from typing import IO


class Encrypt:
    def __init__(self, key: bytes) -> None:
        self.public_key = key

    @classmethod
    def from_public_key(cls, key: bytes) -> "Encrypt":
        return cls(key)

    @classmethod
    def from_public_key_file(cls, key_file: IO) -> "Encrypt":
        return cls.from_public_key(key_file.read())

    @classmethod
    def from_public_key_path(cls, key_path: str) -> "Encrypt":
        with open(key_path, "rb") as key_file:
            return cls.from_public_key_file(key_file)

    def __eq__(self, other: "Encrypt") -> bool:
        return bool(type(self) is type(other) and self.public_key == other.public_key)


class Decrypt:
    def __init__(self, private_key: bytes) -> None:
        self.private_key = private_key

    @classmethod
    def from_private_key(cls, key: bytes) -> "Decrypt":
        return cls(key)

    @classmethod
    def from_private_key_file(cls, key_file: IO) -> "Decrypt":
        return cls.from_private_key(key_file.read())

    @classmethod
    def from_private_key_path(cls, key_path: str) -> "Decrypt":
        with open(key_path, "rb") as key_file:
            return cls.from_private_key_file(key_file)

    def __eq__(self, other: "Decrypt") -> bool:
        return bool(type(self) is type(other) and self.private_key == other.private_key)
