from cryptozero.key import stretch


class Encrypt:
    def __init__(self, key: bytes) -> None:
        self.key = key

    @classmethod
    def from_password(cls, password: str) -> 'Encrypt':
        key = stretch(password)
        return cls.from_key(key)

    @classmethod
    def from_key(cls, key: bytes) -> 'Encrypt':
        return cls(key)

    def __eq__(self, other: 'Encrypt') -> bool:
        return bool(
            type(self) is type(other)
            and self.key == other.key
        )


class Decrypt:
    def __init__(self, key: bytes) -> None:
        self.key = key

    @classmethod
    def from_password(cls, password: str) -> 'Decrypt':
        key = stretch(password)
        return cls.from_key(key)

    @classmethod
    def from_key(cls, key: bytes) -> 'Decrypt':
        return cls(key)

    def __eq__(self, other: 'Decrypt') -> bool:
        return bool(
            type(self) is type(other)
            and self.key == other.key
        )
