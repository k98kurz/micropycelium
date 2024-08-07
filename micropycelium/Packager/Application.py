from .Packager import Packager, Package
from hashlib import sha256

class Application:
    packager: Packager

    def __init__(self, name: str, description: str) -> None:
        app_id = sha256((name + description).encode()).digest()[:16]

    # def deliver(self, )