"""Mock for machine micropython module."""
from os import urandom
from time import sleep

def unique_id() -> bytes:
    return urandom(32)

def lightsleep(ms):
    sleep(ms/1000)

class Pin:
    _val: int
    _mode: int
    IN = 1
    OUT = 3
    def __init__(self, num: int, mode: int = 1) -> None:
        self._val = 0
        self._mode = mode
        pass

    def value(self, val: int = None):
        if val is None:
            return self._val
        self._val = val
