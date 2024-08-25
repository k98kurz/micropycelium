"""Mock for machine micropython module."""
from os import urandom
from time import sleep

def unique_id() -> bytes:
    return urandom(32)

def lightsleep(ms):
    sleep(ms/1000)
