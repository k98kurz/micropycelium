"""Mock for micropython optimization decorator."""

def native(fn):
    return fn

def const(anything):
    return anything
