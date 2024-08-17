"""Mock for micropython optimization decorator."""

def native(fn):
    return fn

def _const(anything):
    return anything
