"""Mock for micropython network module."""

STA_IF = 0
STA_AP = 1

class WLAN:
    def __init__(self, id: int = 0) -> None:
        self.id = id
        self._status = False
        self._conf = {}

    def active(self, status: bool = None) -> bool:
        if status is not None:
            self._status = status
        return self._status

    def disconnect(self):
        return

    def config(self, param: str = None, **kwargs):
        if param:
            return self._conf.get(param, None)
        for k, v in kwargs.items():
            self._conf[k] = v
        return
