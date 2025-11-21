# ui/types.py

from typing import Protocol


class LogEmitterType(Protocol):
    def message(self, text: str, tag: str) -> None: ...
