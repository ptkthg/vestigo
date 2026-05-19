from abc import ABC, abstractmethod
from ..schemas import EventoContext


class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw: str) -> EventoContext:
        """Recebe log bruto, retorna EventoContext parcialmente preenchido."""
        ...
