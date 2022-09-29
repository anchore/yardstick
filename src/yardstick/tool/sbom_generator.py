import abc
from typing import List, Optional

from yardstick import artifact


class SBOMGenerator(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def install(version: str, path: Optional[str] = None, **kwargs) -> "SBOMGenerator":
        raise NotImplementedError

    @abc.abstractmethod
    def capture(self, image: str) -> str:
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def parse(result: str, config: artifact.ScanConfiguration) -> tuple[str, List[artifact.Package]]:
        raise NotImplementedError
