from typing import Optional, Union

from .grype import Grype
from .plugin import load_plugins
from .sbom_generator import SBOMGenerator
from .syft import Syft
from .vulnerability_scanner import VulnerabilityScanner

tools = {
    # vulnerability scanners
    "grype": Grype,
    # sbom generators
    "syft": Syft,
}


def Register(name: str, tool: Union[SBOMGenerator, VulnerabilityScanner]) -> None:
    tools[name] = tool


def get_tool(name: str) -> Optional[Union[SBOMGenerator, VulnerabilityScanner]]:
    # this normalizes the name and removes labels in [brackets]
    return tools.get(name.split("[")[0].lower())


load_plugins()
