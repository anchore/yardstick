import json
from dataclasses import InitVar, dataclass, field
from typing import Any, Dict, Optional

import yaml
from mashumaro.mixins.yaml import DataClassYAMLMixin

from yardstick import artifact
from yardstick.store import config as store_config


@dataclass()
class Profiles(DataClassYAMLMixin):
    data: InitVar[Dict[str, Dict[str, str]]] = None

    def __init__(self, data: Dict[str, Dict[str, str]] = None):
        if not data:
            data = {}
        self.data = data

    def get(self, tool_name: str, profile: str):
        return self.data.get(tool_name, {}).get(profile, {})


@dataclass()
class Tool(DataClassYAMLMixin):
    name: str
    version: str
    produces: Optional[str] = None
    takes: Optional[str] = None
    profile: Optional[str] = None
    refresh: bool = True

    @property
    def short(self):
        return f"{self.name}@{self.version}"


@dataclass()
class ScanMatrix(DataClassYAMLMixin):
    images: list[str] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)

    def __post_init__(self):
        for idx, tool in enumerate(self.tools):
            self.tools[idx].name, self.tools[idx].version = artifact.ScanRequest.render_tool(tool.short).split("@")

        # flatten elements in images (in case yaml anchores are used)
        images = []
        for image in self.images:
            if isinstance(image, list):
                images += image
            else:
                images += [image]
        self.images = images


@dataclass()
class ResultSet(DataClassYAMLMixin):
    description: str = ""
    declared: list[artifact.ScanRequest] = field(default_factory=list)
    matrix: ScanMatrix = field(default_factory=ScanMatrix)

    def scan_requests(self) -> list[artifact.ScanRequest]:
        rendered = []
        for image in self.matrix.images:
            for tool in self.matrix.tools:
                rendered.append(
                    artifact.ScanRequest(
                        image=image,
                        tool=tool.short,
                        profile=tool.profile,
                        provides=tool.produces,
                        takes=tool.takes,
                        refresh=tool.refresh,
                    )
                )
        return self.declared + rendered


@dataclass()
class Application(DataClassYAMLMixin):
    store_root: str = store_config.DEFAULT_STORE_ROOT
    profile_path: str = ".yardstick.profiles.yaml"
    profiles: Profiles = field(default_factory=Profiles)
    result_sets: dict[str, ResultSet] = field(default_factory=dict)
    default_max_year: Optional[int] = None


def clean_dict_keys(d):
    new = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = clean_dict_keys(v)
        new[k.replace("-", "_")] = v
    return new


def yaml_decoder(data) -> Dict[Any, Any]:
    return clean_dict_keys(yaml.load(data, yaml.CSafeLoader))


def load(path: str = ".yardstick.yaml") -> Application:
    try:
        with open(path, encoding="utf-8") as f:
            cfg: Application = Application.from_yaml(f.read(), decoder=yaml_decoder)
    except FileNotFoundError:
        cfg: Application = Application()

    if cfg.profile_path:
        try:
            with open(cfg.profile_path, encoding="utf-8") as json_file:
                profile = Profiles(json.load(json_file))
        except:  # pylint: disable=bare-except
            profile = Profiles({})
        cfg.profiles = profile

    return cfg
