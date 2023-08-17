from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import mergedeep
import yaml
from dataclass_wizard import asdict, fromdict

from yardstick import artifact
from yardstick.store import config as store_config

DEFAULT_CONFIGS = (
    ".yardstick.yaml",
    "yardstick.yaml",
)


@dataclass()
class Profiles:
    data: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def get(self, tool_name: str, profile: str):
        return self.data.get(tool_name, {}).get(profile, {})


@dataclass()
class Tool:
    name: str
    version: str
    label: Optional[str] = None
    produces: Optional[str] = None
    takes: Optional[str] = None
    profile: Optional[str] = None
    refresh: bool = True

    @property
    def short(self):
        return f"{self.name}@{self.version}"


@dataclass()
class ScanMatrix:
    images: list[str] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)

    def __post_init__(self):
        for idx, tool in enumerate(self.tools):
            self.tools[idx].name, self.tools[idx].version = artifact.ScanRequest.render_tool(tool.short).split("@", 1)

        # flatten elements in images (in case yaml anchores are used)
        images = []
        for image in self.images:
            if isinstance(image, list):
                images += image
            if image.startswith("["):
                # technically yaml anchors to lists of lists are interpreted as strings... which is terrible
                images += yaml.safe_load(image)
            else:
                images += [image]
        self.images = images


@dataclass()
class ResultSet:
    description: str = ""
    declared: list[artifact.ScanRequest] = field(default_factory=list)
    matrix: ScanMatrix = field(default_factory=ScanMatrix)

    def images(self) -> list[str]:
        return self.matrix.images + [req.image for req in self.declared]

    def scan_requests(self) -> list[artifact.ScanRequest]:
        rendered = []
        for image in self.matrix.images:
            for tool in self.matrix.tools:
                rendered.append(
                    artifact.ScanRequest(
                        image=image,
                        tool=tool.short,
                        label=tool.label,
                        profile=tool.profile,
                        provides=tool.produces,
                        takes=tool.takes,
                        refresh=tool.refresh,
                    )
                )
        return self.declared + rendered


@dataclass()
class Application:
    store_root: str = store_config.DEFAULT_STORE_ROOT
    profile_path: str = ".yardstick.profiles.yaml"
    profiles: Profiles = field(default_factory=Profiles)
    result_sets: dict[str, ResultSet] = field(default_factory=dict)
    default_max_year: Optional[int] = None
    derive_year_from_cve_only: bool = False


def clean_dict_keys(d):
    new = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = clean_dict_keys(v)
        new[k.replace("-", "_")] = v
    return new


def yaml_decoder(data) -> Dict[Any, Any]:
    return clean_dict_keys(yaml.safe_load(data))


def load(
    path: None | str | list[str] | tuple[str] = DEFAULT_CONFIGS,
) -> Application:
    cfg = _load_paths(path)

    if not cfg:
        msg = "no config found"
        raise RuntimeError(msg)

    if cfg.profile_path:
        try:
            with open(cfg.profile_path, encoding="utf-8") as yaml_file:
                profile = Profiles(yaml_decoder(yaml_file))
        except:  # pylint: disable=bare-except
            profile = Profiles({})
        cfg.profiles = profile

    return cfg


def _load_paths(
    path: None | str | list[str] | tuple[str],
) -> Application | None:
    if not path:
        path = DEFAULT_CONFIGS

    if isinstance(path, str):
        if path == "":
            path = DEFAULT_CONFIGS
        else:
            return _load(path)

    if isinstance(path, (list, tuple)):
        for p in path:
            if not os.path.exists(p):
                continue

            return _load(p)

        # use the default application config
        return Application()

    msg = f"invalid path type {type(path)}"
    raise ValueError(msg)


def _load(path: str) -> Application:
    with open(path, encoding="utf-8") as f:
        app_object = yaml.load(f.read(), yaml.SafeLoader) or {}  # noqa: S506 (since our loader is using the safe loader)
        # we need a full default application config first then merge the loaded config on top.
        # Why? dataclass_wizard.fromdict() will create instances from the dataclass default
        # and NOT the field definition from the container. So it is possible to specify a
        # single field in the config and all other fields would be set to the default value
        # based on the dataclass definition and not any field(default_factory=...) hints
        # from the containing class.
        instance = asdict(Application())

        mergedeep.merge(instance, app_object)
        cfg = fromdict(
            Application,
            instance,
        )

    if cfg is None:
        msg = "parsed empty config"
        raise FileNotFoundError(msg)

    return cfg
