from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Sequence

import mergedeep  # type: ignore[import]
import re
import yaml
from dataclass_wizard import asdict, fromdict  # type: ignore[import]

from yardstick import artifact, validate
from yardstick.store import config as store_config

DEFAULT_CONFIGS = (
    ".yardstick.yaml",
    "yardstick.yaml",
)


@dataclass()
class Profiles:
    data: dict[str, dict[str, str]] = field(default_factory=dict)

    def get(self, tool_name: str, profile: str):
        return self.data.get(tool_name, {}).get(profile, {})


@dataclass()
class Tool:
    name: str
    version: str
    label: str | None = None
    produces: str | None = None
    takes: str | None = None
    profile: str | None = None
    refresh: bool = True

    @property
    def short(self):
        return f"{self.name}@{self.version}"


@dataclass()
class ScanMatrix:
    images: list[str] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)

    DIGEST_REGEX = re.compile(r"(?P<digest>sha256:[a-fA-F0-9]{64})")

    def __post_init__(self):
        for idx, tool in enumerate(self.tools):
            (
                self.tools[idx].name,
                self.tools[idx].version,
            ) = artifact.ScanRequest.render_tool(tool.short).split("@", 1)

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
        invalid = [
            image for image in images if not ScanMatrix.is_valid_oci_reference(image)
        ]
        if invalid:
            raise ValueError(
                f"all images must be complete OCI references, but {' '.join(invalid)} are not"
            )

    @staticmethod
    def is_valid_oci_reference(image: str) -> bool:
        host, _, repository, _, digest = ScanMatrix.parse_oci_reference(image)
        return (
            all([host, repository, digest])
            and bool(ScanMatrix.DIGEST_REGEX.match(digest or ""))
            and ("." in host or "localhost" in host)
        )

    @staticmethod
    def parse_oci_reference(image: str) -> tuple[str, str, str, str, str]:
        host = ""
        path = ""
        host_and_path = ""
        repository = ""
        tag = ""
        digest = ""

        if "@" in image:
            pre_digest, digest = image.rsplit("@", 1)
        else:
            pre_digest = image

        if ":" in pre_digest:
            pre_tag, tag = pre_digest.rsplit(":", 1)
        else:
            pre_tag = pre_digest

        if "/" in pre_tag:
            host_and_path, repository = pre_tag.rsplit("/", 1)
        else:
            repository = pre_tag

        if host_and_path:
            parts = host_and_path.split("/")
            host = parts[0]
            path = "/".join(parts[1:]) if len(parts) > 1 else ""

        return host, path, repository, tag, digest


@dataclass()
class Validation(validate.GateConfig):
    name: str = "default"


@dataclass()
class ResultSet:
    description: str = ""
    declared: list[artifact.ScanRequest] = field(default_factory=list)
    matrix: ScanMatrix = field(default_factory=ScanMatrix)
    validations: list[Validation] = field(default_factory=list)

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
                    ),
                )
        return self.declared + rendered


@dataclass()
class Application:
    store_root: str = store_config.DEFAULT_STORE_ROOT
    profile_path: str = ".yardstick.profiles.yaml"
    profiles: Profiles = field(default_factory=Profiles)
    result_sets: dict[str, ResultSet] = field(default_factory=dict)
    default_max_year: int | None = None
    derive_year_from_cve_only: bool = False

    def max_year_for_any_result_set(self, result_sets: list[str]) -> int | None:
        years = []
        for result_set in result_sets:
            m = self.max_year_for_result_set(result_set)
            if m is not None:
                years.append(m)

        if not years:
            return None

        return max(years)

    def max_year_for_result_set(self, result_set: str) -> int | None:
        """return the max year needed by any validation on the result set, or default_max_year"""
        rs = self.result_sets.get(result_set, None)
        years = []
        if rs is not None:
            for gate in rs.validations:
                if gate.max_year is not None:
                    years.append(gate.max_year)
                elif self.default_max_year is not None:
                    years.append(self.default_max_year)

        if years:
            return max(years)

        return self.default_max_year


def clean_dict_keys(d):
    new = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = clean_dict_keys(v)
        new[k.replace("-", "_")] = v
    return new


def yaml_decoder(data) -> dict[Any, Any]:
    return clean_dict_keys(yaml.safe_load(data))


def load(
    path: str | Sequence[str] = DEFAULT_CONFIGS,
) -> Application:
    cfg = _load_paths(path)

    if not cfg:
        msg = "no config found"
        raise RuntimeError(msg)

    if cfg.profile_path:
        try:
            with open(cfg.profile_path, encoding="utf-8") as yaml_file:
                profile = Profiles(yaml_decoder(yaml_file))
        except FileNotFoundError:
            profile = Profiles({})
        cfg.profiles = profile

    return cfg


def _load_paths(
    path: str | Sequence[str],
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
        app_object = (
            yaml.load(f.read(), yaml.SafeLoader) or {}
        )  # noqa: S506 (since our loader is using the safe loader)
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
