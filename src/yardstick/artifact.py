import collections
import datetime
import functools
import getpass
import hashlib
import json
import os
import re
import subprocess
import uuid
from dataclasses import InitVar, asdict, dataclass, field
from enum import Enum
from typing import Any

from dataclasses_json import config, dataclass_json

from yardstick.utils import grype_db, is_cve_vuln_id, parse_year_from_id


def get_image_digest(image: str) -> str:
    result = subprocess.run(
        ["docker", "manifest", "inspect", image],
        stdout=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"failed to get image digest for {image}")
    obj = json.loads(result.stdout)
    digest = obj.get("config", {}).get("digest", "")
    if digest:
        return digest
    for manifest in obj.get("manifests", []):
        if manifest.get("platform", {}) != {"architecture": "amd64", "os": "linux"}:
            continue
        digest = manifest.get("digest", "")
        if digest:
            return digest
    raise RuntimeError(f"no image digest found for {image}")


@dataclass(frozen=True, eq=True)
class Tool:
    tool: str
    name: str | None = field(init=False)
    version: str = field(init=False)
    label: str = None

    def __post_init__(self):
        name, version = self.tool.split("@", 1)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)

    def __str__(self):
        return self.id_version

    @property
    def id_version(self):
        return f"{self.id}@{self.version}"

    @property
    def id(self):  # noqa: A003
        if self.label:
            return f"{self.name}[{self.label}]"
        return self.name

    def __lt__(self, other):
        if not isinstance(other, Tool):
            return NotImplemented
        return self.id < other.id


@dataclass()
class Image:
    image: str
    repository: str = field(init=False)
    tag: str = field(init=False)
    digest: str = field(init=False)

    def __post_init__(self):
        digest = ""
        repo = self.image
        if "@" in repo:
            repo, digest = repo.split("@", 1)

        tag = ""
        if ":" in repo:
            repo, tag = repo.split(":", 1)

        self.repository = repo
        self.tag = tag
        self.digest = digest

    @property
    def repository_encoded(self) -> str:
        return self.repository.replace("/", "+")

    @property
    def encoded(self) -> str:
        return f"{self.repository_encoded}@{self.digest}"

    def is_like(self, other: str) -> bool:
        other_obj = Image(other)
        if self.repository != other_obj.repository:
            return False
        if self.tag and other_obj.tag and self.tag != other_obj.tag:
            return False
        if self.digest and other_obj.digest and self.digest != other_obj.digest:
            return False
        return True


# note: this dataclass cannot be modified as it is used in Match.id and responsible for accessing previously stored results.
# note: we cannot freeze this class since the tool installation may add additional metadata
@dataclass_json
@dataclass(frozen=False, eq=True, order=True)
class ScanConfiguration:
    image_repo: str
    image_digest: str
    tool_name: str
    tool_version: str
    tool_label: str | None = None
    image_tag: str = ""
    timestamp: datetime.datetime | None = field(
        default=None,
        metadata=config(
            encoder=lambda dt: dt.isoformat(),
            decoder=datetime.datetime.fromisoformat,
        ),
    )
    tool_input: str | None = None
    detail: dict[str, dict | str] = field(default_factory=dict)
    ID: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        self.image_repo = self.image_repo.replace("+", "/")

    @property
    def path(self):
        return f"{self.image_repo}@{self.image_digest}/{self.tool}/{self.timestamp_rfc3339}"

    @property
    def tool(self):
        return f"{self.tool_name}@{self.tool_version}"

    @property
    def encoded_path(self):
        return f"{self.image_encoded}/{self.tool}/{self.timestamp_rfc3339}"

    @property
    def image_repo_encoded(self) -> str:
        return self.image_repo.replace("/", "+")

    @property
    def timestamp_rfc3339(self) -> str:
        return self.timestamp.isoformat() if self.timestamp else ""

    @property
    def image(self):
        return f"{self.image_repo}@{self.image_digest}"

    @property
    def full_image(self):
        if self.image_tag == "":
            return self.image

        return f"{self.image_repo}:{self.image_tag}@{self.image_digest}"

    @property
    def image_encoded(self):
        return f"{self.image_repo_encoded}@{self.image_digest}"

    def __str__(self):
        s = f"""\
image:\t\t{self.image_repo}{':'+self.image_tag if self.image_tag else ''}@{self.image_digest}
tool:\t{self.tool}"""
        if self.timestamp:
            s += f"\ntimestamp:\t{self.timestamp}"
        return s

    @staticmethod
    def new(
        image: str | None = None,
        tool: str | None = None,
        path: str | None = None,
        timestamp: datetime.datetime | None = None,
        label: str | None = None,
    ):
        if tool:
            tool_obj = Tool(tool, label=label)

        if image:
            img = Image(image)
            if img.digest == "":
                img.digest = get_image_digest(image)

        if path:
            image_and_digest, tool_and_version, timestamp_str = path.rsplit("/", 2)
            tool_obj = Tool(tool_and_version)
            timestamp = datetime.datetime.fromisoformat(timestamp_str)
            img = Image(image_and_digest)

        return ScanConfiguration(
            image_repo=img.repository,
            image_digest=img.digest,
            image_tag=img.tag,
            tool_name=tool_obj.id,
            tool_version=tool_obj.version,
            timestamp=timestamp,
            tool_label=label,
        )


@dataclass(frozen=True, eq=True, order=True)
class ScanMetadata:
    timestamp: datetime.datetime | None = field(
        default=None,
        metadata=config(
            encoder=lambda dt: dt.isoformat(),
            decoder=datetime.datetime.fromisoformat,
        ),
    )
    elapsed: float | None = field(default=None)
    image_digest: str | None = field(default=None)


@dataclass(frozen=True, eq=True, order=True)
class Package:
    name: str
    version: str

    def __repr__(self):
        return f"{self.name}@{self.version}"


@dataclass(frozen=True, eq=True, order=True)
class Vulnerability:
    id: str  # noqa: A003
    cve_id: str | None = field(default=None, hash=False)

    def __post_init__(self):
        if is_cve_vuln_id(self.id) and not self.cve_id:
            object.__setattr__(self, "cve_id", self.id)

    def _get_cve(self):
        cve = grype_db.normalize_to_cve(self.id)
        if is_cve_vuln_id(cve):
            return cve
        return None

    def _effective_cve_year(self) -> int | None:
        cve = self.cve_id
        if not cve:
            # this is rather expensive, so try this last
            cve = self._get_cve()
        if not cve:
            return None
        return parse_year_from_id(cve)

    def effective_year(self, by_cve=False) -> int | None:
        if by_cve:
            return self._effective_cve_year()
        candidate: int | str | None = self.id
        if self.id:
            candidate = parse_year_from_id(self.id)
        if not isinstance(candidate, int):
            candidate = self._effective_cve_year()
        if isinstance(candidate, int):
            return candidate
        return None


class DTEncoder(json.JSONEncoder):
    def default(self, o):
        # if passed in object is datetime object convert it to a string
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        # otherwise use the default behavior
        return json.JSONEncoder.default(self, o)


# note: cannot use order=True since lt/gt/etc require not including the fullentry dict
@dataclass_json
@dataclass(frozen=True)
class Match:
    vulnerability: Vulnerability
    package: Package
    fullentry: dict[str, Any] | None = field(default=None, hash=False)
    config: ScanConfiguration | None = field(default=None, hash=False)
    ID: str = field(init=False, hash=False)

    def __post_init__(self):
        identifier = {
            "output": self.fullentry,
            "configuration": None,
        }
        if self.config:
            identifier["configuration"] = sorted(
                asdict(self.config).items(),
            )

        # note on S324 usage: we are not using these IDs for crytographic purposes, only
        # for having simple content-sensitive IDs for use for match comparison.
        match_id = hashlib.md5(  # noqa: S324
            json.dumps(identifier, sort_keys=True, cls=DTEncoder).encode(),
        ).hexdigest()

        object.__setattr__(self, "ID", match_id)

    def __eq__(self, other: Any) -> bool:
        return hash(self) == hash(other)

    def __repr__(self) -> str:
        # note: fullentry is excluded
        return f"Match(vulnerability={self.vulnerability.id!r} {self.package!r} id={self.ID!r})"

    def __lt__(self, other: Any) -> bool:
        # don't compare the full entry
        if self.package.name.lower() != other.package.name.lower():
            return self.package.name.lower() < other.package.name.lower()

        if self.vulnerability.id.lower() != other.vulnerability.id.lower():
            return self.vulnerability.id.lower() < other.vulnerability.id.lower()

        if self.package.version != other.package.version:
            return self.package.version < other.package.version

        if (
            self.config
            and other.config
            and self.package.version != other.package.version
        ):
            return self.package.version < other.package.version
        return False


@dataclass_json
@dataclass(frozen=False, eq=True, order=True)
class ScanResult:
    config: ScanConfiguration
    matches: list[Match] | None = field(default=None)
    packages: list[Package] | None = field(default=None)
    metadata: ScanMetadata | None = field(default=None)

    @property
    def ID(self):
        return self.config.ID

    def __post_init__(self):
        if self.matches is None and self.packages is None:
            raise RuntimeError("must have at either matches or packages (or both)")


class Label(Enum):
    TruePositive = "TP"
    FalsePositive = "FP"
    Unclear = "??"

    def __init__(self, display: str):
        self.display = display

    @staticmethod
    def encode(label):
        return label.display

    @staticmethod
    def decode(val):
        return Label.from_str(val)

    @staticmethod
    def from_str(text: str):
        text = text.lower()
        if text in ("tp", "true", "truepositive", "true-positive"):
            return Label.TruePositive
        if text in ("fp", "false", "falsepositive", "false-positive"):
            return Label.FalsePositive
        if text in (
            "unclear",
            "uncertain",
            "indeterminate",
            "dunno",
            "?",
            "??",
            "?!",
            r"¯\_(ツ)_/¯",
        ):
            return Label.Unclear
        return None


@dataclass_json
@dataclass(frozen=True, eq=True, order=True)
class ImageSpecifier:
    exact: str | None = None
    regex: str | None = None
    prefix: str | None = None
    suffix: str | None = None

    def matches_image(self, image: str):
        if not self.exact and not self.regex and not self.prefix and not self.suffix:
            # if the specification is empty then any image matches automatically
            return True
        if self.exact and image == self.exact:
            return True

        if self.prefix and image.startswith(self.prefix):
            return True

        if self.suffix and image.endswith(self.suffix):
            return True

        if self.regex and re.match(self.regex, image):
            return True
        return False

    def __repr__(self):
        result = ""
        if self.exact:
            result += self.exact

        if self.regex:
            result += f" regex={self.regex!r}"

        if self.prefix:
            result += f" prefix={self.prefix!r}"

        if self.suffix:
            result += f" suffix={self.suffix!r}"

        return result


@dataclass_json
@dataclass(eq=True, order=True)
class LabelEntry:
    # label: Label
    label: Label = field(
        metadata=config(
            encoder=Label.encode,
        ),
    )  # TP/FP/Unclear indication (required)
    vulnerability_id: str  # the CVE ID (required)
    image: ImageSpecifier | None = None  # image specifier
    note: str | None = None  # a general comment field (optional)
    source: str | None = None  # e.g. manually added, import, etc. (optional)
    effective_cve: str | None = (
        None  # the CVE the vulnerability ID matches to (optional)
    )
    user: str | None = None  # the user that added this label (optional)
    package: Package | None = None  # package name/version
    fullentry_fields: list[str] = field(
        default_factory=list,
    )  # values that must be found in the full_entry field on the match object
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(tz=datetime.timezone.utc),
        metadata=config(
            encoder=lambda dt: dt.isoformat(),
            decoder=datetime.datetime.fromisoformat,
        ),
    )
    tool: str | None = None  # used to indicate the tool that first saw this label
    lookup_effective_cve: InitVar[bool] = False

    ID: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self, lookup_effective_cve: bool):
        if not self.user:
            self.user = getpass.getuser()
        if lookup_effective_cve and not self.effective_cve:
            self.effective_cve = self._get_cve()

    def __str__(self):
        return f"""\
label: {self.label.name}
vulnerability: {self.vulnerability_id}
package: {self.package}
user: {self.user}
image: {self.image}
number of fullentry_fields: {len(self.fullentry_fields)}
timestamp: {self.timestamp.isoformat()}
id: {self.ID}
"""

    def __hash__(self) -> int:
        # dont include user, ID, or datetime
        return hash(
            (
                self.vulnerability_id,
                self.source,
                self.image,
                self.package,
                self.note,
                # note: we cannot depend on the dataclasses generated hash since fullentry_fields must be hashable
                tuple(sorted(self.fullentry_fields)),
            ),
        )

    def __eq__(self, other: Any) -> bool:
        return hash(self) == hash(other)

    def matches_image(self, image: str | None):
        if not self.image or not image:
            # if no imag specifier is provided, then any image matches automatically
            return True
        return self.image.matches_image(image)

    def summarize(self):
        return f"[{self.ID}] {self.label.name} claim {self.vulnerability_id} on package {self.package or '(any package)'} for {self.image}"

    def _get_cve(self):
        cve = grype_db.normalize_to_cve(self.vulnerability_id)
        if is_cve_vuln_id(cve):
            return cve
        return None

    def _effective_cve_year(self) -> int | None:
        cve = self.effective_cve
        if not cve:
            # this is rather expensive, so try this last
            cve = self._get_cve()
        if not cve:
            return None
        return parse_year_from_id(cve)

    def effective_year(self, by_cve=False) -> int | None:
        if by_cve:
            return self._effective_cve_year()
        candidate: int | str | None = self.vulnerability_id
        if self.vulnerability_id:
            candidate = parse_year_from_id(self.vulnerability_id)
        if not isinstance(candidate, int):
            candidate = self._effective_cve_year()
        if isinstance(candidate, int):
            return candidate
        return None


class LabelEntryCollection:
    def __init__(self, entries: list[LabelEntry]):
        self.entries = entries

    @functools.cache  # noqa: B019
    def for_image(self, image: str) -> list[LabelEntry]:
        return [e for e in self.entries if e.matches_image(image)]


@dataclass()
class ScanRequest:
    image: str
    tool: str
    label: str | None = None
    profile: str | None = None
    provides: str | None = None
    takes: str | None = None
    refresh: bool = True

    @staticmethod
    def needs_rendering(tool: str) -> bool:
        return "@env:" in tool or "@git:current-commit" in tool

    @staticmethod
    def render_tool(tool: str) -> str:
        if "@git:current-commit" in tool:
            val = (
                subprocess.check_output(
                    ["git", "rev-parse", "HEAD"],
                )
                .decode("ascii")
                .strip()
            )
            # preserve the name and any other suffix
            tool = tool.replace("@git:current-commit", f"@{val}")

        if "@env:" in tool:
            name, val = tool.split("@env:")
            if "+" in val:
                val, metadata = val.split("+", 1)
            else:
                metadata = None
            # preserve the name and any other suffix
            tool = f"{name}@{os.environ[val]}"
            if metadata:
                tool += f"+{metadata}"

        return tool

    def __post_init__(self):
        if self.needs_rendering(self.tool):
            object.__setattr__(self, "tool", self.render_tool(self.tool))


@dataclass_json
@dataclass()
class ResultState:
    request: ScanRequest
    config: ScanConfiguration | None = None


@dataclass_json
@dataclass()
class ResultSet:
    name: str
    state: list[ResultState] = field(default_factory=list)

    def get(self, tool: str, image: str) -> ResultState | None:
        img = Image(image)
        for state in self.state:
            if state.request.tool == tool and img.is_like(state.request.image):
                return state
        return None

    def provider(self, image: str, provides: str) -> ResultState | None:
        img = Image(image)
        for state in self.state:
            if img.is_like(state.request.image) and state.request.provides == provides:
                return state
        return None

    def add(self, request: ScanRequest, scan_config: ScanConfiguration):
        self.state.append(ResultState(request=request, config=scan_config))

    @property
    def descriptions(self) -> list[str]:
        descriptions = []
        for result_state in self.state:
            if result_state.config:
                descriptions.append(result_state.config.path)
        return descriptions

    @property
    def ids(self) -> list[str]:
        ids = []
        for result_state in self.state:
            if result_state.config:
                ids.append(result_state.config.ID)
        return ids

    @property
    def result_state_by_image(self) -> dict[str, list[ResultState]]:
        descriptions = collections.defaultdict(list)
        for result_state in self.state:
            if result_state.config:
                descriptions[result_state.config.image].append(result_state)
        return descriptions
