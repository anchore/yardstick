import atexit
import functools
import io
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import git
import xxhash
import zstandard as zstd

from yardstick import artifact, utils
from yardstick.tool.vulnerability_scanner import VulnerabilityScanner
from yardstick.utils import github, is_local_path_version, parse_local_path, strip_local_path_prefix


def _prepare_db(tool: "Grype", db_import_path: Optional[str], update_db: bool) -> None:
    """Handle DB import or update for a Grype instance.

    Args:
        tool: The Grype instance to prepare the database for
        db_import_path: Path to custom DB archive to import, or None for OSS DB
        update_db: Whether to update the DB if no custom DB is provided
    """
    if db_import_path:
        if os.path.exists(tool.db_root):
            logging.info("using existing (custom) db from %r", tool.db_root)
        else:
            logging.info("importing given (custom) db from %r", db_import_path)
            tool.run("db", "import", db_import_path)
    elif update_db:
        logging.debug("updating db from OSS")
        tool.run("db", "update", "-vv")


def _check_executable_path_override() -> Optional[str]:
    """Check for existing grype binary via GRYPE_EXECUTABLE_PATH environment variable.

    Returns:
        str | None: Resolved path to grype binary if found and executable, None otherwise.
    """
    grype_path = os.getenv("GRYPE_EXECUTABLE_PATH")
    if not grype_path:
        return None

    # Handle absolute paths explicitly for clarity
    if os.path.isabs(grype_path):
        if os.path.isfile(grype_path) and os.access(grype_path, os.X_OK):
            resolved = os.path.realpath(grype_path)
            logging.info("Using grype from GRYPE_EXECUTABLE_PATH: %s", resolved)
            return resolved
        logging.warning("GRYPE_EXECUTABLE_PATH not executable: %s", grype_path)
        return None

    # Search PATH for relative names
    found = shutil.which(grype_path)
    if found:
        resolved = os.path.realpath(found)
        logging.info("Using grype from PATH via GRYPE_EXECUTABLE_PATH: %s", resolved)
        return resolved

    logging.warning("GRYPE_EXECUTABLE_PATH not found on PATH: %s", grype_path)
    return None


@dataclass(frozen=False)
class GrypeProfile:
    name: Optional[str] = None
    config_path: Optional[str] = None


class Grype(VulnerabilityScanner):
    def __init__(  # noqa: PLR0913
        self,
        path: str,
        db_identity: str,
        version_detail: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        profile: Optional[GrypeProfile] = None,
        **kwargs,
    ):
        if not profile:
            profile = GrypeProfile()
        self.profile = profile
        self.db_identity = db_identity
        self.path = path
        self._env = env
        if version_detail:
            self.version_detail = version_detail
            if self.profile and self.profile.name:
                self.version_detail += f"+profile={self.profile.name}"

    @staticmethod
    @functools.cache
    def latest_version_from_github():
        return github.get_latest_release_version(project="grype")

    @staticmethod
    def _install_from_installer(
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        **kwargs,
    ) -> "Grype":
        logging.debug(f"installing grype version={version!r} from installer")
        tool_exists = False

        if not use_cache and path:
            shutil.rmtree(path)

        if not path:
            path = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, path)

        if os.path.exists(os.path.join(path, "grype")):
            tool_exists = True

        if not tool_exists:
            subprocess.check_call(
                [
                    "sh",
                    "-c",
                    f"curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b {path} {version}",
                ],
            )

            # note on S103 exception: grype must be executable and it is not valid to assume that
            # a single user or group should be restricted to using it. 0755 is the default
            # permission used for system bin/* contents.
            os.chmod(f"{path}/grype", 0o755)  # noqa: S103
        else:
            logging.debug(f"using existing grype installation {path!r}")

        return Grype(path=path, version_detail=version, **kwargs)

    @classmethod
    def _install_from_git(  # noqa: PLR0912
        cls,
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        **kwargs,
    ) -> "Grype":
        logging.debug(f"installing grype version={version!r} from git")
        tool_exists = False

        repo_url = "github.com/anchore/grype"
        if version.startswith("github.com"):
            repo_url = version
            if "@" in version:
                version = version.split("@")[1]
                repo_url = repo_url.split("@")[0]
            else:
                version = "main"

        if not use_cache and path:
            shutil.rmtree(path, ignore_errors=True)

        if not path:
            path = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, path)

        # grab the latest source code into a local directory
        repo_path = os.path.join(path, "source")

        if os.path.exists(repo_path):
            logging.debug(f"found existing grype repo at {repo_path!r}")
            # use existing source
            try:
                repo = git.Repo(repo_path)
            except:
                logging.error(f"failed to open existing grype repo at {repo_path!r}")
                raise
        else:
            logging.debug(f"cloning the grype git repo: {repo_url!r}")
            # clone the repo
            os.makedirs(repo_path)
            repo = git.Repo.clone_from(f"https://{repo_url}.git", repo_path)

        # checkout the ref in question
        repo.git.fetch("origin", version)
        repo.git.checkout(version)

        # get userful ref
        description = repo.git.describe("--tags", "--always", "--long")
        path = os.path.join(path, "git_install", description)

        logging.debug(f"found grype git description={description!r}")

        if os.path.exists(os.path.join(path, "grype")):
            tool_exists = True
        else:
            os.makedirs(path)

        abspath = os.path.abspath(path)
        if not tool_exists:
            logging.debug(f"installing grype to {abspath!r}")
            cls._run_go_build(
                abs_install_dir=abspath,
                repo_path=repo_path,
                description=description,
                binpath=path,
            )
        else:
            logging.debug(f"using existing grype installation {abspath!r}")

        return Grype(path=path, version_detail=description, **kwargs)

    @classmethod
    def _install_from_path(
        cls,
        path: Optional[str],
        src_path: str,
        use_cache: Optional[bool] = True,
        **kwargs,
    ) -> "Grype":
        if not use_cache and path:
            shutil.rmtree(path, ignore_errors=True)

        if not path:
            path = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, path)

        # get the description and head ref from the repo
        src_repo_path = os.path.abspath(os.path.expanduser(src_path))
        build_version = utils.local_build_version_suffix(src_repo_path)

        logging.debug(f"installing grype from path={src_repo_path!r} to path={path!r}")

        dest_path = os.path.join(
            strip_local_path_prefix(path),
            build_version,
            "local_install",
        )
        os.makedirs(dest_path, exist_ok=True)

        cls._run_go_build(
            abs_install_dir=os.path.abspath(dest_path),
            description=f"{path}:{build_version}",
            repo_path=src_repo_path,
            binpath=dest_path,
        )

        return Grype(path=dest_path, **kwargs)

    @staticmethod
    def _run_go_build(
        abs_install_dir: str,
        repo_path: str,
        description: str,
        binpath: str,
        version_ref: str = "github.com/anchore/grype/internal/version.version",
    ):
        logging.debug(f"installing grype via build to {abs_install_dir!r}")

        main_pkg_path = "./cmd/grype"
        if not os.path.exists(os.path.join(repo_path, "cmd", "grype", "main.go")):
            # support legacy installations, when the main.go was in the root of the repo
            main_pkg_path = "."

        c = f"go build -ldflags \"-w -s -extldflags '-static' -X {version_ref}={description}\" -o {abs_install_dir} {main_pkg_path}"
        logging.debug(f"running {c!r}")

        e = {"GOBIN": abs_install_dir, "CGO_ENABLED": "0"}
        e.update(os.environ)

        subprocess.check_call(
            shlex.split(c),
            stdout=sys.stdout,
            stderr=sys.stderr,
            cwd=repo_path,
            env=e,
        )

        # note on S103 exception: grype must be executable and it is not valid to assume that
        # a single user or group should be restricted to using it. 0755 is the default
        # permission used for system bin/* contents.
        os.chmod(f"{binpath}/grype", 0o755)  # noqa: S103

    @classmethod
    def install(  # noqa: C901, PLR0913
        cls,
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        update_db: bool = True,
        db_import_path=None,
        profile: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> "Grype":
        """Install grype from a specified version.

        If GRYPE_EXECUTABLE_PATH environment variable is set and points to an executable,
        that binary will be used instead of building from source.
        """
        # Check for explicit grype binary override (opt-in only)
        if existing_binary := _check_executable_path_override():
            original_version = version
            specified_db = "+import-db=" in version
            db_identity = "oss"
            if specified_db:
                fields = version.split("+import-db=")
                db_import_path = fields[1]
                version = fields[0]
                update_db = False
                db_identity = get_import_checksum(db_import_path)

            grype_profile = GrypeProfile(**profile) if profile else GrypeProfile()

            # Create a proper working directory for external binary
            # We can't use the binary's directory (/opt/homebrew/bin) as it's not writable
            # Use the provided path or create a temp directory under the tool store
            if not path:
                from yardstick.store import tool as tool_store

                tool_name = "grype"
                if grype_profile and grype_profile.name:
                    tool_name = f"grype[{grype_profile.name}]"
                path = tool_store.install_base(name=tool_name)
                path = os.path.join(path, f"external-{version}")

            # Ensure path exists and create symlink (works for both explicit and generated paths)
            os.makedirs(path, exist_ok=True)
            symlink_path = os.path.join(path, "grype")
            try:
                if not os.path.exists(symlink_path):
                    os.symlink(existing_binary, symlink_path)
            except FileExistsError:
                # Race condition: another process created it
                pass

            # Detect actual version from the binary
            try:
                version_output = subprocess.check_output(
                    [existing_binary, "version", "-o", "json"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=5,
                )
                version_json = json.loads(version_output)
                detected_version = version_json.get("version", version)
                version_detail = f"external-{detected_version}"
            except Exception:
                # Fallback if version detection fails or times out
                version_detail = f"external-{version}"

            tool_obj = Grype(
                path=path,
                db_identity=db_identity,
                version_detail=version_detail,
                profile=grype_profile,
                **kwargs,
            )

            # Handle DB import/update
            _prepare_db(tool_obj, db_import_path, update_db)

            return tool_obj

        original_version = version
        specified_db = "+import-db=" in version
        db_identity = "oss"
        if specified_db:
            # note: doesn't allow for additional version modifiers
            fields = version.split("+import-db=")
            db_import_path = fields[1]
            version = fields[0]
            update_db = False
            db_identity = get_import_checksum(db_import_path)

        logging.debug(
            f"parsed import-db={db_import_path!r} from version={original_version!r} new version={version!r}",
        )
        grype_profile = GrypeProfile(**profile) if profile else GrypeProfile()

        if version == "latest":
            version = cls.latest_version_from_github()
            if path:
                path = os.path.join(os.path.dirname(path), version)
            logging.info(f"latest grype release found is {version}")

        # check if the version is a semver...
        if re.match(
            r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
            version,
        ):
            tool_obj = cls._install_from_installer(
                version=version,
                path=path,
                use_cache=use_cache,
                profile=grype_profile,
                db_identity=db_identity,
                **kwargs,
            )
        elif is_local_path_version(version):
            local_path = parse_local_path(version)
            tool_obj = cls._install_from_path(
                path=path,
                src_path=local_path,
                version=local_path,
                use_cache=use_cache,
                db_identity=db_identity,
                profile=grype_profile,
                **kwargs,
            )
        else:
            tool_obj = cls._install_from_git(
                version=version,
                path=path,
                db_identity=db_identity,
                use_cache=use_cache,
                profile=grype_profile,
                **kwargs,
            )

        # always update the DB, raise exception on failure
        _prepare_db(tool_obj, db_import_path, update_db)

        return tool_obj

    @property
    def db_root(self) -> str:
        return os.path.join(self.path, "db", self.db_identity)

    def env(self, override=None):
        env = os.environ.copy()
        env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
        env["GRYPE_DB_VALIDATE_AGE"] = "false"  # if we are using a local DB, we don't want to validate it (but we should be consistent all the time)
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
        env["GRYPE_DB_CACHE_DIR"] = self.db_root
        if self._env:
            env.update(self._env)
        if override:
            env.update(override)
        return env

    @staticmethod
    def parse(result: str, config: artifact.ScanConfiguration) -> List[artifact.Match]:
        logging.debug("parsing grype results")

        results: List[artifact.Match] = []
        obj = json.loads(result)

        # patch the config with the digest found in the results
        repo = config.image.split(":")[0]
        for digest in utils.dig(obj, "source", "target", "repoDigests", default=[]):
            if digest.startswith(repo + "@"):
                config.image_digest = digest.split("@")[1]
                break

        # patch the config with the db information found
        config.detail["db"] = utils.dig(obj, "descriptor", "db", default={})
        db_location = config.detail["db"].get("location", None)  # type: ignore[union-attr]
        if db_location:
            # we should always interpret results with the same DB if the DB is still there (e.g. to support
            # GHSA to CVE mapping for the latest results) if the DB is not there, we try to fall back to
            # the DB found on the system (which isn't ideal, but is better than nothing)
            logging.debug(
                f"using db location found in results to interpret vulnerability definitions: {db_location!r}",
            )
            utils.grype_db.use(db_location)
        else:
            logging.debug(
                "no db location found in results, using system grype DB (not ideal and may cause issues with date filtering)",
            )
            utils.grype_db.use(None)

        for entry in obj["matches"]:
            # TODO: normalize version here
            pkg = artifact.Package(
                name=entry["artifact"]["name"],
                version=entry["artifact"]["version"],
            )
            vuln_id = entry["vulnerability"]["id"]
            cve_id = vuln_id if vuln_id.startswith("CVE-") else None

            if not cve_id:
                for rv in entry.get("relatedVulnerabilities", []):
                    if rv.get("id", "").startswith("CVE-"):
                        cve_id = rv.get("id")
                        break

            vuln = artifact.Vulnerability(id=vuln_id, cve_id=cve_id)
            match = artifact.Match(
                package=pkg,
                vulnerability=vuln,
                fullentry=entry,
                config=config,
            )
            results.append(match)
        return results

    def capture(self, image: str, tool_input: Optional[str]) -> str:
        i = image if tool_input is None else tool_input
        logging.debug(f"running grype with input={i}")
        return self.run("-o", "json", i)

    def run(self, *args, env=None) -> str:
        # self.path is always a directory containing the grype binary (or symlink to it)
        grype_binary = os.path.join(self.path, "grype")
        cmd = [grype_binary, *args]
        if self.profile and self.profile.config_path:
            cmd.append("-c")
            cmd.append(self.profile.config_path)
        return subprocess.check_output(
            cmd,
            env=self.env(override=env),
        ).decode("utf-8")

    @staticmethod
    def parse_package_type(full_entry: Optional[Dict[str, Any]]) -> str:
        if not full_entry:
            return "unknown"
        return str(
            utils.dig(
                full_entry,
                "artifact",
                "type",
                default=utils.dig(full_entry, "package_type", default="unknown"),
            ),
        )


def get_import_checksum(db_import_path: str) -> str:
    if db_import_path.endswith(".tar.gz"):
        return handle_legacy_archive(db_import_path)
    if db_import_path.endswith(".tar.zstd") or db_import_path.endswith(".tar.zst"):
        return handle_zstd_archive(db_import_path)
    if db_import_path.endswith(".db"):
        return handle_db_file(db_import_path)
    raise ValueError(f"unsupported db import path: {db_import_path!r}")


# handle_legacy_archive deals with getting the checksum of the DB from the metadata.json file within the DB archive
def handle_legacy_archive(archive_path: str) -> str:
    with tarfile.open(archive_path, "r:gz") as tar:
        metadata_path = None
        for member in tar.getmembers():
            if member.name.endswith("metadata.json"):
                metadata_path = member.name
                break

        if not metadata_path:
            raise ValueError(
                f"could not find metadata.json in {archive_path!r}",
            )

        extractor = tar.extractfile(metadata_path)
        if extractor:
            with extractor as metadata_file:
                metadata = json.load(metadata_file)

        return metadata["checksum"]


# handle_zstd_archive calculates the checksum of the DB from the vulnerability.db file within the DB archive
def handle_zstd_archive(archive_path: str) -> str:
    # if starts with https, then hash the URL as a unique identifier
    if archive_path.startswith("https://"):
        hasher = xxhash.xxh64()
        hasher.update(archive_path.encode("utf-8"))
        return hasher.hexdigest()

    # otherwise, decompress the archive and calculate the checksum of vulnerability.db
    with open(archive_path, "rb") as compressed_file:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(compressed_file) as decompressed_stream:
            buffer = io.BytesIO(decompressed_stream.read())

        with tarfile.open(fileobj=buffer, mode="r:") as tar:
            # locate vulnerability.db
            db_member = None
            for member in tar.getmembers():
                if member.name == "vulnerability.db":
                    db_member = member
                    break

            if not db_member:
                raise ValueError(f"could not find vulnerability.db in {archive_path!r}")

            # stream the vulnerability.db file to the hasher
            hasher = xxhash.xxh64()
            with tar.extractfile(db_member) as db_file:
                if not db_file:
                    raise ValueError(f"could not extract vulnerability.db from {archive_path!r}")

                while chunk := db_file.read(8192):
                    hasher.update(chunk)

            return hasher.hexdigest()


# handle_db_file calculates the checksum of a raw SQLite database file
def handle_db_file(db_path: str) -> str:
    hasher = xxhash.xxh64()
    with open(db_path, "rb") as db_file:
        while chunk := db_file.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()
