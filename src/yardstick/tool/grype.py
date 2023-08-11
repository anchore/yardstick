import atexit
import json
import hashlib
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import git
import requests

from yardstick import artifact, utils
from yardstick.tool.vulnerability_scanner import VulnerabilityScanner


@dataclass(frozen=False)
class GrypeProfile:
    name: Optional[str] = None
    config_path: Optional[str] = None


class Grype(VulnerabilityScanner):
    _latest_version_from_github: Optional[str] = None

    def __init__(
        self,
        path: str,
        version_detail: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        profile: Optional[GrypeProfile] = None,
        **kwargs,  # pylint: disable=unused-argument
    ):
        if not profile:
            profile = GrypeProfile()
        self.profile = profile

        self.path = path
        self._env = env
        if version_detail:
            self.version_detail = version_detail
            if self.profile and self.profile.name:
                self.version_detail += f"+profile={self.profile.name}"

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
        else:
            if os.path.exists(os.path.join(path, "grype")):
                tool_exists = True

        if not tool_exists:
            subprocess.check_call(
                [
                    "sh",
                    "-c",
                    # pylint: disable=line-too-long
                    f"curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b {path} {version}",
                ]
            )

            os.chmod(f"{path}/grype", 0o755)
        else:
            logging.debug(f"using existing grype installation {path!r}")

        return Grype(path=path, version_detail=version, **kwargs)

    @classmethod
    def _install_from_git(
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
            cls._run_go_build(
                abspath=abspath,
                repo_path=repo_path,
                description=description,
                binpath=path,
            )
        else:
            logging.debug(f"using existing grype installation {abspath!r}")

        return Grype(path=path, version_detail=description, **kwargs)

    @classmethod
    def _local_build_version_suffix(cls, src_path: str) -> str:
        src_path = os.path.abspath(os.path.expanduser(src_path))
        git_desc = ""
        diff_digest = "clean"
        try:
            repo = git.Repo(src_path)
        except:
            logging.error(f"failed to open existing grype repo at {src_path!r}")
            raise
        git_desc = repo.git.describe("--tags", "--always", "--long", "--dirty")
        diff_digest = hashlib.sha1(repo.git.diff("--stat", "HEAD").encode()).hexdigest()
        return f"{git_desc}-{diff_digest}"

    @classmethod
    def _install_from_path(
        cls,
        path: Optional[str],
        src_path: str,
        **kwargs,
    ) -> "Grype":
        # get the description and head ref from the repo
        src_repo_path = os.path.abspath(os.path.expanduser(src_path))
        build_version = cls._local_build_version_suffix(src_repo_path)
        logging.debug(f"installing grype from path={src_repo_path!r}")
        logging.debug(f"installing grype to path={path!r}")
        if not path:
            path = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, path)
        dest_path = os.path.join(path.replace("path:", ""), build_version, "local_install")
        os.makedirs(dest_path, exist_ok=True)
        cls._run_go_build(
            abspath=os.path.abspath(dest_path),
            description=f"{path}:{build_version}",
            repo_path=src_repo_path,
            binpath=dest_path,
        )

        return Grype(path=dest_path, **kwargs)

    @staticmethod
    def _run_go_build(
        abspath: str,  # TODO: rename; what is an absolute path to?
        repo_path: str,
        description: str,
        binpath: str,
        version_ref: str = "github.com/anchore/grype/internal/version.version",
    ):
        logging.debug(f"installing grype via build to {abspath!r}")

        main_pkg_path = "./cmd/grype"
        if not os.path.exists(os.path.join(repo_path, "cmd", "grype", "main.go")):
            # support legacy installations, when the main.go was in the root of the repo
            main_pkg_path = "."

        c = f"go build -ldflags \"-w -s -extldflags '-static' -X {version_ref}={description}\" -o {abspath} {main_pkg_path}"
        logging.debug(f"running {c!r}")

        e = {"GOBIN": abspath, "CGO_ENABLED": "0"}
        e.update(os.environ)

        subprocess.check_call(
            shlex.split(c),
            stdout=sys.stdout,
            stderr=sys.stderr,
            cwd=repo_path,
            env=e,
        )

        os.chmod(f"{binpath}/grype", 0o755)

    @classmethod
    def _get_latest_version_from_github(cls) -> str:
        headers = {}
        if os.environ.get("GITHUB_TOKEN") is not None:
            headers["Authorization"] = "Bearer " + os.environ.get("GITHUB_TOKEN")

        response = requests.get(
            "https://api.github.com/repos/anchore/grype/releases/latest",
            headers=headers,
        )

        if response.status_code >= 400:
            logging.error(f"error while fetching latest grype version: {response.status_code}: {response.reason} {response.text}")

        response.raise_for_status()

        return response.json()["name"]

    # pylint: disable=too-many-arguments
    @classmethod
    def install(
        cls,
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        update_db: bool = True,
        db_import_path=None,
        profile: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> "Grype":
        original_version = version
        specified_db = "+import-db=" in version
        if specified_db:
            # note: doesn't allow for additional version modifiers
            fields = version.split("+import-db=")
            db_import_path = fields[1]
            version = fields[0]
            update_db = False

        logging.debug(f"parsed import-db={db_import_path!r} from version={original_version!r} new version={version!r}")
        if profile:
            grype_profile = GrypeProfile(**profile)
        else:
            grype_profile = GrypeProfile()

        if version == "latest":
            if cls._latest_version_from_github:
                version = cls._latest_version_from_github
                logging.info(f"latest grype release found (cached) is {version}")
            else:
                version = cls._get_latest_version_from_github()
                cls._latest_version_from_github = version
                path = os.path.join(os.path.dirname(path), version)
                logging.info(f"latest grype release found is {version}")

        # check if the version is a semver...
        if re.match(
            # pylint: disable=line-too-long
            r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
            version,
        ):
            tool_obj = cls._install_from_installer(
                version=version,
                path=path,
                use_cache=use_cache,
                profile=grype_profile,
                **kwargs,
            )
        elif version.startswith("path:"):
            tool_obj = cls._install_from_path(
                path=path,
                src_path=version.removeprefix("path:"),
                version=version.removeprefix("path:"),
                use_cache=use_cache,
                profile=grype_profile,
                **kwargs,
            )
        else:
            tool_obj = cls._install_from_git(
                version=version,
                path=path,
                use_cache=use_cache,
                profile=grype_profile,
                **kwargs,
            )

        # always update the DB, raise exception on failure
        if db_import_path:
            logging.debug(f"using given db from {db_import_path!r}")
            tool_obj.run("db", "import", db_import_path)
        elif update_db:
            logging.debug("updating db")
            tool_obj.run("db", "update")

        return tool_obj

    @property
    def db_root(self) -> str:
        return os.path.join(self.path, "db")

    def env(self, override=None):
        env = os.environ.copy()
        env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
        env[
            "GRYPE_DB_VALIDATE_AGE"
        ] = "false"  # if we are using a local DB, we don't want to validate it (but we should be consistent all the time)
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
        db_location = config.detail["db"].get("location", None)
        if db_location:
            # we should always interpret results with the same DB if the DB is still there (e.g. to support
            # GHSA to CVE mapping for the latest results) if the DB is not there, we try to fall back to
            # the DB found on the system (which isn't ideal, but is better than nothing)
            logging.debug(f"using db location found in results to interpret vulnerability definitions: {db_location!r}")
            utils.grype_db.use(db_location)
        else:
            logging.debug(
                "no db location found in results, using system grype DB (not ideal and may cause issues with date filtering)"
            )

        for entry in obj["matches"]:
            # TODO: normalize version here
            pkg = artifact.Package(name=entry["artifact"]["name"], version=entry["artifact"]["version"])
            vuln_id = entry["vulnerability"]["id"]
            cve_id = vuln_id if vuln_id.startswith("CVE-") else None

            if not cve_id:
                for rv in entry.get("relatedVulnerabilities", []):
                    if rv.get("id", "").startswith("CVE-"):
                        cve_id = rv.get("id")
                        break

            vuln = artifact.Vulnerability(id=vuln_id, cve_id=cve_id)
            match = artifact.Match(package=pkg, vulnerability=vuln, fullentry=entry, config=config)
            results.append(match)
        return results

    def capture(self, image: str, tool_input: Optional[str]) -> str:
        i = image if tool_input is None else tool_input
        logging.debug(f"running grype with input={i}")
        return self.run("-o", "json", i)

    def run(self, *args, env=None) -> str:
        cmd = [f"{self.path}/grype", *args]
        if self.profile and self.profile.config_path:
            cmd.append("-c")
            cmd.append(self.profile.config_path)
        return subprocess.check_output(cmd, env=self.env(override=env)).decode("utf-8")

    @staticmethod
    def parse_package_type(full_entry: Dict[str, Any]) -> str:
        return str(
            utils.dig(
                full_entry,
                "artifact",
                "type",
                default=utils.dig(full_entry, "package_type", default="unknown"),
            )
        )
