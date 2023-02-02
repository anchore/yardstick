import atexit
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional

import git
import requests

from yardstick import artifact, utils
from yardstick.tool.vulnerability_scanner import VulnerabilityScanner


class Grype(VulnerabilityScanner):
    _latest_version_from_github: Optional[str] = None

    def __init__(
        self,
        path: str,
        version_detail: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        **kwargs,  # pylint: disable=unused-argument
    ):
        self.path = path
        self._env = env
        if version_detail:
            self.version_detail = version_detail

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

    @staticmethod
    def _install_from_git(
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        **kwargs,
    ) -> "Grype":
        logging.debug(f"installing grype version={version!r} from git")
        tool_exists = False

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
            logging.debug("cloning the grype git repo")
            # clone the repo
            os.makedirs(repo_path)
            repo = git.Repo.clone_from("https://github.com/anchore/grype.git", repo_path)

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
            c = f"go build -ldflags \"-w -s -extldflags '-static' -X github.com/anchore/grype/internal/version.version={description}\" -o {abspath} ."
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

            os.chmod(f"{path}/grype", 0o755)
        else:
            logging.debug(f"using existing grype installation {abspath!r}")

        return Grype(path=path, version_detail=description, **kwargs)

    # pylint: disable=too-many-arguments
    @classmethod
    def install(
        cls,
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        update_db: bool = True,
        db_import_path=None,
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

        if version == "latest":
            if cls._latest_version_from_github:
                version = cls._latest_version_from_github
                logging.info(f"latest grype release found (cached) is {version}")
            else:
                headers = {}
                if os.environ.get("GITHUB_TOKEN") is not None:
                    headers["Authorization"] = "Bearer " + os.environ.get("GITHUB_TOKEN")

                response = requests.get(
                    "https://api.github.com/repos/anchore/grype/releases/latest",
                    headers=headers,
                )

                if response.status_code >= 400:
                    logging.error(
                        f"error while fetching latest grype version: {response.status_code}: {response.reason} {response.text}"
                    )

                response.raise_for_status()

                version = response.json()["name"]
                cls._latest_version_from_github = version

                path = os.path.join(os.path.dirname(path), version)
                logging.info(f"latest grype release found is {version}")

        # check if the version is a semver...
        if re.match(
            # pylint: disable=line-too-long
            r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
            version,
        ):
            tool_obj = cls._install_from_installer(version=version, path=path, use_cache=use_cache, **kwargs)
        else:
            tool_obj = cls._install_from_git(version=version, path=path, use_cache=use_cache, **kwargs)

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
        return subprocess.check_output([f"{self.path}/grype", *args], env=self.env(override=env)).decode("utf-8")

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
