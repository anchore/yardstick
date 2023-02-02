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
from typing import Dict, List, Optional

import git
import requests

from yardstick import artifact, utils
from yardstick.tool.sbom_generator import SBOMGenerator


class Syft(SBOMGenerator):
    _latest_version_from_github: Optional[str] = None

    def __init__(self, path: str, version_detail: Optional[str] = None, env: Optional[Dict[str, str]] = None):
        self.path = path
        self._env = env
        if version_detail:
            self.version_detail = version_detail

    @staticmethod
    def _install_from_installer(
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        **kwargs,  # pylint: disable=unused-argument
    ) -> "Syft":
        logging.debug(f"installing syft version={version!r} from installer")
        tool_exists = False

        if not use_cache and path:
            shutil.rmtree(path, ignore_errors=True)

        if not path:
            path = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, path)
        else:
            if os.path.exists(os.path.join(path, "syft")):
                tool_exists = True

        if not tool_exists:
            subprocess.check_call(
                [
                    "sh",
                    "-c",
                    # pylint: disable=line-too-long
                    f"curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b {path} {version}",
                ]
            )

            os.chmod(f"{path}/syft", 0o755)
        else:
            logging.debug(f"using existing syft installation {path!r}")

        return Syft(path=path)

    @staticmethod
    def _install_from_git(
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        **kwargs,  # pylint: disable=unused-argument
    ) -> "Syft":
        logging.debug(f"installing syft version={version!r} from git")
        tool_exists = False

        if not use_cache and path:
            shutil.rmtree(path, ignore_errors=True)

        if not path:
            path = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, path)

        # grab the latest source code into a local directory
        repo_path = os.path.join(path, "source")

        if os.path.exists(repo_path):
            logging.debug(f"found existing syft repo at {repo_path!r}")
            # use existing source
            repo = git.Repo(repo_path)
        else:
            logging.debug("cloning the syft git repo")
            # clone the repo
            os.makedirs(repo_path)
            repo = git.Repo.clone_from("https://github.com/anchore/syft.git", repo_path)

        # checkout the ref in question
        repo.git.fetch("origin", version)
        repo.git.checkout(version)

        # get userful ref
        description = repo.git.describe("--tags", "--always", "--long")
        path = os.path.join(path, "git_install", description)

        logging.debug(f"found syft git description={description!r}")

        if os.path.exists(os.path.join(path, "syft")):
            tool_exists = True
        else:
            os.makedirs(path)

        abspath = os.path.abspath(path)
        if not tool_exists:
            logging.debug(f"installing syft to {abspath!r}")
            # pylint: disable=line-too-long
            c = f"go build -ldflags \"-w -s -extldflags '-static' -X github.com/anchore/syft/internal/version.version={description}\" -o {abspath} ./cmd/syft/"
            logging.debug(f"running {c!r}")
            subprocess.check_call(
                shlex.split(c),
                stdout=sys.stdout,
                stderr=sys.stderr,
                cwd=repo_path,
                env=dict(**{"GOBIN": abspath, "CGO_ENABLED": "0"}, **os.environ),
            )

            os.chmod(f"{path}/syft", 0o755)
        else:
            logging.debug(f"using existing syft installation {abspath!r}")

        return Syft(path=path, version_detail=description)

    @classmethod
    def install(cls, version: str, path: Optional[str] = None, use_cache: Optional[bool] = True, **kwargs) -> "Syft":
        if version == "latest":
            if cls._latest_version_from_github:
                version = cls._latest_version_from_github
                logging.info(f"latest syft release found (cached) is {version}")

            else:
                response = requests.get("https://api.github.com/repos/anchore/syft/releases/latest")
                version = response.json()["name"]
                cls._latest_version_from_github = version

                path = os.path.join(os.path.dirname(path), version)
                logging.info(f"latest syft release found is {version}")

        # check if the version is a semver...
        if re.match(
            # pylint: disable=line-too-long
            r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
            version,
        ):
            tool_obj = cls._install_from_installer(version=version, path=path, use_cache=use_cache, **kwargs)
        else:
            tool_obj = cls._install_from_git(version=version, path=path, use_cache=use_cache, **kwargs)

        return tool_obj

    def env(self):
        env = os.environ.copy()
        env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
        if self._env:
            env.update(self._env)
        return env

    @staticmethod
    def parse(result: str, config: artifact.ScanConfiguration) -> List[artifact.Package]:
        logging.debug("parsing syft results")

        results: List[artifact.Package] = []
        obj = json.loads(result)

        # patch the config with the digest found in the results
        repo = config.image.split(":")[0]
        for digest in utils.dig(obj, "source", "target", "repoDigests", default=[]):
            if digest.startswith(repo + "@"):
                config.image_digest = digest.split("@")[1]
                break

        for entry in obj["artifacts"]:
            # TODO: normalize version here
            pkg = artifact.Package(name=entry["name"], version=entry["version"])
            results.append(pkg)
        return results

    def capture(self, image: str, tool_input: Optional[str]) -> str:
        i = image if tool_input is None else tool_input
        logging.debug(f"running syft with input={i}")
        return self.run("-o", "json", i)

    def run(self, *args) -> str:
        return subprocess.check_output([f"{self.path}/syft", *args], env=self.env()).decode("utf-8")
