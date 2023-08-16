import atexit
import hashlib
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


# pylint: disable=no-member
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

    @classmethod
    def _install_from_git(
        cls,
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        **kwargs,  # pylint: disable=unused-argument
    ) -> "Syft":
        logging.debug(f"installing syft version={version!r} from git")
        tool_exists = False

        repo_url = "github.com/anchore/syft"
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
            logging.debug(f"found existing syft repo at {repo_path!r}")
            # use existing source
            try:
                repo = git.Repo(repo_path)
            except:
                logging.error(f"failed to open existing syft repo at {repo_path!r}")
                raise
        else:
            logging.debug("cloning the syft git repo: {repo_url!r}")
            # clone the repo
            os.makedirs(repo_path)
            repo = git.Repo.clone_from("https://{repo_url}.git", repo_path)

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
            cls._run_go_build(abs_install_dir=abspath, repo_path=repo_path, description=description, binpath=path)
        else:
            logging.debug(f"using existing syft installation {abspath!r}")

        return Syft(path=path, version_detail=description)

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
        if repo.is_dirty():
            hash_obj = hashlib.sha1()
            for untracked in repo.untracked_files:
                hash_obj.update(cls._hash_file(os.path.join(repo.working_dir, untracked)).encode())
            hash_obj.update(repo.git.diff("HEAD").encode())
            diff_digest = hash_obj.hexdigest()[:8]
        return f"{git_desc}-{diff_digest}"

    @classmethod
    def _install_from_path(
        cls,
        path: Optional[str],
        src_path: str,
    ) -> "Syft":
        # get the description and head ref from the repo
        src_repo_path = os.path.abspath(os.path.expanduser(src_path))
        build_version = cls._local_build_version_suffix(src_repo_path)
        logging.debug(f"installing syft from path={src_repo_path!r}")
        logging.debug(f"installing syft to path={path!r}")
        if not path:
            path = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, path)
        dest_path = os.path.join(path.replace("path:", ""), build_version, "local_install")
        os.makedirs(dest_path, exist_ok=True)
        cls._run_go_build(
            abs_install_dir=os.path.abspath(dest_path),
            description=f"{path}:{build_version}",
            repo_path=src_repo_path,
            binpath=dest_path,
        )

        return Syft(path=dest_path)

    @staticmethod
    def _run_go_build(
        abs_install_dir: str,
        repo_path: str,
        description: str,
        binpath: str,
        version_ref: str = "github.com/anchore/syft/internal/version.version",
    ):
        logging.debug(f"installing syft via build to {abs_install_dir!r}")

        main_pkg_path = "./cmd/syft"
        if not os.path.exists(os.path.join(repo_path, "cmd", "syft", "main.go")):
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

        os.chmod(f"{binpath}/syft", 0o755)

    @classmethod
    def _get_latest_version_from_github(cls) -> str:
        headers = {}
        if os.environ.get("GITHUB_TOKEN") is not None:
            headers["Authorization"] = "Bearer " + os.environ.get("GITHUB_TOKEN")

        response = requests.get(
            "https://api.github.com/repos/anchore/syft/releases/latest",
            headers=headers,
        )

        if response.status_code >= 400:
            logging.error(f"error while fetching latest syft version: {response.status_code}: {response.reason} {response.text}")

        response.raise_for_status()

        return response.json()["name"]

    @classmethod
    def install(cls, version: str, path: Optional[str] = None, use_cache: Optional[bool] = True, **kwargs) -> "Syft":
        if version == "latest":
            if cls._latest_version_from_github:
                version = cls._latest_version_from_github
                logging.info(f"latest syft release found (cached) is {version}")

            else:
                version = cls._get_latest_version_from_github()
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
        elif version.startswith("path:"):
            tool_obj = cls._install_from_path(
                path=path,
                src_path=version.removeprefix("path:"),
            )
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
