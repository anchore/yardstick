import atexit
import functools
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

from yardstick import artifact, utils
from yardstick.tool.sbom_generator import SBOMGenerator
from yardstick.utils import github


class Syft(SBOMGenerator):
    _latest_version_from_github: Optional[str] = None

    def __init__(
        self,
        path: str,
        version_detail: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ):
        self.path = path
        self._env = env
        if version_detail:
            self.version_detail = version_detail

    @staticmethod
    @functools.cache
    def latest_version_from_github():
        return github.get_latest_release_version(project="syft")

    @staticmethod
    def _install_from_installer(
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        **kwargs,  # noqa: ARG004
    ) -> "Syft":
        logging.debug(f"installing syft version={version!r} from installer")
        tool_exists = False

        if not use_cache and path:
            shutil.rmtree(path, ignore_errors=True)

        if not path:
            path = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, path)

        os.makedirs(path, exist_ok=True)
        if os.path.exists(os.path.join(path, "syft")):
            tool_exists = True

        if not tool_exists:
            subprocess.check_call(
                [
                    "sh",
                    "-c",
                    f"curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b {path} {version}",
                ],
            )

            # note on S103 exception: syft must be executable and it is not valid to assume that
            # a single user or group should be restricted to using it. 0755 is the default
            # permission used for system bin/* contents.
            os.chmod(f"{path}/syft", 0o755)  # noqa: S103
        else:
            logging.debug(f"using existing syft installation {path!r}")

        return Syft(path=path, version_detail=version)

    @classmethod
    def _install_from_git(  # noqa: PLR0912
        cls,
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        **kwargs,  # noqa: ARG003
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
            cls._run_go_build(
                abs_install_dir=abspath,
                repo_path=repo_path,
                description=description,
                binpath=path,
            )
        else:
            logging.debug(f"using existing syft installation {abspath!r}")

        return Syft(path=path, version_detail=description)

    @classmethod
    def _install_from_path(
        cls,
        path: Optional[str],
        src_path: str,
    ) -> "Syft":
        # get the description and head ref from the repo
        src_repo_path = os.path.abspath(os.path.expanduser(src_path))
        build_version = utils.local_build_version_suffix(src_repo_path)
        logging.debug(f"installing syft from path={src_repo_path!r}")
        logging.debug(f"installing syft to path={path!r}")
        if not path:
            path = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, path)
        dest_path = os.path.join(
            path.replace("path:", ""),
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

        # note on S103 exception: syft must be executable and it is not valid to assume that
        # a single user or group should be restricted to using it. 0755 is the default
        # permission used for system bin/* contents.
        os.chmod(f"{binpath}/syft", 0o755)  # noqa: S103

    @classmethod
    def install(
        cls,
        version: str,
        path: Optional[str] = None,
        use_cache: Optional[bool] = True,
        **kwargs,
    ) -> "Syft":
        if version == "latest":
            version = cls.latest_version_from_github()
            if path:
                path = os.path.join(os.path.dirname(path), version)
            logging.info(f"latest syft release found is {version}")

        # check if the version is a semver...
        if re.match(
            r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
            version,
        ):
            tool_obj = cls._install_from_installer(
                version=version,
                path=path,
                use_cache=use_cache,
                **kwargs,
            )
        elif version.startswith("path:"):
            tool_obj = cls._install_from_path(
                path=path,
                src_path=version.removeprefix("path:"),
            )
        else:
            tool_obj = cls._install_from_git(
                version=version,
                path=path,
                use_cache=use_cache,
                **kwargs,
            )

        return tool_obj

    def env(self):
        env = os.environ.copy()
        env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
        if self._env:
            env.update(self._env)
        return env

    @staticmethod
    def parse(
        result: str,
        config: artifact.ScanConfiguration,
    ) -> List[artifact.Package]:
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
        return subprocess.check_output(
            [f"{self.path}/syft", *args],
            env=self.env(),
        ).decode("utf-8")
