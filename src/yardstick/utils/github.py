import logging
import os

import requests


def get_latest_release_version(project: str, owner: str = "anchore") -> str:
    headers = {}
    if os.environ.get("GITHUB_TOKEN") is not None:
        headers["Authorization"] = "Bearer " + os.environ.get("GITHUB_TOKEN")

    response = requests.get(
        f"https://api.github.com/repos/{owner}/{project}/releases/latest",
        headers=headers,
    )

    if response.status_code >= 400:
        logging.error(f"error while fetching latest {project} version: {response.status_code}: {response.reason} {response.text}")

    response.raise_for_status()

    return response.json()["name"]
