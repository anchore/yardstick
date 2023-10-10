import logging
import os

import requests


def get_latest_release_version(project: str, owner: str = "anchore") -> str:
    headers = {}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token

    response = requests.get(
        f"https://api.github.com/repos/{owner}/{project}/releases/latest",
        headers=headers,
        timeout=15.0,
    )

    if response.status_code >= 400:
        logging.error(
            f"error while fetching latest {project} version: {response.status_code}: {response.reason} {response.text}",
        )

    response.raise_for_status()

    return response.json()["name"]
