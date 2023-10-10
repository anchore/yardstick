import json
import logging
import os
import sqlite3
import subprocess
import sys
import threading
from contextlib import closing
from typing import Optional


def remove_prefix(text, prefix):
    return text[text.startswith(prefix) and len(prefix) :]


class GrypeDBManager:
    enabled: bool
    message: str
    db_location: Optional[str]
    connections: dict[int, sqlite3.Connection]

    def __init__(self, db_location: Optional[str] = None):
        self.enabled = False
        self.message = ""
        self.db_location = db_location
        self.connections = {}

        if self.db_location:
            try:
                self.connect()
            except:  # noqa: E722
                self.db_location = None
                logging.error(
                    f"unable to open grype DB at {self.db_location}. Falling back to system grype DB.",
                )

        if not self.db_location:
            self.set_db_to_system_grype_db()

        if self.db_location:
            self.enabled = True

    def close(self):
        for conn in self.connections.values():
            conn.close()
        self.connections = {}

    def set_db_to_system_grype_db(self):
        try:
            logging.debug("using system grype DB...")
            out = subprocess.check_output(
                ["grype", "db", "status"],
            ).decode(
                sys.stdout.encoding,
            )
            for line in out.split("\n"):
                if line.startswith("Location:"):
                    self.db_location = remove_prefix(line, "Location:").strip()
        except Exception as e:
            self.message = str(e)
            logging.error("unable to open grype DB %s", e)

    def connect(self):
        # sqlite3 is not thread safe, so we need to create a connection per thread
        tid = threading.get_ident()
        if tid in self.connections:
            return self.connections[tid]

        conn = sqlite3.connect(os.path.join(self.db_location, "vulnerability.db"))
        self.connections[tid] = conn
        return conn

    def get_upstream_vulnerability(self, vuln_id: str) -> Optional[str]:
        with closing(self.connect().cursor()) as cur:
            cur.execute(
                "select related_vulnerabilities from vulnerability where id == ? ;",
                (vuln_id,),
            )
            vulnerability_info = cur.fetchall()

        for info in vulnerability_info:
            if info and len(info) > 0 and info[0]:
                loaded_info = json.loads(info[0])
                if len(loaded_info) > 0:
                    return loaded_info[0]["id"]
        return None

    def get_vuln_description(self, vuln_id: str) -> str:
        with closing(self.connect().cursor()) as cur:
            cur.execute(
                "select description from vulnerability_metadata where id == ? ;",
                (vuln_id,),
            )
            results = cur.fetchall()

        for result in results:
            if result and len(result) > 0 and result[0]:
                return result[0]
        return ""

    # get vulnerability description of a vulnerability and all its related vulnerabilities
    def get_all_vulnerability_descriptions(self, vuln_id: str) -> str:
        if not self.db_location:
            return ""

        upstream = self.get_upstream_vulnerability(vuln_id)

        message = ""

        if upstream and upstream != vuln_id:
            vuln_desc = self.get_vuln_description(upstream)
            if vuln_desc:
                message += f"Upstream Vulnerability: {upstream}\n{vuln_desc}\n\n"

        vuln_desc = self.get_vuln_description(vuln_id)
        if vuln_desc:
            message += f"Vulnerability: {vuln_id}\n{vuln_desc}\n"

        return message


_instance = None
_raise_on_failure = False


def raise_on_failure(value: bool):
    global _raise_on_failure  # noqa: PLW0603
    _raise_on_failure = value


def use(location: str):
    global _instance  # noqa: PLW0603

    if _instance:
        _instance.close()

    _instance = GrypeDBManager(location)


def normalize_to_cve(vuln_id: str):
    global _instance  # noqa: PLW0603
    if vuln_id.lower().startswith("cve-"):
        return vuln_id

    try:
        if not _instance:
            _instance = GrypeDBManager()

        upstream = _instance.get_upstream_vulnerability(vuln_id)
    except:  # noqa: E722
        if _raise_on_failure:
            raise
        return vuln_id

    if upstream and upstream.lower().startswith("cve-"):
        return upstream

    # unable to normalize, return the original
    return vuln_id
