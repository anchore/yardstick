import json
import logging
import os
import sqlite3
import subprocess
import sys
from typing import Optional


def remove_prefix(text, prefix):
    return text[text.startswith(prefix) and len(prefix) :]


class GrypeDBManager:
    def __init__(self, db_location: str = None):
        self.connection = None
        self.enabled = False
        self.message = ""
        self.db_location = db_location
        try:
            if not self.db_location:
                out = subprocess.check_output(["grype", "db", "status"]).decode(sys.stdout.encoding)
                for line in out.split("\n"):
                    if line.startswith("Location:"):
                        self.db_location = remove_prefix(line, "Location:").strip()
        except Exception as e:  # pylint: disable=broad-except
            self.message = str(e)
            logging.error("unable to open grype DB %s", e)

        if self.db_location:
            self._connection().close()
            self.enabled = True

    def _connection(self):
        return sqlite3.connect(os.path.join(self.db_location, "vulnerability.db"))

    def get_upstream_vulnerability(self, vuln_id: str) -> Optional[str]:
        connection = self._connection()
        cur = connection.cursor()
        cur.execute("select related_vulnerabilities from vulnerability where id == ? ;", (vuln_id,))
        vulnerability_info = cur.fetchall()
        connection.close()

        for info in vulnerability_info:
            if info and info[0]:
                loaded_info = json.loads(info[0])
                if len(loaded_info) > 0:
                    return loaded_info[0]["id"]
        return None

    def get_vuln_description(self, vuln_id: str) -> str:
        connection = self._connection()
        cur = connection.cursor()
        cur.execute("select description from vulnerability_metadata where id == ? ;", (vuln_id,))
        results = cur.fetchall()
        connection.close()
        for result in results:
            if result and result[0]:
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
    global _raise_on_failure  # pylint: disable=global-statement
    _raise_on_failure = value


def use(location: str):
    global _instance  # pylint: disable=global-statement
    _instance = GrypeDBManager(location)


def normalize_to_cve(vuln_id: str):
    global _instance  # pylint: disable=global-statement
    if vuln_id.lower().startswith("cve-"):
        return vuln_id

    try:
        if not _instance:
            _instance = GrypeDBManager()

        upstream = _instance.get_upstream_vulnerability(vuln_id)
    except:  # pylint: disable=bare-except
        if _raise_on_failure:
            raise
        return vuln_id

    if upstream and upstream.lower().startswith("cve-"):
        return upstream

    # unable to normalize, return the original
    return vuln_id
