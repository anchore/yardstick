from yardstick import utils


class CveDescriptions:
    def __init__(self):
        self.grype_db = utils.grype_db.GrypeDBManager()
        self.cache = {}

    def is_cached(self, cve: str):
        return cve in self.cache

    def get(self, cve: str):
        if cve in self.cache:
            return self.cache[cve]

        if not self.grype_db.enabled:
            description = "could not connect to grype db:\n" + self.grype_db.message
        else:
            description = self.grype_db.get_all_vulnerability_descriptions(cve)

        if not description:
            description = "Unable to get CVE description"

        self.cache[cve] = description
        return description
