from __future__ import annotations

import hashlib
import logging
import os

import git


def local_build_version_suffix(src_path: str) -> str:
    src_path = os.path.abspath(os.path.expanduser(src_path))
    git_desc = ""
    diff_digest = "clean"
    try:
        repo = git.Repo(src_path)
    except:
        logging.error(f"failed to open existing repo at {src_path!r}")
        raise
    git_desc = repo.git.describe("--tags", "--always", "--long", "--dirty")
    if repo.is_dirty():
        # note on S324 usage: this is currently only used for deriving a unique, content-sensitive
        # value to use for identifying local builds. This is not used for cryptographic purposes.
        hash_obj = hashlib.sha1()  # noqa: S324
        for untracked in repo.untracked_files:
            hash_obj.update(
                hash_file(os.path.join(repo.working_dir, untracked)).encode(),
            )
        hash_obj.update(repo.git.diff("HEAD").encode())
        diff_digest = hash_obj.hexdigest()[:8]
    return f"{git_desc}-{diff_digest}"


def hash_file(path: str) -> str:
    # note on S324 usage: this is currently only used for deriving a unique, content-sensitive
    # value to use for identifying local builds. This is not used for cryptographic purposes.
    hash_obj = hashlib.sha1()  # noqa: S324
    with open(path, "rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            hash_obj.update(data)
    return hash_obj.hexdigest()


def dig(target, *keys, **kwargs):
    """
    Traverse a nested set of dictionaries, tuples, or lists similar to ruby's dig function.
    """
    end_of_chain = target
    for key in keys:
        if (isinstance(end_of_chain, dict) and key in end_of_chain) or (
            isinstance(end_of_chain, (list, tuple)) and isinstance(key, int)
        ):
            end_of_chain = end_of_chain[key]
        else:
            if "fail" in kwargs and kwargs["fail"] is True:
                if isinstance(end_of_chain, dict):
                    raise KeyError
                raise IndexError
            if "default" in kwargs:
                return kwargs["default"]
            end_of_chain = None
            break

    # we may have found a falsy value in the collection at the given key
    # and the caller has specified to return a default value in this case in it's place.
    if not end_of_chain and "falsy_default" in kwargs:
        end_of_chain = kwargs["falsy_default"]

    return end_of_chain


def safe_div(one, two):
    if two == 0:
        return 0
    return float(one) / float(two)


# CVE prefix + Year + Arbitrary Digits
# CVE-YYYY-NNNNN
def is_cve_vuln_id(vuln_id: str | None) -> bool:
    if not vuln_id:
        return False
    return vuln_id.lower().startswith("cve-")


def parse_year_from_id(vuln_id: str) -> int | None:
    def try_convert_year(s: str) -> int | None:
        try:
            value = int(s)
            if value < 1990 or digits_in_number(value) != 4:
                return None
            return value
        except ValueError:
            return None

    components = vuln_id.split("-")
    if not components:
        return None

    first_component = components[0].lower()

    if len(components) == 3 and first_component in {"cve", "alas", "elsa"}:
        return try_convert_year(components[1])

    # there are cases in the amazon data that are considered "extras" and the vulnerability ID is augmented
    # in a way that portrays the application scope. For instance, ALASRUBY3.0-2023-003 or ALASSELINUX-NG-2023-001.
    # fore more information on the "extras" feature for amazon linux, see: https://aws.amazon.com/amazon-linux-2/faqs/#Amazon_Linux_Extras
    if first_component.startswith("alas") and len(components) >= 3:
        # note that we need to reference the compoents from the end since the ID may contain a dynamic number of hyphens.
        return try_convert_year(components[-2])

    return None


def digits_in_number(n: int) -> int:
    count = 0
    while n > 0:
        count = count + 1
        n = n // 10
    return count


def remove_prefix(s: str, prefix: str, /) -> str:
    if s.startswith(prefix):
        return s[len(prefix) :]
    return s[:]
