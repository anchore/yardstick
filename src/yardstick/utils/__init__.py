from . import grype_db


def dig(target, *keys, **kwargs):
    """
    Traverse a nested set of dictionaries, tuples, or lists similar to ruby's dig function.
    """
    end_of_chain = target
    for key in keys:
        if isinstance(end_of_chain, dict) and key in end_of_chain:
            end_of_chain = end_of_chain[key]
        elif isinstance(end_of_chain, (list, tuple)) and isinstance(key, int):
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
def is_cve_vuln_id(vuln_id: str) -> bool:
    return vuln_id.lower().startswith("cve-")


def remove_prefix(s: str, prefix: str, /) -> str:
    if s.startswith(prefix):
        return s[len(prefix) :]
    return s[:]
