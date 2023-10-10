import collections
from typing import Dict, List, Set

from yardstick import artifact


def packages_by_vulnerability(
    matches: List[artifact.Match],
) -> Dict[artifact.Vulnerability, Set[artifact.Package]]:
    result: Dict[artifact.Vulnerability, Set[artifact.Package]] = {
        m.vulnerability: set() for m in matches
    }
    for match in matches:
        result[match.vulnerability].add(match.package)
    return result


def scan_results_by_image(
    results: list[artifact.ScanResult],
) -> Dict[str, list[artifact.ScanResult]]:
    results_by_image = collections.defaultdict(list)
    for r in results:
        results_by_image[r.config.image].append(r)
    return results_by_image
