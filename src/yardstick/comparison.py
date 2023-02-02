import collections
import logging
from dataclasses import InitVar, dataclass, field
from typing import Any, Dict, List, Sequence, Set, Tuple, Union

from dataclasses_json import dataclass_json
from tabulate import tabulate

from yardstick import store, utils
from yardstick.artifact import (  # MatchLabelEntry,
    Label,
    LabelEntry,
    Match,
    Package,
    ScanConfiguration,
    ScanResult,
    Vulnerability,
)
from yardstick.label import find_labels_for_match, label_entry_matches_image_lineage
from yardstick.tool import get_tool


# AgainstLabels compares a scan result against a set of labels
@dataclass_json
@dataclass
class AgainstLabels:
    # basic identifying information
    config: ScanConfiguration = field(init=False)

    label_entries: List[LabelEntry]

    ###################
    # Relative to the matches from the result, which may not be complete

    # { label : [matches with the label] }
    # why not a set? we want to preserve the counts
    matches_by_label: Dict[Label, List[Match]] = field(init=False)

    # { match_id : list(labels found for match) }
    # why not a set? we want to preserve the counts
    labels_by_match: Dict[str, List[Label]] = field(init=False)
    label_entries_by_match: Dict[str, List[LabelEntry]] = field(init=False)

    # matches that:
    # - do not have exactly one label
    # - have an Unclear label
    matches_with_indeterminate_labels: List[Match] = field(init=False)

    ##################
    # Relative to the aggregate of matches from results and MatchLabels

    false_positive_matches: List[Match] = field(
        init=False
    )  # discovered matches in the result where there is a label that is NOT TP
    true_positive_matches: List[Match] = field(init=False)  # discovered matches in the result where there is a TP label found
    false_negative_label_entries: List[LabelEntry] = field(
        init=False
    )  # labels found that indicate TP, but not found as a match in the result

    result: InitVar[ScanResult]
    lineage: InitVar[List[str]]

    fuzzy_package_match: bool = field(default=False)

    def __post_init__(self, result: ScanResult, lineage: List[str]):
        self.config = result.config

        self.matches_by_label = {
            Label.TruePositive: [],
            Label.FalsePositive: [],
            Label.Unclear: [],
        }
        self.labels_by_match = {}
        self.label_entries_by_match = {}
        self.false_negative_label_entries = set(
            l
            for l in self.label_entries
            if label_entry_matches_image_lineage(l, result.config.image, lineage) and l.label == Label.TruePositive
        )
        self.true_positive_matches = []
        self.false_positive_matches = []
        self.matches_with_indeterminate_labels = []

        for match in result.matches:
            # capture matches_by_label & labels_by_match ...
            label_entries = find_labels_for_match(
                result.config.image,
                match,
                self.label_entries,
                lineage=lineage,
                fuzzy_package_match=self.fuzzy_package_match,
            )

            # remove any labels that have been paried with a result match
            self.false_negative_label_entries -= set(label_entries)

            self.label_entries_by_match[match.ID] = label_entries
            self.labels_by_match[match.ID] = [l.label for l in label_entries]
            labels_for_match = self.labels_by_match[match.ID]
            label_set = set(labels_for_match)

            for l in label_set:
                self.matches_by_label[l].append(match)

            # capture any matches that are in an indeterminate state...
            # note: it is important NOT to use a set here, as multiple instances of the same label will throw
            # the F1 score (e.g. [TP, TP ,TP] != [TP], only the latter is acceptable).
            if len(label_set) != 1 or Label.Unclear in labels_for_match:
                self.matches_with_indeterminate_labels.append(match)
                # capture TP & FP only beyond this point...
                continue

            if Label.TruePositive in label_set:
                self.true_positive_matches.append(match)
            elif Label.FalsePositive in label_set:
                self.false_positive_matches.append(match)

        self.summary = LabelComparisonSummary(result=result, comparison=self)

    def __str__(self):
        return str(self.summary)


def _f1_score(tp, fp, fn):
    if tp + fp + fn == 0:
        return 0
    return tp / (tp + (0.5 * (fp + fn)))


@dataclass_json
@dataclass
class LabelComparisonSummary:
    # basic identifying information
    config: ScanConfiguration = field(init=False)

    total: int = field(init=False)
    indeterminate: int = field(init=False)
    indeterminate_percent: float = field(init=False)

    false_positives: float = field(init=False)
    true_positives: float = field(init=False)
    false_negatives: float = field(init=False)

    f1_score: float = field(init=False)
    f1_score_lower_confidence: float = field(init=False)
    f1_score_upper_confidence: float = field(init=False)
    f1_score_is_practicable: bool = field(init=False)

    # note: does NOT support ByMatchComponent (yet?)
    comparison: InitVar[AgainstLabels]
    result: InitVar[ScanResult] = None

    def __post_init__(self, comparison, result):
        self.config = comparison.config  # basic identifying information

        self.total = len(result.matches)
        self.indeterminate = len(comparison.matches_with_indeterminate_labels)
        self.indeterminate_percent = utils.safe_div(self.indeterminate, self.total) * 100
        self.true_positives = len(comparison.true_positive_matches)
        self.false_positives = len(comparison.false_positive_matches)
        self.false_negatives = len(comparison.false_negative_label_entries)

        self.f1_score = _f1_score(self.true_positives, self.false_positives, self.false_negatives)
        self.f1_score_upper_confidence = _f1_score(
            self.true_positives + self.indeterminate, self.false_positives, self.false_negatives
        )
        self.f1_score_lower_confidence = _f1_score(
            self.true_positives, self.false_positives + self.indeterminate, self.false_negatives
        )

        self.f1_score_is_practicable = (
            self.f1_score_upper_confidence - self.f1_score_lower_confidence
        ) <= 0.1  # is less than 10% variance

    def __str__(self):
        lines = []

        lines.append(f"Image: {self.config.image}")
        lines.append(f"Tool: {self.config.tool_name} @ {self.config.tool_version}")

        indent = "    "

        usable = ""
        if not self.f1_score_is_practicable:
            usable = "[IMPRACTICAL]"

        lines.append("Matches:")
        results_table: List[List[Any]] = [
            ["True positive", self.true_positives],
            ["False positive", self.false_positives],
            ["False negative", self.false_negatives],
            ["Indeterminate", f"{self.indeterminate} ({self.indeterminate_percent:0.2f}%)"],
            ["Total", self.total],
        ]

        lines.append(indent + tabulate(results_table, tablefmt="plain").replace("\n", "\n" + indent))

        lines.append(f"F1 score        : {self.f1_score:0.2f}       {usable}")
        lines.append(f"(possible range): {self.f1_score_lower_confidence:0.2f}-{self.f1_score_upper_confidence:0.2f}")

        return "\n".join(lines)


@dataclass(frozen=True)
class EquivalentMatch:
    vulnerability: Vulnerability
    package: Package
    matches: Dict[str, List[Match]]


# ByPreservedMatch achieves the same effect as ByMatch, where set logic considers the relationships of
# packages and vulnerabilities, however, the difference is that all equivalent matches from each respective
# result source is preserved. This is useful in cases where you want to get the common and unique matches
# across multiple result sources, but are also interested into digging into specific elements in each
# record that are unrelated to data used in the set logic (e.g. you want to see the package IDs for each
# match for each record that is equivalent).
@dataclass
class ByPreservedMatch:
    configs: Dict[str, ScanConfiguration] = field(init=False)
    match_set: Dict[str, Set[Match]] = field(init=False)
    common: List[EquivalentMatch] = field(init=False)
    unique: Dict[str, Set[Match]] = field(init=False)

    summary: "RelativeComparisonSummary" = field(init=False)

    results: InitVar[Sequence[ScanResult]] = None

    def __post_init__(self, results: Sequence[ScanResult]):
        self.results = results
        self.configs = {result.ID: result.config for result in results}

        # create a set of matches discovered from each result
        self.match_set = {}
        for result in results:
            self.match_set[result.ID] = set(m for m in result.matches)

        # what set of matches are unique to each result?
        self.unique = {}
        for result in results:
            other_sets = [matches for res_id, matches in self.match_set.items() if res_id != result.ID]
            self.unique[result.ID] = self.match_set[result.ID].difference(*other_sets)

        # what set of matches were discovered across all results? Keep track of each result that matches
        # with any other result --they should be grouped together into a EquivalentMatch
        hashes: Dict[int, List[Tuple[str, Match]]] = collections.defaultdict(list)
        for result_id, matches in self.match_set.items():
            for match in matches:
                hashes[hash(match)].append((result_id, match))

        self.common = []
        for _, matches in hashes.items():
            # only capture matches as "common" if all of the results have a representative
            if len(set(result_id for result_id, _ in matches)) == len(results):
                match_group: Dict[str, List[Match]] = collections.defaultdict(list)
                for result_id, match in matches:
                    match_group[result_id].append(match)

                ex = matches[0][1]
                vuln = Vulnerability(id=ex.vulnerability.id)
                pkg = Package(name=ex.package.name, version=ex.package.version)

                self.common.append(EquivalentMatch(vulnerability=vuln, package=pkg, matches=dict(match_group)))

        self.summary = RelativeComparisonSummary(comparison=self, results=results)

    def __str__(self):
        return str(self.summary)


# ByMatch takes the set() approach, coupling the hash()/eq() logic for Match objects and all children
# and evaluating the results based on python set operations. The upside to this comparator is the ease
# of implementation and groking (common = A intersect B , unique[id] = all other packages not in common),
# the downside is that the original objects from each result group are not captured, only a SINGLE result
# is captured, and which element is selected is arbitrary. This is useful if you are trying to collect
# stats about these groups, and common information (such as package name, version, and vulnerability ID).
# This is not useful if you need the original records from all result sets which are equivalent, in that
# case use ByPreservedMatch.
@dataclass
class ByMatch:
    configs: Dict[str, ScanConfiguration] = field(init=False)
    match_set: Dict[str, Set[Match]] = field(init=False)
    common: Set[Match] = field(init=False)
    unique: Dict[str, Set[Match]] = field(init=False)

    summary: "RelativeComparisonSummary" = field(init=False)

    results: InitVar[Sequence[ScanResult]] = None

    def __post_init__(self, results: Sequence[ScanResult]):
        self.results = results
        self.configs = {result.ID: result.config for result in results}

        # create a set of matches discovered from each result
        self.match_set = {}
        for result in results:
            self.match_set[result.ID] = set(m for m in result.matches)

        # what set of matches were discovered across all results?
        self.common = set.intersection(*self.match_set.values())

        # what set of matches are unique to each result?
        self.unique = {}
        for result in results:
            other_sets = [matches for res_id, matches in self.match_set.items() if res_id != result.ID]
            self.unique[result.ID] = self.match_set[result.ID].difference(*other_sets)

        self.summary = RelativeComparisonSummary(comparison=self, results=results)

    def __str__(self):
        return str(self.summary)


# ByVulnerability looks solely at at matches vulnerability for comparison. This alone isn't an accurate comparison,
# however, if you have two tools that have different package name/version extraction algorithms that result in
# slightly different values, this comparison is a fair proxy for answering the question "did both tools find the
# same CVEs or different CVEs for the same image".
@dataclass
class ByVulnerability:
    configs: Dict[str, ScanConfiguration] = field(init=False)
    vulnerabilities: Dict[str, List[Vulnerability]] = field(init=False)
    vulnerability_set_by_result_id: Dict[str, Set[Vulnerability]] = field(init=False)
    common: Set[Vulnerability] = field(init=False)
    unique: Dict[str, Set[Vulnerability]] = field(init=False)

    results: InitVar[Sequence[ScanResult]] = None

    def __post_init__(self, results: Sequence[ScanResult]):
        self.results = results
        self.configs = {result.ID: result.config for result in results}

        # create a set of vulnerabilities discovered from each result
        self.vulnerability_set_by_result_id = {}
        self.vulnerabilities = {}
        for result in results:
            self.vulnerabilities[result.ID] = [m.vulnerability.id for m in result.matches]
            self.vulnerability_set_by_result_id[result.ID] = set(self.vulnerabilities[result.ID])

        # what set of vulnerabilities were discovered across all results?
        self.common = set.intersection(*self.vulnerability_set_by_result_id.values())

        # what set of vulnerabilities are unique to each result?
        self.unique = {}
        for result in results:
            other_sets = [
                vulnerabilities for res_id, vulnerabilities in self.vulnerability_set_by_result_id.items() if res_id != result.ID
            ]
            self.unique[result.ID] = self.vulnerability_set_by_result_id[result.ID].difference(*other_sets)


# ByPackage looks solely at at matches package info for comparison. This alone isn't an accurate comparison,
# however, if you have two tools that have different package name/version extraction algorithms that result in
# slightly different values, this comparison is a fair proxy for answering the question "did both tools find the
# same packages or different packages for the same image (with respect to match findings)".
@dataclass
class ByPackage:
    configs: Dict[str, ScanConfiguration] = field(init=False)
    packages: Dict[str, List[Package]] = field(init=False)
    package_set_by_result_id: Dict[str, Set[Package]] = field(init=False)
    common: Set[Package] = field(init=False)
    unique: Dict[str, Set[Package]] = field(init=False)

    results: InitVar[Sequence[ScanResult]] = None

    def __post_init__(self, results: Sequence[ScanResult]):
        self.results = results
        self.configs = {result.ID: result.config for result in results}

        # create a set of packages discovered from each result
        self.package_set_by_result_id = {}
        self.packages = {}
        for result in results:
            self.packages[result.ID] = [m.package for m in result.matches]
            self.package_set_by_result_id[result.ID] = set(self.packages[result.ID])

        # what set of packages were discovered across all results?
        self.common = set.intersection(*self.package_set_by_result_id.values())

        # what set of packages are unique to each result?
        self.unique = {}
        for result in results:
            other_sets = [packages for res_id, packages in self.package_set_by_result_id.items() if res_id != result.ID]
            self.unique[result.ID] = self.package_set_by_result_id[result.ID].difference(*other_sets)


@dataclass_json
@dataclass
class ComponentSummary:
    # count of matches found in all result sets
    deduplicated_common_count: int = field(init=False)

    # count of all matches for a result set
    total_count: Dict[str, int] = field(init=False)

    # count of all matches that are unique within each result set
    deduplicated_total_count: Dict[str, int] = field(init=False)

    # matches found only in each result set
    deduplicated_unique_count: Dict[str, int] = field(init=False)

    # this is the same as the F1 score, but an F1 score is typically relative to a ground truth, where as dice
    # similarity does not imply this... it is a measure of the similarity of two samples without an assumption that one
    # of the samples is a ground truth (a small but important semantic difference).
    dice_similarity_coefficient: float = field(init=False)

    # elements needed to compute the summary
    common: InitVar[Sequence[Any]]
    originals: InitVar[Dict[str, Sequence[Any]]]
    uniques: InitVar[Dict[str, Sequence[Any]]]

    def __post_init__(self, common: Sequence[Any], originals: Dict[str, Sequence[Any]], uniques: Dict[str, Sequence[Any]]):
        if originals.keys() != uniques.keys():
            raise RuntimeError(f"mismatched component elements: {originals.keys()} {uniques.keys()}")
        self.deduplicated_common_count = len(common)
        self.total_count = {}
        self.deduplicated_total_count = {}
        self.deduplicated_unique_count = {}
        for parent_id, items in originals.items():
            self.total_count[parent_id] = len(items)
            self.deduplicated_total_count[parent_id] = len(set(items))
            self.deduplicated_unique_count[parent_id] = len(set(uniques[parent_id]))

        # | A intersect B | / | A union B | = | A intersect B | / ((| A | + | B |) - | A intersect B |)
        # note: this is done on the count of SETs of matches... we are ignore duplicates here
        # why? because the common count is a set, so we cannot use non-set counts for the two data groups.
        jaccard_similarity = utils.safe_div(
            self.deduplicated_common_count, sum(self.deduplicated_total_count.values()) - self.deduplicated_common_count
        )
        # now we can easily compute the dice similarity...
        self.dice_similarity_coefficient = (2 * jaccard_similarity) / (jaccard_similarity + 1)


@dataclass_json
@dataclass
class RelativeComparisonSummary:
    # basic identifying information
    configs: Dict[str, ScanConfiguration] = field(init=False)

    match_component: ComponentSummary = field(init=False)
    vulnerability_component: ComponentSummary = field(init=False)
    package_component: ComponentSummary = field(init=False)

    # note: does NOT support ByMatchComponent (yet?)
    comparison: InitVar[Union[ByPreservedMatch, ByMatch]]
    results: InitVar[Sequence[ScanResult]] = None

    def __post_init__(self, comparison, results):
        self.configs = comparison.configs  # basic identifying information
        self.match_component = ComponentSummary(
            common=comparison.common,
            # note: this is the original LIST, not de-duplicated set
            originals={result.ID: result.matches for result in results},
            uniques=comparison.unique,
        )

        # once you see the dice similarity, you may want to see other kinds of comparisons to determine why the similarity
        # is what it is. This is where a comparison by sub-components could help.
        comparison_by_vulnerabilities = ByVulnerability(results)
        self.vulnerability_component = ComponentSummary(
            common=comparison_by_vulnerabilities.common,
            # note: this is the original LIST, not de-duplicated set
            originals=comparison_by_vulnerabilities.vulnerabilities,
            uniques=comparison_by_vulnerabilities.unique,
        )

        comparison_by_packages = ByPackage(results)
        self.package_component = ComponentSummary(
            common=comparison_by_packages.common,
            # note: this is the original LIST, not de-duplicated set
            originals=comparison_by_packages.packages,
            uniques=comparison_by_packages.unique,
        )

    def __str__(self):
        lines = []

        if len(set(config.image for _, config in self.configs.items())) == 1:
            lines.append(f"Image: {list(self.configs.values())[0].image}")

        indent = "    "

        results_table: List[List[Any]] = [
            [
                "TOOL",
                "MATCHES",
                "",
                "PACKAGES",
                "VULNERABILITES",
            ]
        ]
        for result_id, config in self.configs.items():
            results_table.append(
                [
                    config.tool,
                    self.match_component.total_count[result_id],
                    f"({self.match_component.deduplicated_total_count[result_id]} unique)",
                    self.package_component.deduplicated_total_count[result_id],
                    self.vulnerability_component.deduplicated_total_count[result_id],
                ]
            )

        lines.append(indent + tabulate(results_table, tablefmt="plain").replace("\n", "\n" + indent) + "\n")

        lines.append("Comparison Results (deduplicated): ")

        table: List[List[Any]] = [
            [
                "TOOL",
                "MATCHES",
                "PACKAGES",
                "VULNERABILITES",
            ]
        ]
        table.append(
            [
                "(common to all)",
                f"{self.match_component.deduplicated_common_count}",
                f"{self.package_component.deduplicated_common_count}",
                f"{self.vulnerability_component.deduplicated_common_count}",
            ],
        )

        for result_id, config in self.configs.items():
            table.append(
                [
                    f"unique to {config.tool}",
                    self.match_component.deduplicated_unique_count[result_id],
                    self.package_component.deduplicated_unique_count[result_id],
                    self.vulnerability_component.deduplicated_unique_count[result_id],
                ]
            )

        lines.append(indent + tabulate(table, tablefmt="plain").replace("\n", "\n" + indent) + "\n")

        lines.append(f"Package similarity       : {self.package_component.dice_similarity_coefficient:0.2f}")
        lines.append(f"Vulnerability similarity : {self.vulnerability_component.dice_similarity_coefficient:0.2f}")
        lines.append(f"Match similarity         : {self.match_component.dice_similarity_coefficient:0.2f}")
        return "\n".join(lines)


@dataclass(frozen=True)
class ImageToolLabelStats:
    indeterminate: dict[str, dict[str, int]] = field(
        default_factory=lambda: collections.defaultdict(lambda: collections.defaultdict(int))
    )
    indeterminate_percent: dict[str, dict[str, str]] = field(default_factory=lambda: collections.defaultdict(dict))
    true_positives: dict[str, dict[str, int]] = field(
        default_factory=lambda: collections.defaultdict(lambda: collections.defaultdict(int))
    )
    false_positives: dict[str, dict[str, int]] = field(
        default_factory=lambda: collections.defaultdict(lambda: collections.defaultdict(int))
    )
    false_negatives: dict[str, dict[str, int]] = field(
        default_factory=lambda: collections.defaultdict(lambda: collections.defaultdict(int))
    )
    f1_scores: dict[str, dict[str, float]] = field(default_factory=lambda: collections.defaultdict(dict))
    f1_score_ranges: dict[str, dict[str, str]] = field(default_factory=lambda: collections.defaultdict(dict))

    @property
    def images(self):
        return sorted(self.f1_scores.keys())

    @property
    def tools(self):
        tools = set()
        for image in self.f1_scores:
            tools.update(self.f1_scores[image].keys())
        return sorted(list(tools))

    @staticmethod
    def new(comparisons: List[AgainstLabels]) -> "ImageToolLabelStats":
        indeterminate: dict[str, dict[str, int]] = collections.defaultdict(lambda: collections.defaultdict(int))
        indeterminate_percent: dict[str, dict[str, str]] = collections.defaultdict(dict)
        true_positives: dict[str, dict[str, int]] = collections.defaultdict(lambda: collections.defaultdict(int))
        false_positives: dict[str, dict[str, int]] = collections.defaultdict(lambda: collections.defaultdict(int))
        false_negatives: dict[str, dict[str, int]] = collections.defaultdict(lambda: collections.defaultdict(int))
        f1_scores: dict[str, dict[str, float]] = collections.defaultdict(dict)
        f1_score_ranges: dict[str, dict[str, str]] = collections.defaultdict(dict)

        for comp in comparisons:
            image = comp.config.image
            tool = comp.config.tool

            if comp.summary.f1_score_is_practicable:
                f1_scores[image][tool] = comp.summary.f1_score
            else:
                f1_scores[image][tool] = -1

            if comp.summary.f1_score_lower_confidence != 0 and comp.summary.f1_score_upper_confidence != 0:
                f1_score_ranges[image][tool] = (
                    comp.summary.f1_score_lower_confidence,
                    comp.summary.f1_score_upper_confidence,
                )

            false_negatives[image][tool] = comp.summary.false_negatives
            true_positives[image][tool] = comp.summary.true_positives
            false_positives[image][tool] = comp.summary.false_positives
            indeterminate[image][tool] = comp.summary.indeterminate
            indeterminate_percent[image][tool] = utils.safe_div(comp.summary.indeterminate, comp.summary.total) * 100.0

        return ImageToolLabelStats(
            indeterminate=indeterminate,
            indeterminate_percent=indeterminate_percent,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            f1_scores=f1_scores,
            f1_score_ranges=f1_score_ranges,
        )


def of_results_against_label(
    *results: ScanResult,
    label_entries,
    fuzzy_package_match: bool = False,
) -> tuple[dict[str, list[AgainstLabels]], ImageToolLabelStats]:
    logging.info("starting comparison against labels")

    comparisons_by_result_id = {}

    comparisons = []
    for result in results:
        logging.info(f"comparing labels for image={result.config.image} tool={result.config.tool}")

        lineage = store.image_lineage.get(image=result.config.image)
        comp = AgainstLabels(result=result, label_entries=label_entries, lineage=lineage, fuzzy_package_match=fuzzy_package_match)
        comparisons_by_result_id[result.ID] = comp
        comparisons.append(comp)

    # { image : {tool@version : F1 score or "I" if impractical }  }
    stats_by_image_tool_pair = ImageToolLabelStats.new(comparisons)

    return comparisons_by_result_id, stats_by_image_tool_pair


@dataclass
class ToolLabelStatsByEcosystem:
    tps_by_tool_by_ecosystem: dict[str, dict[str, int]] = field(
        default_factory=lambda: collections.defaultdict(lambda: collections.defaultdict(int))
    )
    fps_by_tool_by_ecosystem: dict[str, dict[str, int]] = field(
        default_factory=lambda: collections.defaultdict(lambda: collections.defaultdict(int))
    )
    precision_by_tool_by_ecosystem: dict[str, dict[str, int]] = field(
        default_factory=lambda: collections.defaultdict(lambda: collections.defaultdict(int))
    )
    tools: list[str] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)

    @staticmethod
    def new(comparisons_by_result_id_by_image: dict[str, list[dict[str, AgainstLabels]]]) -> "ToolLabelStatsByEcosystem":
        stats = ToolLabelStatsByEcosystem()

        def normalize_ecosystem(e: str) -> str:
            e = e.lower().replace("-", "_")
            if e in ("java_archive", "jenkins_plugin"):
                return "java"
            return e

        def ecosystem(match: Match) -> str:
            t = get_tool(match.config.tool_name)
            package_type = t.parse_package_type(match.fullentry)
            return normalize_ecosystem(package_type)

        tools = set()
        ecosystems = set()
        for _, comparisons in comparisons_by_result_id_by_image.items():
            for comparisons_by_result_id in comparisons:
                for _, comp in comparisons_by_result_id.items():
                    tool = comp.config.tool
                    tools.add(tool)

                    for tp in comp.true_positive_matches:
                        e = ecosystem(tp)
                        ecosystems.add(e)
                        stats.tps_by_tool_by_ecosystem[tool][e] += 1

                    for fp in comp.false_positive_matches:
                        e = ecosystem(fp)
                        ecosystems.add(e)
                        stats.fps_by_tool_by_ecosystem[tool][e] += 1

        stats.tools = sorted(list(tools))
        stats.ecosystems = sorted(list(ecosystems))

        # calculate precision
        for tool in tools:
            for e in ecosystems:
                stats.precision_by_tool_by_ecosystem[tool][e] = utils.safe_div(
                    stats.tps_by_tool_by_ecosystem[tool][e],
                    stats.tps_by_tool_by_ecosystem[tool][e] + stats.fps_by_tool_by_ecosystem[tool][e],
                )

        return stats


def of_results_against_label_by_ecosystem(
    results_by_image: dict[str, ScanResult],
    label_entries,
    fuzzy_package_match: bool = False,
) -> ToolLabelStatsByEcosystem:
    comparisons_by_result_id_by_image = collections.defaultdict(list)
    for image, results in results_by_image.items():
        comparisons_by_result_id, _ = of_results_against_label(
            *results,
            fuzzy_package_match=fuzzy_package_match,
            label_entries=label_entries,
        )
        comparisons_by_result_id_by_image[image].append(comparisons_by_result_id)

    return ToolLabelStatsByEcosystem.new(comparisons_by_result_id_by_image)
