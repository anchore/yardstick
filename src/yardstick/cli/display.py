import colorsys
import json
from typing import Any, Union

from colr import color
from tabulate import tabulate

from yardstick import artifact, comparison


def summarize(comp: Union[comparison.ByPreservedMatch, comparison.ByMatch]):
    print(str(comp))


def preserved_matches(comp: comparison.ByPreservedMatch, details=True, summary=True, common=True):
    if details:
        if common:
            for common_match in comp.common:
                print("common ", common_match)
            print()

        all_rows: list[list[Any]] = []
        for result in comp.results:
            for unique_match in comp.unique[result.ID]:
                all_rows.append(
                    [
                        f"{result.config.tool_name}-{result.config.tool_version}-only",
                        unique_match.package.name,
                        unique_match.package.version,
                        unique_match.vulnerability.id,
                    ]
                )

        all_rows = sorted(all_rows)

        if len(all_rows) == 0:
            print("All results are the same (no differences found)\n")
        else:
            print(tabulate(all_rows, tablefmt="plain"))

    if summary:
        summarize(comp)


def matches(comp: comparison.ByMatch, details=True, summary=True, common=True):
    if details:
        if common:
            for match in comp.common:
                print("common ", match)

        all_rows: list[list[Any]] = []
        for result in comp.results:
            for match in comp.unique[result.ID]:
                all_rows.append(
                    [
                        f"{result.config.tool_name}-{result.config.tool_version}-only",
                        match.package.name,
                        match.package.version,
                        match.vulnerability.id,
                    ]
                )

        all_rows = sorted(all_rows)
        print(tabulate(all_rows, tablefmt="plain"))

    if summary:
        summarize(comp)


#############################################################################################################
# For label comparisons


def get_section_rgb_tuple(index, sections):
    half_sections = int(sections / 2)
    red_hsv_tuples = list(reversed([(0, float(x) / float(half_sections - 1), 1) for x in range(half_sections)]))
    green_hsv_tuples = [(0.33, float(x) / float(half_sections - 1), 1) for x in range(half_sections)]
    spectrum = red_hsv_tuples + green_hsv_tuples
    values = list(map(lambda x: colorsys.hsv_to_rgb(*x), spectrum))[index]
    return values[0] * 255, values[1] * 255, values[2] * 255


def get_section_index(value, min_value, max_value, sections, invert):
    value = min(max(value, min_value), max_value)
    value_ratio = float(value - min_value) / float(max_value - min_value)
    if invert:
        value_ratio = 1.0 - value_ratio
    return min(max(int(sections * value_ratio), 0), sections - 1), value_ratio


def format_value_red_green_spectrum(value, min_value=0, max_value=1, sections=10, invert=False):
    index, value_ratio = get_section_index(value, min_value, max_value, sections, invert)
    color_rgb_tuple = get_section_rgb_tuple(index, sections)

    formatted_value = color(f"{value:6.2f}", fore=color_rgb_tuple)

    if value_ratio > 0.9:
        # bold
        formatted_value = "\033[1m" + formatted_value
    if value_ratio > 0.95:
        # underline
        formatted_value = "\033[4m" + formatted_value
    return formatted_value


def format_percent(value: float) -> str:
    if value < 0:
        return ""
    return (
        "("
        + format_value_red_green_spectrum(
            value,
            min_value=0,
            max_value=50,
            invert=True,
        )
        + " %)"
    )


# pylint: disable=too-many-statements
def show_label_comparison_summary(stats_by_image_tool_pair: comparison.ImageToolLabelStats):
    tools = stats_by_image_tool_pair.tools
    images = stats_by_image_tool_pair.images

    def summarize_by_tool(
        title, tp, fp, fn, intedeterminate, intedeterminate_percent, f1, f1_ranges
    ):  # pylint: disable=too-many-arguments
        header = ["", "TP", "FP", "FN", "Indeterminate", "F1 Score", "F1 Score Range"]
        all_rows = []
        for tool in sorted(list(tools)):
            f1r = ""
            if f1_ranges.get(tool, None) and f1.get(tool, -1) > 0:
                f1r = f"{f1_ranges[tool][0]:0.2f}-{f1_ranges[tool][1]:0.2f}"

            f1s = ""
            if f1.get(tool, -1) > 0:
                f1s = f"{format_value_red_green_spectrum(f1.get(tool))}"

            row = [
                tool,
                tp.get(tool, ""),
                fp.get(tool, ""),
                fn.get(tool, ""),
                f"{intedeterminate.get(tool, '')} {format_percent(intedeterminate_percent.get(tool, -1))}",
                f1s,
                f1r,
            ]
            all_rows.append(row)

        print(f"~~~ {title!r} Summary (by Tool) ~~~")
        print(tabulate(all_rows, tablefmt="simple", headers=header))

    def summarize_across_images(title, description, source, context_source=None):
        header = [""] + sorted(list(tools))
        all_rows = []
        for image in sorted(list(i for i in images)):  # pylint: disable=unnecessary-comprehension # we are using a copy of images
            row = [image]
            for tool in sorted(list(tools)):
                # why \0? to prevent from tabulate from stripping the whitespace
                cell = f"\0{source[image].get(tool, ''):-5}"
                if context_source:
                    cell += f" {context_source[image].get(tool, None):7}"
                row.append(cell)

            all_rows.append(row)

        print(f"\n\n\n~~~ {title} Summary ~~~")
        if description:
            print(f"\n{description}")
        print(tabulate(all_rows, tablefmt="simple", headers=header))

    for image in images:
        summarize_by_tool(
            image,
            stats_by_image_tool_pair.true_positives[image],
            stats_by_image_tool_pair.false_positives[image],
            stats_by_image_tool_pair.false_negatives[image],
            stats_by_image_tool_pair.indeterminate[image],
            stats_by_image_tool_pair.indeterminate_percent[image],
            stats_by_image_tool_pair.f1_scores[image],
            stats_by_image_tool_pair.f1_score_ranges[image],
        )

    summarize_across_images(
        "False Negative",
        """\
Ideally FNs for a vuln scanner is 0, which means that all possible known vulnerabilities that could have been
reported were (relative to the label data). So each FN is a missed vulnerability match for the tool-image pair.

Each FN entry for each tool-image pair is logged above.""",
        stats_by_image_tool_pair.false_negatives,
    )

    summarize_across_images(
        "Indeterminate Label",
        """\
Ideally there should be no indeterminate labels. The more indeterminate labels there are the wider the F1
score range is. An indeterminate label is either an explicit label of "?" or there is more that one label
for a match that is in conflict (there is a TP and a FP).

Each indeterminate match for each tool-image pair is logged above.""",
        stats_by_image_tool_pair.indeterminate,
        context_source={
            image: {tool: format_percent(value) for tool, value in values.items()}
            for image, values in stats_by_image_tool_pair.indeterminate_percent.items()
        },
    )

    # F1 Summary
    header = [""] + sorted(list(tools))
    all_rows = []
    for image in sorted(i for i in images):  # pylint: disable=unnecessary-comprehension # we are using a copy of images
        row = [image]
        for tool in sorted(list(tools)):
            f1_score = stats_by_image_tool_pair.f1_scores[image].get(tool, None)

            if f1_score and f1_score > 0:
                lower, upper = stats_by_image_tool_pair.f1_score_ranges[image].get(tool, (-1, -1))
                if lower == -1 or upper == -1:
                    f1_score = "error!"
                else:
                    f1_score = f"{format_value_red_green_spectrum(f1_score)} ({lower:0.2f}-{upper:0.2f})"
            elif f1_score < 0:
                lower, upper = stats_by_image_tool_pair.f1_score_ranges[image].get(tool, (-1, -1))
                if lower == -1 or upper == -1:
                    f1_score = "error!"
                else:
                    f1_score = color(f"Impractical ({lower:0.2f}-{upper:0.2f})", fore="red")
            else:
                f1_score = ""
            row.append(f1_score)

        all_rows.append(row)

    print("\n\n~~~ F1 Score Summary ~~~\n")
    print(
        """\
Ideally the F1 score for an image-tool pair should be 1. F1 score combines the TP, FP, and FN counts into a
single metric between 0 and 1. This helps summarize the matching performance but does not explain why the
matching performance is what it is.

Also, each F1 score is given a possible range based on how much label data is available. The more data that
is available, the smaller the range. Large ranges are not evaluated and the F1 score is overall deemed
Impractical.

See the TP/FP/FN counts for the tool-image sections logged above for more context."""
    )
    print(tabulate(all_rows, tablefmt="simple", headers=header))


def label_comparison_json(
    results: list[artifact.ScanResult],
    comparisons_by_result_id: dict[str, comparison.AgainstLabels],
    stats_by_image_tool_pair: comparison.ImageToolLabelStats,
    show_fns: bool,
    show_indeterminates: bool,
):
    ret = []

    for result in results:
        comp = comparisons_by_result_id[result.ID]
        image = comp.config.image
        tool = comp.config.tool

        more = {}

        if show_fns:
            more["fns"] = [l.to_dict() for l in comp.false_negative_label_entries]

        if show_indeterminates:
            more["indeterminate"] = []
            for match in comp.matches_with_indeterminate_labels:
                more["indeterminate"].append(
                    {
                        "match": match.to_dict(),
                        "label_set": sorted([l.display for l in set(comp.labels_by_match.get(match.ID, []))]),
                        "labels": [l.to_dict() for l in comp.label_entries_by_match.get(match.ID, [])],
                    }
                )

        ret.append(
            {
                "image": image,
                "tool": tool,
                "stats": {
                    "f1_score": stats_by_image_tool_pair.f1_scores[image][tool],
                    "f1_score_range": stats_by_image_tool_pair.f1_score_ranges[image][tool],
                    "fn": stats_by_image_tool_pair.false_negatives[image][tool],
                    "tp": stats_by_image_tool_pair.true_positives[image][tool],
                    "fp": stats_by_image_tool_pair.false_positives[image][tool],
                    "indeterminate": stats_by_image_tool_pair.indeterminate[image][tool],
                    "indeterminate_percent": stats_by_image_tool_pair.indeterminate_percent[image][tool],
                },
                **more,
            }
        )

    print(json.dumps(ret, indent=2))


# pylint: disable=too-many-arguments
def label_comparison(
    results: list[artifact.ScanResult],
    comparisons_by_result_id: dict[str, comparison.AgainstLabels],
    stats_by_image_tool_pair: comparison.ImageToolLabelStats,
    show_fns: bool = False,
    show_indeterminates: bool = False,
    show_summaries: bool = True,
):
    for result in results:
        comp = comparisons_by_result_id[result.ID]

        # show the results
        if show_summaries:
            print(str(comp))
            print()

        if show_fns:
            print("False Negative Label Entries: ", len(comp.false_negative_label_entries))
            for l in comp.false_negative_label_entries:
                print("   ", l.summarize())
            print()

        if show_indeterminates:
            print("Indeterminate Matches: ", len(comp.matches_with_indeterminate_labels))
            for match in comp.matches_with_indeterminate_labels:
                print("   ", match, f"from {match.config.tool_name}@{match.config.tool_version}")
                match_labels = comp.label_entries_by_match.get(match.ID, [])
                if match_labels:
                    print("    Label Set: ", set(comp.labels_by_match.get(match.ID, [])))
                for l in match_labels:
                    print("      ", l.summarize(), "\n")
                if not match_labels:
                    print("      [no labels paired]\n")
            print()

        if show_summaries or show_fns or show_indeterminates:
            print("\n\n")

    if show_summaries:
        show_label_comparison_summary(stats_by_image_tool_pair)


# pylint: disable=too-many-arguments,too-many-locals
def labels_by_ecosystem_comparison(
    results_by_image: dict[str, artifact.ScanResult],
    stats: comparison.ToolLabelStatsByEcosystem,
    show_images_used: bool = True,
):
    if show_images_used:
        print("Images used:")
        for image in results_by_image.keys():
            print(f"  {image}")

    # show table per-tool... rows are ecosystems and columns are TPs, FPs, Precision
    for tool in stats.tools:
        header = [
            "",
            "TPs",
            "FPs",
            "Precision",
        ]
        all_rows = []
        for e in stats.ecosystems:
            row = [
                e,
                stats.tps_by_tool_by_ecosystem[tool][e],
                stats.fps_by_tool_by_ecosystem[tool][e],
                format_value_red_green_spectrum(stats.precision_by_tool_by_ecosystem[tool][e]),
            ]
            all_rows.append(row)

        tps = sum([stats.tps_by_tool_by_ecosystem[tool][e] for e in stats.ecosystems])  # pylint: disable=consider-using-generator
        fps = sum([stats.fps_by_tool_by_ecosystem[tool][e] for e in stats.ecosystems])  # pylint: disable=consider-using-generator
        d = tps + fps
        precision = 0.0
        if d:
            precision = float(tps) / float(d)
        all_rows.append(
            [
                "[overall] --->",
                tps,
                fps,
                format_value_red_green_spectrum(precision),
            ]
        )

        print(f"\n~~~ {tool!r} Ecosystem Breakdown (across all images) ~~~")
        print(tabulate(all_rows, tablefmt="simple", headers=header))
        print()

    print(
        """\
Note: precision is inversely proportional to the false positive rate, so the lower the precision the
more false positives are negatively affecting the results.
"""
    )
