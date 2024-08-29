import re
import sys

import click
from tabulate import tabulate
from dataclasses import dataclass

import yardstick
from yardstick import store, validate as val
from yardstick.cli import display, config
from yardstick.validate import Gate, GateInputDescription

# see the .yardstick.yaml configuration for details
# TODO: remove this; package specific
default_result_set = "pr_vs_latest_via_sbom"
yardstick.utils.grype_db.raise_on_failure(False)


@dataclass
class GateConfig:
    max_f1_decrease: float = 0.0
    max_unlabeled_match_percent: int = 0
    max_new_false_negatives: int = 0


def guess_tool_orientation(tools: list[str]):
    """
    Given a pair of tools, guess which is latest version, and which is the one
    being compared to the latest version.
    Returns (latest_tool, current_tool)
    """
    if len(tools) != 2:
        raise RuntimeError("expected 2 tools, got %s" % tools)
    tool_a, tool_b = sorted(tools)
    if tool_a == tool_b:
        raise ValueError("latest release tool and current tool are the same")
    if tool_a.endswith("latest"):
        return tool_a, tool_b
    elif tool_b.endswith("latest"):
        return tool_b, tool_a

    if "@path:" in tool_a and "@path:" not in tool_b:
        # tool_a is a local build, so compare it against tool_b
        return tool_b, tool_a

    if "@path:" in tool_b and "@path:" not in tool_a:
        # tool_b is a local build, so compare it against tool_a
        return tool_a, tool_b

    return tool_a, tool_b


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


if not sys.stdout.isatty():
    bcolors.HEADER = ""
    bcolors.OKBLUE = ""
    bcolors.OKCYAN = ""
    bcolors.OKGREEN = ""
    bcolors.WARNING = ""
    bcolors.FAIL = ""
    bcolors.BOLD = ""
    bcolors.UNDERLINE = ""
    bcolors.RESET = ""


@click.command()
@click.pass_obj
@click.option(
    "--image",
    "-i",
    "images",
    multiple=True,
    help="filter down to one or more images to validate with (don't use the full result set)",
)
@click.option(
    "--label-comparison",
    "-l",
    "always_run_label_comparison",
    is_flag=True,
    help="run label comparison irregardless of relative comparison results",
)
@click.option(
    "--breakdown-by-ecosystem",
    "-e",
    is_flag=True,
    help="show label comparison results broken down by ecosystem",
)
@click.option(
    "--verbose", "-v", "verbosity", count=True, help="show details of all comparisons"
)
@click.option(
    "--result-set",
    "-r",
    default=default_result_set,
    help="the result set to use for the quality gate",
)
def validate(
    cfg: config.Application,
    images: list[str],
    always_run_label_comparison: bool,
    breakdown_by_ecosystem: bool,
    verbosity: int,
    result_set: str,
):
    setup_logging(verbosity)

    # let's not load any more labels than we need to, base this off of the images we're validating
    if not images:
        unique_images = set()
        result_set_obj = store.result_set.load(name=result_set)
        for state in result_set_obj.state:
            unique_images.add(state.config.image)
        images = sorted(list(unique_images))

    print("Loading label entries...", end=" ")
    label_entries = store.labels.load_for_image(
        images, year_max_limit=cfg.max_year_for_result_set(result_set)
    )
    print(f"done! {len(label_entries)} entries loaded")

    result_sets = [
        result_set
    ]  # today only one result set is supported, but more can be added
    gates = []
    for result_set in result_sets:
        rs_config = cfg.result_sets[result_set]
        for gate_config in rs_config.validations:
            new_gates = val.validate_result_set(
                gate_config,
                result_set,
                images=images,
                always_run_label_comparison=always_run_label_comparison,
                verbosity=verbosity,
                label_entries=label_entries,
            )
            for gate in new_gates:
                show_results_used(gate.result_descriptions)
                show_delta_commentary(gate)

            gates.extend(new_gates)
        print()

        if breakdown_by_ecosystem:
            print(
                f"{bcolors.HEADER}Breaking down label comparison by ecosystem performance...",
                bcolors.RESET,
            )
            results_by_image, label_entries, stats = (
                yardstick.compare_results_against_labels_by_ecosystem(
                    result_set=result_set,
                    year_max_limit=cfg.max_year_for_result_set(result_set),
                    label_entries=label_entries,
                )
            )
            display.labels_by_ecosystem_comparison(
                results_by_image,
                stats,
                show_images_used=False,
            )
            print()

    failure = not all([gate.passed() for gate in gates])
    if failure:
        print("Reasons for quality gate failure:")
    for gate in gates:
        for reason in gate.reasons:
            print(f"   - {reason}")

    if failure:
        print()
        print(f"{bcolors.FAIL}{bcolors.BOLD}Quality gate FAILED{bcolors.RESET}")
        sys.exit(1)
    else:
        print(f"{bcolors.OKGREEN}{bcolors.BOLD}Quality gate passed!{bcolors.RESET}")


def setup_logging(verbosity: int):
    # pylint: disable=redefined-outer-name, import-outside-toplevel
    import logging.config

    if verbosity in [0, 1, 2]:
        log_level = "WARN"
    elif verbosity == 3:
        log_level = "INFO"
    else:
        log_level = "DEBUG"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
                    # [%(module)s.%(funcName)s]
                    "format": "%(asctime)s [%(levelname)s] %(message)s",
                    "datefmt": "",
                },
            },
            "handlers": {
                "default": {
                    "level": log_level,
                    "formatter": "standard",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "": {  # root logger
                    "handlers": ["default"],
                    "level": log_level,
                },
            },
        }
    )


def show_delta_commentary(gate: Gate):
    if not gate.deltas:
        print("No differences found between tooling (with labels)")

    header_row = ["TOOL PARTITION", "PACKAGE", "VULNERABILITY", "LABEL", "COMMENTARY"]

    all_rows = []
    for delta in gate.deltas:
        color = ""
        if delta.is_improved:
            color = bcolors.OKBLUE
        elif delta.is_improved is not None and not delta.is_improved:
            color = bcolors.FAIL
        all_rows.append(
            [
                f"{color}{delta.tool} ONLY{bcolors.RESET}",
                f"{color}{delta.package_name}@{delta.package_version}{bcolors.RESET}",
                f"{color}{delta.vulnerability_id}{bcolors.RESET}",
                f"{color}{delta.label}{bcolors.RESET}",
                f"{delta.commentary}",
            ]
        )

    def escape_ansi(line):
        ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
        return ansi_escape.sub("", line)

    # sort but don't consider ansi escape codes
    all_rows = sorted(
        all_rows, key=lambda x: escape_ansi(str(x[0] + x[1] + x[2] + x[3]))
    )
    print("Match differences between tooling (with labels):")
    indent = "   "
    print(
        indent
        + tabulate(
            [header_row] + all_rows,
            tablefmt="plain",
        ).replace("\n", "\n" + indent)
        + "\n"
    )


def show_results_used(results: list[GateInputDescription]):
    print("   Results used:")
    for idx, description in enumerate(results):
        branch = "├──"
        if idx == len(results) - 1:
            branch = "└──"
        label = " "
        if len(description.tool_label) > 0:
            label = f" ({description.tool_label}) "
        print(
            f"    {branch} {description.result_id} : {description.tool}{label} against {description.image}"
        )
    print()
