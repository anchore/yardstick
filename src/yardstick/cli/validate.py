import re
import sys

import click
from tabulate import tabulate

import yardstick
from yardstick import store
from yardstick import validate as val
from yardstick.cli import config, display
from yardstick.validate import Gate, GateInputDescription


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
    "result_sets",
    multiple=True,
    default=[],
    help="the result set to use for the quality gate",
)
@click.option(
    "--all",
    "all_result_sets",
    is_flag=True,
    default=False,
    help="validate all known result sets",
)
def validate(
    cfg: config.Application,
    images: list[str],
    always_run_label_comparison: bool,
    breakdown_by_ecosystem: bool,
    verbosity: int,
    result_sets: list[str],
    all_result_sets: bool,
):
    # TODO: don't artificially inflate logging; figure out what to print
    setup_logging(verbosity + 3)
    if (
        all_result_sets and result_sets and len(result_sets) > 0
    ):  # default result set will be present anyway
        raise ValueError(
            f"cannot pass --all and -r / --result-set: {all_result_sets} {result_sets}"
        )

    if all_result_sets:
        result_sets = [r for r in cfg.result_sets.keys()]

    if not result_sets:
        raise ValueError(
            "must pass --result-set / -r at least once or --all to validate all result sets"
        )

    # let's not load any more labels than we need to, base this off of the images we're validating
    if not images:
        unique_images = set()
        for r in result_sets:
            result_set_obj = store.result_set.load(name=r)
            for state in result_set_obj.state:
                if state and state.config and state.config.image:
                    unique_images.add(state.config.image)
        images = sorted(list(unique_images))

    click.echo("Loading label entries...", nl=False)
    label_entries = store.labels.load_for_image(
        images, year_max_limit=cfg.max_year_for_any_result_set(result_sets)
    )
    click.echo(f"done! {len(label_entries)} entries loaded")

    gates = []
    for result_set in result_sets:
        rs_config = cfg.result_sets[result_set]
        for gate_config in rs_config.validations:
            if gate_config.max_year is None:
                gate_config.max_year = cfg.default_max_year

            click.echo(
                f"{bcolors.HEADER}{bcolors.BOLD}Validating with {result_set!r}{bcolors.RESET}"
            )
            new_gates = val.validate_result_set(
                gate_config,
                result_set,
                images=images,
                always_run_label_comparison=always_run_label_comparison,
                verbosity=verbosity,
                label_entries=label_entries,
            )
            for gate in new_gates:
                show_results_used(gate.input_description)
                show_delta_commentary(gate)

            gates.extend(new_gates)
        click.echo()

        if breakdown_by_ecosystem:
            click.echo(
                f"{bcolors.HEADER}Breaking down label comparison by ecosystem performance...{bcolors.RESET}",
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
            click.echo()

    failure = not all([gate.passed() for gate in gates])
    if failure:
        click.echo("Reasons for quality gate failure:")
    for gate in gates:
        for reason in gate.reasons:
            click.echo(f"   - {reason}")

    if failure:
        click.echo()
        click.echo(f"{bcolors.FAIL}{bcolors.BOLD}Quality gate FAILED{bcolors.RESET}")
        sys.exit(1)
    else:
        click.echo(
            f"{bcolors.OKGREEN}{bcolors.BOLD}Quality gate passed!{bcolors.RESET}"
        )


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
        click.echo("No differences found between tooling (with labels)")
        return

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
    click.echo("Match differences between tooling (with labels):")
    indent = "   "
    click.echo(
        indent
        + tabulate(
            [header_row] + all_rows,
            tablefmt="plain",
        ).replace("\n", "\n" + indent)
        + "\n"
    )


def show_results_used(input_description: GateInputDescription):
    if not input_description:
        return
    click.echo(f"   Results used for image {input_description.image}:")
    for idx, description in enumerate(input_description.configs):
        branch = "├──"
        if idx == len(input_description.configs) - 1:
            branch = "└──"
        label = " "
        if description.tool_label and len(description.tool_label) > 0:
            label = f" ({description.tool_label}) "
        click.echo(
            f"    {branch} {description.id} : {description.tool}{label} against {input_description.image}"
        )
    click.echo()
