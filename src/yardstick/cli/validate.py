import re
import sys

import click
from tabulate import tabulate

import yardstick
from yardstick import store
from yardstick import validate as val
from yardstick.cli import config, display
from yardstick.cli.interactive_validate import InteractiveValidateTUI
from yardstick.validate import Gate, GateInputDescription


class bcolors:
    HEADER: str = "\033[95m"
    OKBLUE: str = "\033[94m"
    OKCYAN: str = "\033[96m"
    OKGREEN: str = "\033[92m"
    WARNING: str = "\033[93m"
    FAIL: str = "\033[91m"
    BOLD: str = "\033[1m"
    UNDERLINE: str = "\033[4m"
    RESET: str = "\033[0m"


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
@click.option("--verbose", "-v", "verbosity", count=True, help="show details of all comparisons")
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
@click.option(
    "--derive-year-from-cve-only",
    "-c",
    default=None,
    help="only use the CVE ID year-max-limit",
    is_flag=True,
)
@click.option(
    "--max-year",
    "-y",
    type=int,
    help="filter matches by maximum CVE year (e.g., 2022 includes CVE-2022-XXXX and earlier)",
)
@click.option(
    "--interactive",
    is_flag=True,
    help="open interactive TUI for relabeling after quality gate failure",
)
def validate(
    cfg: config.Application,
    images: list[str],
    always_run_label_comparison: bool,
    breakdown_by_ecosystem: bool,
    verbosity: int,
    result_sets: list[str],
    all_result_sets: bool,
    derive_year_from_cve_only: bool | None,
    max_year: int | None,
    interactive: bool,
):
    # TODO: don't artificially inflate logging; figure out what to print
    setup_logging(verbosity + 3)

    if derive_year_from_cve_only is None:
        derive_year_from_cve_only = cfg.derive_year_from_cve_only

    if all_result_sets and result_sets and len(result_sets) > 0:  # default result set will be present anyway
        raise ValueError(f"cannot pass --all and -r / --result-set: {all_result_sets} {result_sets}")

    if all_result_sets:
        result_sets = [r for r in cfg.result_sets.keys()]

    if not result_sets:
        raise ValueError("must pass --result-set / -r at least once or --all to validate all result sets")

    # let's not load any more labels than we need to, base this off of the images we're validating
    if not images:
        unique_images = set()
        for r in result_sets:
            result_set_obj = store.result_set.load(name=r)
            for state in result_set_obj.state:
                if state and state.config and state.config.image:
                    unique_images.add(state.config.image)
        images = sorted(list(unique_images))

    # Determine the year limit to use: CLI option overrides config
    year_limit = max_year if max_year is not None else cfg.max_year_for_any_result_set(result_sets)

    click.echo("Loading label entries...", nl=False)
    label_entries = store.labels.load_for_image(images, year_max_limit=year_limit, year_from_cve_only=derive_year_from_cve_only)
    click.echo(f"done! {len(label_entries)} entries loaded")

    gates = []
    for result_set in result_sets:
        rs_config = cfg.result_sets[result_set]
        for gate_config in rs_config.validations:
            if gate_config.max_year is None:
                gate_config.max_year = max_year if max_year is not None else cfg.default_max_year

            gate_config.year_from_cve_only = derive_year_from_cve_only

            click.echo(f"{bcolors.HEADER}{bcolors.BOLD}Validating with {result_set!r}{bcolors.RESET}")
            new_gates = val.validate_result_set(
                gate_config,
                result_set,
                images=images,
                always_run_label_comparison=always_run_label_comparison,
                verbosity=verbosity,
                label_entries=label_entries,
            )
            for gate in new_gates:
                show_results_for_image(gate.input_description, gate)

            gates.extend(new_gates)
        click.echo()

        if breakdown_by_ecosystem:
            click.echo(
                f"{bcolors.HEADER}Breaking down label comparison by ecosystem performance...{bcolors.RESET}",
            )
            ecosystem_year_limit = max_year if max_year is not None else cfg.max_year_for_result_set(result_set)
            results_by_image, label_entries, stats = yardstick.compare_results_against_labels_by_ecosystem(
                result_set=result_set,
                year_max_limit=ecosystem_year_limit,
                year_from_cve_only=derive_year_from_cve_only,
                label_entries=label_entries,
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
            click.echo(f"   - {reason} ({gate.input_description.image})")

    if failure:
        click.echo()
        click.echo(f"{bcolors.FAIL}{bcolors.BOLD}Quality gate FAILED{bcolors.RESET}")

        if interactive:
            click.echo("Starting interactive mode...")
            tui = InteractiveValidateTUI(gates, label_entries, year_max_limit=year_limit, year_from_cve_only=derive_year_from_cve_only)
            tui.run()

        sys.exit(1)
    else:
        click.echo(f"{bcolors.OKGREEN}{bcolors.BOLD}Quality gate passed!{bcolors.RESET}")


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
    all_rows = sorted(all_rows, key=lambda x: escape_ansi(str(x[0] + x[1] + x[2] + x[3])))
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


def show_results_for_image(input_description: GateInputDescription, gate: Gate):
    click.echo(f"   Results used for image {input_description.image}:")
    for idx, description in enumerate(input_description.configs):
        branch = "├──"
        if idx == len(input_description.configs) - 1:
            branch = "└──"
        label = " "
        if description.tool_label and len(description.tool_label) > 0:
            label = f" ({description.tool_label}) "
        click.echo(f"    {branch} {description.id} : {description.tool}{label} against {input_description.image}")
    if gate.deltas:
        click.echo(f"Deltas for {input_description.image}:")
        show_delta_commentary(gate)
    click.echo("-" * 80)
