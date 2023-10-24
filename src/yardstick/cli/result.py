from __future__ import annotations

import datetime
import logging
import subprocess
import sys
from dataclasses import dataclass

import click
from tabulate import tabulate

import yardstick
from yardstick import artifact, capture, store
from yardstick.cli import config, display, explore


@click.group(name="result", help="manage image scan results")
@click.pass_obj
def group(
    _: config.Application,
):
    pass


@group.command(name="capture", help="capture all tool output for the given image")
@click.option("--image", "-i", help="the image to scan")
@click.option("--tool", "-t", help="the tool 'name@version' reference")
@click.option(
    "--profile",
    "-p",
    help="an optional profile name of extra install/capture configuration",
)
@click.option(
    "--result-set",
    "-r",
    help="use a named result set instead of a single tool/image",
)
@click.option(
    "--only-producers",
    help="only capture results from producers",
    is_flag=True,
)
@click.pass_obj
def capture_results(  # noqa: PLR0913
    cfg: config.Application,
    image: str,
    tool: str,
    profile: str,
    result_set: str,
    only_producers: bool,
):
    if (image or tool or profile) and result_set:
        raise RuntimeError("cannot specify both image+tool and result-set, choose one")

    if not ((image and tool) or result_set):
        raise RuntimeError("must specify image and tool OR result-set")

    if result_set:
        result_set_config = cfg.result_sets.get(result_set, None)
        if not result_set_config:
            raise RuntimeError(f"no result set found for {result_set}")

        try:
            capture.result_set(
                result_set,
                result_set_config.scan_requests(),
                only_producers=only_producers,
                profiles=cfg.profiles.data,
            )
        except subprocess.CalledProcessError as e:
            logging.error(f"unable to capture result set: {e.output.decode()}")
            raise e
    else:
        scan_result = capture.one(
            artifact.ScanRequest(image=image, tool=tool, profile=profile),
        )
        print(scan_result.ID)


@group.command(name="compare", help="show a comparison between tool output")
@click.option(
    "--year-max-limit",
    "-y",
    default=None,
    help="max year to include in comparison (relative to the CVE ID)",
)
@click.option(
    "--summary",
    "-s",
    default=False,
    is_flag=True,
    help="show summary without detailed breakdown of each entry",
)
@click.option(
    "--show-common",
    "-c",
    default=False,
    is_flag=True,
    help="show common match details",
)
@click.argument("ids", nargs=-1)
@click.pass_obj
def compare_results(
    cfg: config.Application,
    ids: list[str],
    year_max_limit: int | None,
    summary: bool,
    show_common: bool,
):
    if not year_max_limit:
        year_max_limit = cfg.default_max_year

    comp = yardstick.compare_results(descriptions=ids, year_max_limit=year_max_limit)

    display.preserved_matches(
        comp,
        details=not summary,
        summary=summary,
        common=show_common,
    )


@group.command(name="show", help="show a the results for a single scan + tool")
@click.option(
    "--year-max-limit",
    "-y",
    default=None,
    help="max year to include in comparison (relative to the CVE ID)",
)
@click.option(
    "--derive-year-from-cve-only",
    "-c",
    default=None,
    help="only use the CVE ID year-max-limit",
    is_flag=True,
)
@click.argument("description")
@click.pass_obj
def show_results(
    cfg: config.Application,
    description: str,
    year_max_limit: int | None,
    derive_year_from_cve_only: None | bool,
):
    if not year_max_limit:
        year_max_limit = cfg.default_max_year

    if derive_year_from_cve_only is None:
        derive_year_from_cve_only = cfg.derive_year_from_cve_only

    logging.info(
        f"showing capture data for {description} (year limit: {year_max_limit})",
    )

    scan_config = store.scan_result.find_one(by_description=description)

    result = store.scan_result.load(
        config=scan_config,
        year_max_limit=year_max_limit,
        year_from_cve_only=derive_year_from_cve_only,
    )

    if result.matches:
        for match in sorted(result.matches):
            print(match)


@group.command(name="clear", help="remove all results and result sets")
@click.pass_obj
def clear_results(_: config.Application):
    logging.info("deleting all results")

    store.scan_result.clear()
    store.result_set.clear()


@group.command(name="list", help="list stored results")
@click.option(
    "--result-set",
    "-r",
    help="filter list to results for a named result set (instead of all results)",
)
@click.option(
    "--tool",
    "-t",
    "tools",
    help="filter results down to that partially match given tool names",
    multiple=True,
)
@click.option(
    "--images",
    "-i",
    "images",
    help="filter results down to that partially match given image names",
    multiple=True,
)
@click.option("--ids", "show_id", help="show result IDs only", is_flag=True)
@click.pass_obj
def list_results(
    _: config.Application,
    result_set: str,
    show_id: bool,
    tools: list[str],
    images: list[str],
):
    results = result_descriptions(result_set=result_set)

    if tools:
        results = [r for r in results if any(t in r.tool for t in tools)]

    if images:
        results = [r for r in results if any(i in r.image for i in images)]

    if show_id:
        for result in results:
            print(result.ID)
    else:
        all_rows = []
        for result in results:
            all_rows.append([result.ID, result.image, result.tool, result.timestamp])

        print(tabulate(all_rows, tablefmt="plain"))


@group.command(name="images", help="list images in results")
@click.option(
    "--result-set",
    "-r",
    help="filter list to results for a named result set (instead of all results)",
)
@click.pass_obj
def list_images(cfg: config.Application, result_set: str):
    if result_set:
        result_set_config = cfg.result_sets.get(result_set, None)
        if not result_set_config:
            raise RuntimeError(f"no result set found for {result_set}")

    results = result_descriptions(result_set=result_set)
    images = set()
    for result in results:
        images.add(result.image)

    for image in sorted(images):
        print(image)


@group.command(name="tools", help="list tools in results")
@click.option(
    "--result-set",
    "-r",
    help="filter list to results for a named result set (instead of all results)",
)
@click.pass_obj
def list_tools(cfg: config.Application, result_set: str):
    if result_set:
        result_set_config = cfg.result_sets.get(result_set, None)
        if not result_set_config:
            raise RuntimeError(f"no result set found for {result_set}")

    results = result_descriptions(result_set=result_set)
    tools = set()
    for result in results:
        tools.add(result.tool)

    for tool in sorted(tools):
        print(tool)


@dataclass(eq=True, order=True)
class ResultDescription:
    image: str
    tool: str
    ID: str
    timestamp: datetime.datetime | None = None


def result_descriptions(result_set: str | None = None) -> list[ResultDescription]:
    results = []
    if result_set:
        result_set_obj = store.result_set.load(result_set)

        for result_state in result_set_obj.state:
            if not result_state.config:
                raise ValueError("result set missing a configuration")

            scan_config = store.scan_result.find_one(
                by_description=result_state.config.path,
            )

            if not scan_config:
                raise RuntimeError(
                    f"unable to find scan configuration for {result_state.config.path}",
                )

            results.append(
                ResultDescription(
                    ID=scan_config.ID,
                    image=result_state.request.image,
                    tool=result_state.config.tool,
                    timestamp=result_state.config.timestamp,
                ),
            )

    else:
        scan_configs = store.scan_result.list_all_configs()
        for scan_config in scan_configs:
            results.append(
                ResultDescription(
                    ID=scan_config.ID,
                    image=scan_config.image,
                    tool=scan_config.tool,
                    timestamp=scan_config.timestamp,
                ),
            )

    return sorted(results)


@group.group(name="set", help="manipulate result sets")
@click.pass_obj
def set_group(_: config.Application):
    pass


@set_group.command(name="list", help="list configured result sets")
@click.pass_obj
def list_result_sets(_: config.Application):
    for result_set in store.result_set.load_all():
        print(result_set.name)


@set_group.command(name="add", help="create a result set")
@click.argument("ids", nargs=-1)
@click.option(
    "--name",
    "-n",
    "result_set",
    required=True,
    help="the name of the result set",
)
@click.pass_obj
def add_result_sets(_: config.Application, ids: list[str], result_set: str):
    result_set_obj = artifact.ResultSet(name=result_set)
    for scan_config_id in ids:
        scan_config = store.scan_result.find_one(by_description=scan_config_id)
        scan_request = artifact.ScanRequest(
            image=scan_config.full_image,
            tool=scan_config.tool,
        )

        if not scan_config:
            raise RuntimeError(f"unable to find scan configuration for {scan_request}")

        result_set_obj.add(request=scan_request, scan_config=scan_config)
    store.result_set.save(result_set_obj)


@group.command(name="import", help="import results for a tool that were run externally")
@click.option("--image", "-i", required=True, help="the image that was scanned")
@click.option("--tool", "-t", required=True, help="the tool 'name@version' reference")
@click.option(
    "--file",
    "-f",
    required=False,
    help="the file path to the image scan results (uses stdin if not provided)",
)
@click.pass_obj
def import_results(
    _: config.Application,
    image: str,
    tool: str,
    file: str | None = None,
):
    logging.info(f"importing data image={image} tool={tool} file={file}")

    scan_config = artifact.ScanConfiguration.new(
        image=image,
        tool=tool,
        timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
    )

    if file:
        with open(file, encoding="utf-8") as file_handle:
            raw_results = file_handle.read()
    else:
        logging.info("reading stdin")
        raw_results = sys.stdin.read()

    match_results = capture.intake(config=scan_config, raw_results=raw_results)
    store.scan_result.save(raw_results, match_results)
    print(scan_config.ID)


@group.command(name="explore", help="interact with an image scan result")
@click.argument("ids")
@click.option(
    "--year-max-limit",
    "-y",
    default=None,
    help="max year to include in comparison (relative to the CVE ID)",
)
@click.option(
    "--derive-year-from-cve-only",
    "-c",
    default=None,
    help="only use the CVE ID year-max-limit",
    is_flag=True,
)
@click.pass_obj
def explore_results(
    cfg: config.Application,
    ids: str,
    year_max_limit: int | None,
    derive_year_from_cve_only: None | bool,
):
    if not year_max_limit:
        year_max_limit = cfg.default_max_year

    if derive_year_from_cve_only is None:
        derive_year_from_cve_only = cfg.derive_year_from_cve_only

    scan_config = store.scan_result.find_one(by_description=ids)
    result = store.scan_result.load(config=scan_config)
    if year_max_limit:
        results = store.scan_result.filter_by_year(
            [result],
            int(year_max_limit),
            year_from_cve_only=derive_year_from_cve_only,
        )
        result = results[0]
    explore.result.run(result)
