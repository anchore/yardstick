from __future__ import annotations

import logging

import click

import yardstick
from yardstick import artifact, label, store
from yardstick.cli import config, display, explore


@click.group(name="label", help="manage match labels")
@click.pass_obj
def group(_: config.Application):
    pass


@group.command(
    "compare",
    help="compare a scan result against labeled data",
)
@click.argument("descriptions", nargs=-1)
@click.option(
    "--show-fns",
    default=False,
    is_flag=True,
    help="show all FN labels for each tool-image pair",
)
@click.option(
    "--show-indeterminates",
    default=False,
    is_flag=True,
    help="show each indeterminate result for each tool-image pair",
)
@click.option(
    "--fuzzy",
    default=False,
    is_flag=True,
    help="loosen restrictions on package matching",
)
@click.option("--result-set", "-r", help="use a named result set as description input")
@click.option(
    "--year-max-limit",
    "-y",
    default=None,
    help="max year to include in comparison (relative to the CVE ID)",
)
@click.option("--json", "-j", "is_json", help="show results as JSON", is_flag=True)
@click.pass_obj
def compare_results_against_labels(  # noqa: PLR0913
    cfg: config.Application,
    descriptions: list[str],
    show_fns: bool,
    show_indeterminates: bool,
    fuzzy: bool,
    result_set: str,
    year_max_limit: int | None,
    is_json: bool,
):
    if not year_max_limit:
        year_max_limit = cfg.default_max_year

    (
        results,
        _,
        comparisons_by_result_id,
        stats_by_image_tool_pair,
    ) = yardstick.compare_results_against_labels(
        descriptions=descriptions,
        result_set=result_set,
        fuzzy=fuzzy,
        year_max_limit=year_max_limit,
    )

    if is_json:
        display.label_comparison_json(
            results,
            comparisons_by_result_id,
            stats_by_image_tool_pair,
            show_fns=show_fns,
            show_indeterminates=show_indeterminates,
        )
    else:
        display.label_comparison(
            results,
            comparisons_by_result_id,
            stats_by_image_tool_pair,
            show_fns=show_fns,
            show_indeterminates=show_indeterminates,
        )


@group.command(name="list", help="show all labels")
@click.option("--image", "-i", default=None, help="an image to filter labels on")
@click.option("--summarize", "-s", is_flag=True, help="summarize each entry")
@click.pass_obj
def list_labels(_: config.Application, image: str, summarize: bool):
    display_label_entries = (
        store.labels.load_for_image(image) if image else store.labels.load_all()
    )

    for entry in display_label_entries:
        if summarize:
            print(entry.summarize())
        else:
            print(entry)

    logging.info(f"total label entries: {len(display_label_entries)}")


@group.command(name="images", help="show all images derived from label data")
@click.pass_obj
def list_images(_: config.Application):
    # TODO: base this off of the label directory structure instead of the entries for better performance
    display_label_entries = store.labels.load_all()

    images = set()
    for entry in display_label_entries:
        if entry.image and entry.image.exact:
            images.add(entry.image.exact)

    for image in sorted(images):
        print(image)

    logging.info(f"total images: {len(images)}")


@group.command(name="add", help="add a match label indication for an image")
@click.option("--image", "-i", required=True, help="the image to use")
@click.option("--vulnerability", "-c", required=True, help="the vulnerability id")
@click.option("--package-name", "-p", required=True, help="the package name")
@click.option("--package-version", "-v", required=True, help="the package version")
@click.option(
    "--label",
    "-l",
    "label_name",
    required=True,
    help="the match label (tp/fp/unclear)",
)
@click.option("--note", "-n", help="an optional note")
@click.pass_obj
def add_label(  # noqa: PLR0913
    _: config.Application,
    image: str,
    vulnerability: str,
    package_name: str,
    package_version: str,
    label_name: str,
    note: str,
):
    package = artifact.Package(
        name=package_name,
        version=package_version,
    )

    label_obj = artifact.Label.from_str(label_name)
    if not label_obj:
        raise RuntimeError(f"unable to parse label={label_name!r}")

    new_label = artifact.LabelEntry(
        vulnerability_id=vulnerability,
        image=artifact.ImageSpecifier(exact=image),
        package=package,
        label=label_obj,
        note=note,
        lookup_effective_cve=True,
    )
    store.labels.save([new_label])
    print(new_label.ID)


@group.command(name="remove", help="remove a match label indication for an image")
@click.argument("label-ids", nargs=-1)
@click.pass_obj
def remove_label(
    _: config.Application,
    label_ids: list[str],
):
    deleted_ids = store.labels.delete(label_ids)
    for d in deleted_ids:
        print(d)
    logging.info(f"removed {len(deleted_ids)} labels")


@group.command(
    name="explore",
    help="interact with an label results for a single image scan",
)
@click.argument("result_id")
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
def explore_labels(
    cfg: config.Application,
    result_id: str,
    year_max_limit: int | None,
    derive_year_from_cve_only: bool | None,
):
    logging.disable(level=logging.CRITICAL)

    if not year_max_limit:
        year_max_limit = cfg.default_max_year

    if derive_year_from_cve_only is None:
        derive_year_from_cve_only = cfg.derive_year_from_cve_only

    scan_config = store.scan_result.find_one(by_description=result_id)
    result = store.scan_result.load(
        config=scan_config,
        year_max_limit=year_max_limit,
        year_from_cve_only=derive_year_from_cve_only,
    )

    lineage = store.image_lineage.get(scan_config.image)
    label_entries = store.labels.load_for_image(
        [scan_config.image, *lineage],
        year_max_limit=year_max_limit,
        year_from_cve_only=derive_year_from_cve_only,
    )

    filter_spec = ""
    if year_max_limit:
        filter_spec = f"CVE year <= {year_max_limit}"

    explore.image_labels.run(result, label_entries, lineage, filter_spec)


@group.command(name="set-image-parent", help="set the parent image for a given image")
@click.option("--child", "-c", help="the image that is the child")
@click.option("--parent", "-p", help="the image that is the parent")
@click.pass_obj
def set_image_parent(_: config.Application, child: str, parent: str):
    logging.info(f"setting image={child!r} parent to {parent!r}")
    store.image_lineage.add(child, [parent])
    lineage = store.image_lineage.get(child)
    logging.info(f"full image={child!r} lineage={lineage!r}")


@group.command(
    name="show-image-lineage",
    help="show all parents and children for the given image",
)
@click.option("--image", "-i", help="the container image")
@click.pass_obj
def show_image_lineage(_: config.Application, image: str):
    lineage = store.image_lineage.get(image)
    logging.info(f"full image={image!r} lineage={lineage!r}")


@group.command(
    name="apply",
    help="see which labels apply to the given image and tool pair",
)
@click.argument("result_id")
@click.option(
    "--inverse",
    "-i",
    help="show image lables that should not be applied",
    is_flag=True,
)
@click.option("--id", "show_ids", help="show IDs only", is_flag=True)
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
def apply_labels(  # noqa: C901, PLR0913
    cfg: config.Application,
    result_id: str,
    inverse: bool,
    show_ids: bool,
    year_max_limit: int | None,
    derive_year_from_cve_only: bool | None,
):
    if not year_max_limit:
        year_max_limit = cfg.default_max_year

    if derive_year_from_cve_only is None:
        derive_year_from_cve_only = cfg.derive_year_from_cve_only

    logging.info(f"applying labels to {result_id!r} (year limit: {year_max_limit})")

    scan_config = store.scan_result.find_one(by_description=result_id)
    result = store.scan_result.load(config=scan_config)

    lineage = store.image_lineage.get(scan_config.image)
    images = [scan_config.image, *lineage]
    label_entries_for_images = store.labels.load_for_image(
        images,
        year_max_limit=year_max_limit,
        year_from_cve_only=derive_year_from_cve_only,
    )
    label_entries = {label.ID: label for label in label_entries_for_images}

    labels = []
    for i in images:
        label_entries_for_image = store.labels.load_for_image(
            i,
            year_max_limit=year_max_limit,
            year_from_cve_only=derive_year_from_cve_only,
        )
        labels.append(label_entries_for_image)

    found = {}
    for idx, _ in enumerate(images):
        remaining_label_entries_for_image = labels[idx]

        if result.matches is None:
            raise ValueError("no matches found in result")

        for match in result.matches:
            # look through ancestors from the most root image upwards (not top down)
            paired_labels = label.find_labels_for_match(
                image=None,  # with must_match_image=False this should not matter
                match=match,
                label_entries=remaining_label_entries_for_image,
                # don't consider image field when pairing labels with matches
                must_match_image=False,
            )

            for paired_label in paired_labels:
                found[paired_label.ID] = paired_label
                if paired_label.ID in label_entries:
                    label_entries.pop(paired_label.ID)

    def show(label_entry):
        if show_ids:
            print(label_entry.ID)
        else:
            print(label_entry)

    if inverse:
        for label_entry in label_entries.values():
            show(label_entry)
    else:
        for _, label_entry in found.items():
            show(label_entry)

    logging.info(f"found {len(found)} labels that apply to {result_id!r}")


@group.command(
    "compare-by-ecosystem",
    help="show TPs/FPs/Precision from label comparison results broken down by ecosystem",
)
@click.option("--result-set", "-r", help="use a named result set as description input")
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
def compare_results_against_labels_by_ecosystem(
    cfg: config.Application,
    result_set: str,
    year_max_limit: int | None,
    derive_year_from_cve_only: bool | None,
):
    if not year_max_limit:
        year_max_limit = cfg.default_max_year

    if derive_year_from_cve_only is None:
        derive_year_from_cve_only = cfg.derive_year_from_cve_only

    results_by_image, _, stats = yardstick.compare_results_against_labels_by_ecosystem(
        result_set=result_set,
        year_max_limit=year_max_limit,
        year_from_cve_only=derive_year_from_cve_only,
    )

    display.labels_by_ecosystem_comparison(
        results_by_image,
        stats,
    )
