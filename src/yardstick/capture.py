import datetime
import logging
from typing import Any, Dict, Optional, Tuple, Union

from yardstick import artifact, store
from yardstick.tool import get_tool, sbom_generator, vulnerability_scanner


class Timer:
    start = None
    end = None

    def __enter__(self):
        self.start = datetime.datetime.now(datetime.timezone.utc)
        return self

    def __exit__(self, ty, value, traceback):
        self.end = datetime.datetime.now(datetime.timezone.utc)


def run_scan(
    config: artifact.ScanConfiguration,
    tool: Optional[
        Union[vulnerability_scanner.VulnerabilityScanner, sbom_generator.SBOMGenerator]
    ] = None,
    reinstall: bool = False,
    **kwargs,
) -> Tuple[artifact.ScanResult, str]:
    logging.debug(
        f"capturing via run config image={config.image} tool={config.tool_name}@{config.tool_version}",
    )

    tool_cls = get_tool(str(config.tool_name))
    if not tool_cls:
        raise RuntimeError(f"unknown tool: {config.tool.name}")

    if not tool:
        path = store.tool.install_path(config=config)
        tool = tool_cls.install(
            version=config.tool_version,
            path=path,
            use_cache=not reinstall,
            **kwargs,
        )

    # some tools will have additional metadata... persist this on the config
    if hasattr(tool, "version_detail"):
        installed_version = tool.version_detail
        if installed_version != config.tool_version:
            config.detail["version_detail"] = installed_version
            config.tool_version = installed_version

    with Timer() as timer:
        raw_json = tool.capture(image=config.full_image, tool_input=config.tool_input)
        result = tool.parse(raw_json, config=config)

    config.timestamp = timer.start

    keys = {}
    if issubclass(tool_cls, vulnerability_scanner.VulnerabilityScanner):
        keys["matches"] = result
    elif issubclass(tool_cls, sbom_generator.SBOMGenerator):
        keys["packages"] = result
    else:
        raise RuntimeError("unknown tool type")

    metadata = artifact.ScanMetadata(
        timestamp=config.timestamp,
        elapsed=(timer.end - timer.start).microseconds / 100000.0,
        image_digest=config.image_digest,
    )
    return (
        artifact.ScanResult(config=config, metadata=metadata, **keys),  # type: ignore[arg-type]
        raw_json,
    )


def intake(config: artifact.ScanConfiguration, raw_results: str) -> artifact.ScanResult:
    logging.info(f"capturing via intake config={config}")

    tool_cls = get_tool(config.tool_name)
    if not tool_cls:
        raise RuntimeError(f"unknown tool: {config.tool_name}")

    result = tool_cls.parse(raw_results, config=config)
    keys = {}
    if issubclass(tool_cls, vulnerability_scanner.VulnerabilityScanner):
        keys["matches"] = result
    elif issubclass(tool_cls, sbom_generator.SBOMGenerator):
        keys["packages"] = result
    else:
        raise RuntimeError("unknown tool type")

    metadata = artifact.ScanMetadata(
        timestamp=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0),
    )
    return artifact.ScanResult(config=config, metadata=metadata, **keys)  # type: ignore[arg-type]


def one(
    request: artifact.ScanRequest,
    producer_state: Optional[str] = None,
    profiles: Optional[Dict[str, Dict[str, Any]]] = None,
) -> artifact.ScanConfiguration:
    logging.debug(
        f"capturing data image={request.image} tool={request.tool} profile={request.profile}",
    )

    if not profiles:
        profiles = {}

    scan_config = artifact.ScanConfiguration.new(
        image=request.image,
        tool=request.tool,
        label=request.label,
    )

    if producer_state:
        scan_config.tool_input = producer_state

    profile_obj = None
    if request.profile:
        profile_obj = profiles.get(scan_config.tool_name, {}).get(request.profile, {})
        if not profile_obj:
            raise RuntimeError(f"no profile found for tool {scan_config.tool_name}")

    match_results, raw_json = run_scan(config=scan_config, profile=profile_obj)
    store.scan_result.save(
        raw_json,
        match_results,
    )

    return scan_config


def result_set(  # noqa: C901, PLR0912
    result_set: str,
    scan_requests: list[artifact.ScanRequest],
    only_producers: bool = False,
    profiles=Optional[Dict[str, Dict[str, Any]]],
) -> artifact.ResultSet:
    logging.info(f"capturing data result_set={result_set}")

    if not profiles:
        profiles = {}

    existing_result_set_obj = None
    if store.result_set.exists(name=result_set):
        existing_result_set_obj = store.result_set.load(result_set)

    result_set_obj = artifact.ResultSet(name=result_set)
    total = len(scan_requests)
    for idx, scan_request in enumerate(scan_requests):
        logging.info(f"capturing data for request {idx+1} of {total}")
        producer_data_path = None
        if scan_request.takes:
            producer = result_set_obj.provider(
                image=scan_request.image,
                provides=scan_request.takes,
            )
            if not producer:
                raise RuntimeError(
                    f"unable to find result state for the requested tool {scan_request}",
                )

            if producer.config:
                producer_scan_config = store.scan_result.find_one(
                    by_description=producer.config.path,
                )
                producer_data_path, _ = store.scan_result.store_paths(
                    producer_scan_config,
                )

        if only_producers and not scan_request.provides:
            logging.info(f"skipping non-producer tool {scan_request.tool}")
            continue

        refresh = scan_request.refresh
        scan_config = None

        if existing_result_set_obj and not refresh:
            result_state = existing_result_set_obj.get(
                image=scan_request.image,
                tool=scan_request.tool,
            )
            if result_state and result_state.config:
                try:
                    scan_config = store.scan_result.find_one(
                        by_description=result_state.config.path,
                    )
                except RuntimeError:
                    logging.warning(
                        f"unable to find scan config for result state, will refresh: {result_state.config.path}",
                    )
                    scan_config = None

                if scan_config:
                    logging.info(f"using existing scan result {scan_config.ID}")

        if refresh or not scan_config:
            scan_config = one(
                scan_request,
                producer_state=producer_data_path,
                profiles=profiles,
            )

        if not scan_config:
            raise RuntimeError(f"unable to find scan configuration for {scan_request}")

        result_set_obj.add(request=scan_request, scan_config=scan_config)
    store.result_set.save(result_set_obj)

    return result_set_obj
