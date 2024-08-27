import dataclasses
import enum
import logging
from typing import Any

import click
import importlib_metadata
import yaml

from yardstick import store
from yardstick.cli import config, label, result, validate


@click.option("--verbose", "-v", default=False, help="show logs", is_flag=True)
@click.option("--config", "-c", "config_path", default="", help="override config path")
@click.group(
    help="Tool for parsing and comparing the vulnerability report output from multiple tools.",
)
@click.pass_context
def cli(ctx, verbose: bool, config_path: str):
    import logging.config

    # initialize yardstick based on the current configuration and
    # set the config object to click context to pass to subcommands
    ctx.obj = config.load(config_path)
    store.config.set_values(store_root=ctx.obj.store_root)

    log_level = "INFO"
    if verbose:
        log_level = "DEBUG"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
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
        },
    )


@cli.command(name="config", help="show the application config")
@click.pass_obj
def show_config(cfg: config.Application):
    logging.info("showing application config")

    class IndentDumper(yaml.Dumper):
        def increase_indent(
            self,
            flow: bool = False,
            indentless: bool = False,
        ) -> None:
            return super().increase_indent(flow, False)

    def enum_asdict_factory(data: list[tuple[str, Any]]) -> dict[Any, Any]:
        # prevents showing oddities such as
        #
        #   wolfi:
        #       request_timeout: 125
        #       runtime:
        #       existing_input: !!python/object/apply:vunnel.provider.InputStatePolicy
        #           - keep
        #       existing_results: !!python/object/apply:vunnel.provider.ResultStatePolicy
        #           - delete-before-write
        #       on_error:
        #           action: !!python/object/apply:vunnel.provider.OnErrorAction
        #           - fail
        #           input: !!python/object/apply:vunnel.provider.InputStatePolicy
        #           - keep
        #           results: !!python/object/apply:vunnel.provider.ResultStatePolicy
        #           - keep
        #           retry_count: 3
        #           retry_delay: 5
        #       result_store: !!python/object/apply:vunnel.result.StoreStrategy
        #           - flat-file
        #
        # and instead preferring:
        #
        #   wolfi:
        #       request_timeout: 125
        #       runtime:
        #       existing_input: keep
        #       existing_results: delete-before-write
        #       on_error:
        #           action: fail
        #           input: keep
        #           results: keep
        #           retry_count: 3
        #           retry_delay: 5
        #       result_store: flat-file

        def convert_value(obj: Any) -> Any:
            if isinstance(obj, enum.Enum):
                return obj.value
            return obj

        return {k: convert_value(v) for k, v in data}

    cfg_dict = dataclasses.asdict(cfg, dict_factory=enum_asdict_factory)
    print(yaml.dump(cfg_dict, Dumper=IndentDumper, default_flow_style=False))


@cli.command(name="version", help="show the installed version of yardstick")
@click.pass_obj
def version(_: config.Application):
    d = importlib_metadata.distribution("yardstick")
    if not d:
        raise RuntimeError("yardstick install information could not be found")
    print(f"{d.name} {d.version} ({d.locate_file(d.name).parent})")


cli.add_command(validate.validate)
cli.add_command(result.group)
cli.add_command(label.group)
