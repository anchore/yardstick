import logging

import click
import pkg_resources

from yardstick import store
from yardstick.cli import config, label, result


@click.option("--verbose", "-v", default=False, help="show logs", is_flag=True)
@click.option("--config", "-c", "config_path", default=".yardstick.yaml", help="override config path")
@click.group(help="Tool for parsing and comparing the vulnerability report output from multiple tools.")
@click.pass_context
def cli(ctx, verbose: bool, config_path: str):
    # pylint: disable=redefined-outer-name, import-outside-toplevel
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


@cli.command(name="config", help="show the application config")
@click.pass_obj
def show_config(cfg: config.Application):
    logging.info("showing application config")
    print()
    print(cfg.to_yaml())


@cli.command(name="version", help="show the installed version of yardstick")
@click.pass_obj
def version(_: config.Application):
    d = pkg_resources.get_distribution("yardstick")
    if not d:
        raise RuntimeError("yardstick install information could not be found")
    print(repr(d))


cli.add_command(result.group)
cli.add_command(label.group)
