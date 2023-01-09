# note: don't import anything here to prevent the prompt_toolkit from being loaded by default
from .cli import cli


def run() -> None:
    cli()
