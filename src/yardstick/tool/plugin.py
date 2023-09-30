import logging
import sys

if sys.version_info < (3, 10):
    from importlib_metadata import entry_points
else:
    from importlib.metadata import entry_points


def load_plugins():
    tool_plugins = entry_points(group="yardstick.plugins.tools")
    logging.debug(f"discovered plugin entrypoints: {tool_plugins}")

    for tool in tool_plugins:
        try:
            logging.info(f"Loading tool plugin {tool.name}")
            tool.load()
        except:  # noqa: E722
            logging.exception(f"Failed loading tool plugin {tool.name}")
