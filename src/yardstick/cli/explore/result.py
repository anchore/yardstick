import json
from typing import Callable, Dict, Optional

import pygments
from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.completion import (
    CompleteEvent,
    Completer,
    Completion,
    merge_completers,
)
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import HTML, PygmentsTokens
from prompt_toolkit.styles import style_from_pygments_cls
from prompt_toolkit.validation import ValidationError, Validator
from pygments.lexers.data import JsonLexer
from pygments.styles.monokai import MonokaiStyle

from yardstick import artifact
from yardstick.tool import get_tool


def display_match_table_row(match: artifact.Match) -> str:
    if not match.config:
        return ""
    t = get_tool(match.config.tool_name)
    package_type = t.parse_package_type(match.fullentry)  # type: ignore[union-attr]
    return f"{match.vulnerability.id:20} {match.package.name}@{match.package.version} {package_type}"


def display_match(match: artifact.Match) -> str:
    if not match.config:
        return ""
    t = get_tool(match.config.tool_name)
    package_type = t.parse_package_type(match.fullentry)  # type: ignore[union-attr]
    pkg = f"{match.package.name}@{match.package.version}"
    return f"match vuln='{match.vulnerability.id}', cve='{match.vulnerability.cve_id}', package='{pkg}', type='{package_type}', id='{match.ID}'"


class MatchCollection:
    def __init__(self, result: artifact.ScanResult):
        self.result = result
        if not self.result.matches:
            raise ValueError("no matches provided")

        self.match_display_text_by_id = {
            m.ID: display_match(m) for m in self.result.matches
        }
        self.match_by_id = {m.ID: m for m in self.result.matches}
        self.match_id_by_display_text = {
            v: k for k, v in self.match_display_text_by_id.items()
        }

    def has_display_text(self, text):
        return text in self.match_display_text_by_id.values()

    def get_match_display_text(self, match):
        return self.match_display_text_by_id[match.ID]

    def get_match(self, text) -> Optional[artifact.Match]:
        match_id = self.match_id_by_display_text.get(text, None)
        if match_id:
            return self.match_by_id.get(match_id, None)
        return None

    def get_matches(self, filter_text=None):
        if filter_text:
            filter_text = filter_text.lower()

            def condition(match: artifact.Match) -> bool:
                if not match.config:
                    return False
                t = get_tool(match.config.tool_name)
                package_type = t.parse_package_type(match.fullentry)  # type: ignore[union-attr]

                return (
                    filter_text in match.vulnerability.id.lower()
                    or filter_text in match.package.name.lower()
                    or filter_text in match.package.version.lower()
                    or filter_text in package_type
                )

        else:

            def condition(
                match: artifact.Match,
            ) -> bool:
                return True

        return [match for match in sorted(self.result.matches) if condition(match)]


class ResultCompleter(Completer):
    def __init__(self, matches: MatchCollection):
        self.matches = matches

    def get_completions(self, document: Document, complete_event: CompleteEvent):
        matches = self.matches.get_matches(filter_text=document.text.strip())
        if document.text.lower().startswith("match"):
            matches += self.matches.get_matches(
                filter_text=document.text.lstrip("match").strip(),
            )

        for match in matches:
            yield Completion(
                self.matches.get_match_display_text(match),
                start_position=-len(document.text_before_cursor),
                display=display_match_table_row(match),
                display_meta="match",
            )


class ExploreValidator(Validator):
    def __init__(self, completers, matches):
        self.completers = completers
        self.matches = matches

    def validate(self, document: Document):
        # did we find a match or command? then error out
        if not self.completers.get_completions(
            document,
            None,
        ) and not self.matches.has_display_text(document.text):
            raise ValidationError(message="Not matches found")


class Executor(Completer):
    def __init__(self, matches: MatchCollection):
        self.matches = matches
        self.commands: Dict[str, Callable] = {
            "list": self.list,
            "help": self.help,
            "match": self.match,
        }
        self.display: Dict[str, HTML] = {
            "list": HTML("<b>list</b> [optional filter text]"),
            "help": HTML("<b>help</b>"),
            "match": HTML(
                "<b>match</b> <i>vuln</i>=str <i>package</i>=str <i>id</i>=str",
            ),
        }
        self.command_descriptions: Dict[str, Optional[str]] = {
            cmd: fn.__doc__ for cmd, fn in self.commands.items()
        }

    def get_completions(self, document: Document, complete_event: CompleteEvent):
        text = document.text.lower()
        for name in self.commands:
            if text.startswith(name) or name.startswith(text):
                yield Completion(
                    name,
                    start_position=-len(document.text_before_cursor),
                    display=self.display[name],
                    display_meta="command",
                )

    def execute(self, text):
        cmd = self.commands.get(text.split(" ").pop(0), None)
        if cmd:
            cmd(text)
        else:
            print(f"could not parse input '{text}'")

    def match(self, text: str):
        """
        show original json entry for a given match (prompt matches partial CVE, package name, and package version))
        """
        match = self.matches.get_match(text)
        if match:
            json_str = json.dumps(match.fullentry, indent=2)
            tokens = list(pygments.lex(json_str, lexer=JsonLexer()))
            style = style_from_pygments_cls(pygments_style_cls=MonokaiStyle)
            print_formatted_text(PygmentsTokens(tokens), style=style)

    def list(self, text: Optional[str] = None):  # noqa: A003
        """
        list all vulnerability matches (accepts optional filter argument)
        """
        if text:
            text = text.lstrip("list").strip()

        matches = [
            f"{num+1!s:3} | " + display_match(match)
            for num, match in enumerate(sorted(self.matches.get_matches(text)))
        ]
        print_formatted_text("\n".join(matches))

    def help(self, _: Optional[str] = None):  # noqa: A003
        """
        show available commands
        """
        messages = []
        for k in sorted(self.commands):
            description = ""
            command_description = self.command_descriptions.get(k, None)
            if command_description:
                description = ": " + command_description
            messages.append("   <b>" + k + "</b>" + description)
        print_formatted_text(HTML("\n".join(["Commands:", *messages])))


def bottom_toolbar(result: artifact.ScanResult):
    def _render():
        info = f"<b>{result.config.image} {result.config.tool_name}@{result.config.tool_version}</b>"
        stats = [f"[matches <style bg='ansired'>{len(result.matches)}</style>]"]

        unique = len(set(result.matches))
        if unique != len(result.matches):
            stats += [f"[unique matches <style bg='ansired'>{len(set())}</style>]"]

        return HTML(f"{info} {' '.join(stats)}")

    return _render


def run(result: artifact.ScanResult):
    matches = MatchCollection(result)
    executor = Executor(matches)
    completer = ResultCompleter(matches)
    all_completers = merge_completers((completer, executor))
    vaidator = ExploreValidator(all_completers, matches)
    config = {
        "bottom_toolbar": bottom_toolbar(result),
        # mouse_support=True, # with mouse support, scrolling is disabled
        "completer": all_completers,
        "validator": vaidator,
    }
    session: PromptSession = PromptSession()

    executor.help()
    while True:
        text = session.prompt("> ", **config)
        executor.execute(text)
