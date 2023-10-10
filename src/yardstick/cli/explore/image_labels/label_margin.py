from typing import TYPE_CHECKING, Callable

from prompt_toolkit.formatted_text import StyleAndTextTuples, fragment_list_width
from prompt_toolkit.layout.controls import UIContent
from prompt_toolkit.layout.margins import Margin

if TYPE_CHECKING:
    from prompt_toolkit.layout.containers import WindowRenderInfo


class LabelMargin(Margin):
    def __init__(self, label_manager) -> None:
        self.label_manager = label_manager
        self.minwidth = 8
        self.maxwidth = 8 * 3  # no more than about 3 tags worth
        self.width = self.minwidth

    def get_width(self, get_ui_content: Callable[[], UIContent]) -> int:
        return min(self.maxwidth, self.width * 2)

    def create_margin(
        self,
        window_render_info: "WindowRenderInfo",
        width: int,
        height: int,
    ) -> StyleAndTextTuples:
        # Get current line number.
        current_lineno = window_render_info.ui_content.cursor_position.y

        # Construct margin.
        result: StyleAndTextTuples = []
        last_lineno = None

        entries = self.label_manager.match_select_entries

        self.width = self.minwidth
        for _, lineno in enumerate(window_render_info.displayed_lines):
            # Only display line number if this line is not a continuation of the previous line.
            if lineno != last_lineno:
                if lineno is None:
                    pass

                offset = 0
                if lineno == current_lineno:
                    offset = 2

                if lineno < len(entries):
                    text = entries[lineno].get_formatted_annotations()

                    content_width = fragment_list_width(text)
                    self.width = max(self.width, content_width, self.minwidth)
                    padding = width - content_width
                    if padding > 0:
                        result.append(("", " " * (padding - offset)))

                    if lineno == current_lineno:
                        result.append(("fg:#888888", "● "))
                    result.extend(text)

            last_lineno = lineno
            result.append(("", "\n"))

        return result
