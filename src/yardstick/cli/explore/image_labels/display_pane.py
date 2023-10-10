from typing import Union

from prompt_toolkit.formatted_text import split_lines, to_formatted_text
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import (
    Container,
    Dimension,
    FormattedTextControl,
    HSplit,
    Window,
)
from prompt_toolkit.layout.containers import ConditionalContainer
from prompt_toolkit.layout.margins import ScrollbarMargin
from prompt_toolkit.layout.screen import Point


class DisplayPane:
    def __init__(
        self,
        get_formatted_text,
        filter=None,  # noqa: A002
        title="",
        height=None,
    ) -> None:
        self.cursor = Point(0, 0)
        self.get_formatted_text = get_formatted_text
        self.container: Union[HSplit, ConditionalContainer] = HSplit(
            [
                Window(
                    content=FormattedTextControl(
                        text=to_formatted_text(title, style="bold reverse"),
                        focusable=False,
                    ),
                    style="class:pane-title",
                    height=Dimension.exact(1),
                    cursorline=True,
                    always_hide_cursor=True,
                    wrap_lines=False,
                ),
                Window(
                    content=FormattedTextControl(
                        text=get_formatted_text,
                        focusable=True,
                        key_bindings=self._get_key_bindings(),
                        get_cursor_position=self._cursor_position,
                    ),
                    height=height,
                    style="class:details-box",
                    always_hide_cursor=False,
                    right_margins=[
                        ScrollbarMargin(display_arrows=False),
                    ],
                    wrap_lines=True,
                ),
            ],
            width=Dimension(preferred=80),
        )

        if filter is not None:
            self.container = ConditionalContainer(content=self.container, filter=filter)

    def _cursor_position(self):
        # don't allow the cursor to go beyond the rendered content length
        lines = list(split_lines(self.get_formatted_text()()))
        if self.cursor.y >= len(lines) - 1:
            self.cursor = Point(self.cursor.x, len(lines) - 1)
        elif self.cursor.y < 0:
            self.cursor = Point(self.cursor.x, 0)
        return self.cursor

    def _get_key_bindings(self) -> KeyBindings:
        kb = KeyBindings()

        @kb.add("up")
        def _go_up(event) -> None:
            if self.cursor.y > 0:
                self.cursor = Point(self.cursor.x, self.cursor.y - 1)

        @kb.add("down")
        def _go_down(event) -> None:
            self.cursor = Point(self.cursor.x, self.cursor.y + 1)

        return kb

    def __pt_container__(self) -> Container:
        return self.container
