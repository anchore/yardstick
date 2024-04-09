"""
Collection of reusable components for building full screen applications.

All of these widgets implement the ``__pt_container__`` method, which makes
them usable in any situation where we are expecting a `prompt_toolkit`
container object.

.. warning::

    At this point, the API for these widgets is considered unstable, and can
    potentially change between minor releases (we try not too, but no
    guarantees are made yet). The public API in
    `prompt_toolkit.shortcuts.dialogs` on the other hand is considered stable.
"""

from typing import List, Optional

from prompt_toolkit.auto_suggest import AutoSuggest, DynamicAutoSuggest
from prompt_toolkit.buffer import Buffer, BufferAcceptHandler
from prompt_toolkit.completion import Completer, DynamicCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.filters import (
    Condition,
    FilterOrBool,
    has_focus,
    is_done,
    is_true,
    to_filter,
)
from prompt_toolkit.formatted_text import AnyFormattedText
from prompt_toolkit.history import History
from prompt_toolkit.key_binding import KeyBindingsBase
from prompt_toolkit.key_binding.key_processor import KeyPressEvent
from prompt_toolkit.layout.containers import Container, Window
from prompt_toolkit.layout.controls import BufferControl, GetLinePrefixCallable
from prompt_toolkit.layout.dimension import AnyDimension
from prompt_toolkit.layout.dimension import Dimension as D
from prompt_toolkit.layout.margins import Margin, NumberedMargin, ScrollbarMargin
from prompt_toolkit.layout.processors import (
    AppendAutoSuggestion,
    BeforeInput,
    ConditionalProcessor,
    PasswordProcessor,
    Processor,
)
from prompt_toolkit.lexers import DynamicLexer, Lexer
from prompt_toolkit.validation import DynamicValidator, Validator
from prompt_toolkit.widgets.toolbars import SearchToolbar

__all__ = [
    "TextArea",
]

E = KeyPressEvent


class TextArea:
    def __init__(  # noqa: PLR0913
        self,
        text: AnyFormattedText = "",
        multiline: FilterOrBool = True,
        password: FilterOrBool = False,
        lexer: Optional[Lexer] = None,
        auto_suggest: Optional[AutoSuggest] = None,
        completer: Optional[Completer] = None,
        complete_while_typing: FilterOrBool = True,
        validator: Optional[Validator] = None,
        accept_handler: Optional[BufferAcceptHandler] = None,
        history: Optional[History] = None,
        focusable: FilterOrBool = True,
        focus_on_click: FilterOrBool = False,
        wrap_lines: FilterOrBool = True,
        read_only: FilterOrBool = False,
        width: AnyDimension = None,
        height: AnyDimension = None,
        dont_extend_height: FilterOrBool = False,
        dont_extend_width: FilterOrBool = False,
        line_numbers: bool = False,
        get_line_prefix: Optional[GetLinePrefixCallable] = None,
        scrollbar: bool = False,
        style: str = "",
        search_field: Optional[SearchToolbar] = None,
        preview_search: FilterOrBool = True,
        prompt: AnyFormattedText = "",
        input_processors: Optional[List[Processor]] = None,
        cursorline: bool = False,
        cursorcolumn: bool = False,
        key_bindings: Optional[KeyBindingsBase] = None,
        right_margins: Optional[List[Margin]] = None,
    ) -> None:
        if search_field is None:
            search_control = None
        elif isinstance(search_field, SearchToolbar):
            search_control = search_field.control

        if input_processors is None:
            input_processors = []

        # Writeable attributes.
        self.completer = completer
        self.complete_while_typing = complete_while_typing
        self.lexer = lexer
        self.auto_suggest = auto_suggest
        self.read_only = read_only
        self.wrap_lines = wrap_lines
        self.validator = validator

        self.buffer = Buffer(
            document=Document(text, 0),  # type: ignore[arg-type]
            multiline=multiline,
            read_only=Condition(lambda: is_true(self.read_only)),
            completer=DynamicCompleter(lambda: self.completer),
            complete_while_typing=Condition(
                lambda: is_true(self.complete_while_typing),
            ),
            validator=DynamicValidator(lambda: self.validator),
            auto_suggest=DynamicAutoSuggest(lambda: self.auto_suggest),
            accept_handler=accept_handler,
            history=history,
        )

        self.control = BufferControl(
            buffer=self.buffer,
            lexer=DynamicLexer(lambda: self.lexer),
            input_processors=[
                ConditionalProcessor(
                    AppendAutoSuggestion(),
                    has_focus(self.buffer) & ~is_done,
                ),
                ConditionalProcessor(
                    processor=PasswordProcessor(),
                    filter=to_filter(password),
                ),
                BeforeInput(prompt, style="class:text-area.prompt"),
                *input_processors,
            ],
            search_buffer_control=search_control,
            preview_search=preview_search,
            focusable=focusable,
            focus_on_click=focus_on_click,
            key_bindings=key_bindings,
        )

        if multiline:
            _right_margins: list[Margin] = (
                [ScrollbarMargin(display_arrows=False)] if scrollbar else []
            )

            if right_margins:
                _right_margins = right_margins + _right_margins

            left_margins = [NumberedMargin()] if line_numbers else []
        else:
            height = D.exact(1)
            left_margins = []
            _right_margins = []

        style = "class:text-area " + style

        # If no height was given, guarantee height of at least 1.
        if height is None:
            height = D(min=1)

        self.window = Window(
            height=height,
            width=width,
            dont_extend_height=dont_extend_height,
            dont_extend_width=dont_extend_width,
            content=self.control,
            style=style,
            wrap_lines=Condition(lambda: is_true(self.wrap_lines)),
            left_margins=left_margins,
            right_margins=_right_margins,
            get_line_prefix=get_line_prefix,
            cursorline=cursorline,
            cursorcolumn=cursorcolumn,
        )

    @property
    def text(self) -> str:
        """
        The `Buffer` text.
        """
        return self.buffer.text

    @text.setter
    def text(self, value: str) -> None:
        self.document = Document(value, 0)

    @property
    def document(self) -> Document:
        """
        The `Buffer` document (text + cursor position).
        """
        return self.buffer.document

    @document.setter
    def document(self, value: Document) -> None:
        self.buffer.set_document(value, bypass_readonly=True)

    @property
    def accept_handler(self) -> Optional[BufferAcceptHandler]:
        """
        The accept handler. Called when the user accepts the input.
        """
        return self.buffer.accept_handler

    @accept_handler.setter
    def accept_handler(self, value: BufferAcceptHandler) -> None:
        self.buffer.accept_handler = value

    def __pt_container__(self) -> Container:
        return self.window
