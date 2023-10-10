from asyncio import Future

from prompt_toolkit.application.current import get_app
from prompt_toolkit.formatted_text import StyleAndTextTuples
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Dimension
from prompt_toolkit.layout.containers import Container, HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.widgets import Button, Dialog, TextArea
from pygments.lexers.data import JsonLexer

from yardstick import artifact


class LabelJsonEditorDialog:
    future: Future

    def __init__(
        self,
        entry: artifact.LabelEntry,
        title="Edit label JSON",
        ok_button_text="Save",
        cancel_button_text="Cancel",
    ):
        self.future = Future()

        def accept_text(buf):
            get_app().layout.focus(ok_button)
            buf.complete_state = None
            return True

        def accept():
            if self.validation_toolbar.is_value:
                self.future.set_result(self.text_area.text)

        kb = KeyBindings()

        kb.add("escape")

        def cancel():
            self.future.set_result(None)

        formatted_json = entry.to_json(indent=2)  # type: ignore[attr-defined]

        ok_button = Button(
            text=ok_button_text,
            left_symbol="[",
            right_symbol="]",
            handler=accept,
        )
        cancel_button = Button(
            text=cancel_button_text,
            left_symbol="[",
            right_symbol="]",
            handler=cancel,
        )

        self.text_area = TextArea(
            text=formatted_json,
            multiline=True,
            line_numbers=True,
            scrollbar=True,
            lexer=PygmentsLexer(JsonLexer),
            height=Dimension(preferred=50),
            accept_handler=accept_text,
            style="bg:#333333",
            complete_while_typing=True,
        )

        self.validation_toolbar = ValidationToolbar(self.text_area)

        layout_items = [self.text_area, self.validation_toolbar]

        self.dialog = Dialog(
            title=title,
            # layout_items is a list of MagicContainer, which is only exported when checking types unfortunately
            body=HSplit(layout_items, key_bindings=kb),  # type: ignore[arg-type]
            buttons=[ok_button, cancel_button],
            width=Dimension(preferred=100),
            modal=True,
        )

    def __pt_container__(self):
        return self.dialog


class ValidationToolbar:
    def __init__(self, text_area) -> None:
        self.is_value = True

        def get_formatted_text() -> StyleAndTextTuples:
            try:
                artifact.LabelEntry.from_json(  # type: ignore[attr-defined]
                    text_area.text,
                )
                self.is_value = True
            except Exception as e:
                self.is_value = False
                return [("class:validation-toolbar", "Invalid LabelEntry: " + repr(e))]

            return []

        self.control = FormattedTextControl(get_formatted_text)

        self.container = Window(
            self.control,
            height=1,
            always_hide_cursor=True,
            wrap_lines=True,
        )

    def __pt_container__(self) -> Container:
        return self.container
