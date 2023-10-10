from asyncio import Future

from prompt_toolkit.application.current import get_app
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Dimension
from prompt_toolkit.layout.containers import HSplit
from prompt_toolkit.widgets import Button, Dialog, Label, TextArea


class TextDialog:
    def __init__(  # noqa: PLR0913
        self,
        title="",
        label_text="",
        completer=None,
        text_area=True,
        default_value="",
        ok_button_text="OK",
        cancel_button_text="Cancel",
    ):
        self.future = Future()

        def accept_text(buf):
            get_app().layout.focus(ok_button)
            buf.complete_state = None
            return True

        def accept():
            if text_area:
                self.future.set_result(self.text_area.text)
            else:
                self.future.set_result(True)

        kb = KeyBindings()

        kb.add("escape")

        def cancel():
            self.future.set_result(None)

        if text_area:
            self.text_area = TextArea(
                text=default_value or "",
                completer=completer,
                multiline=True,
                width=Dimension(preferred=40),
                height=Dimension(preferred=5),
                accept_handler=accept_text,
            )

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

        layout_items = [Label(text=label_text)]
        if text_area:
            layout_items.append(self.text_area)

        self.dialog = Dialog(
            title=title,
            body=HSplit(layout_items, key_bindings=kb),
            buttons=[ok_button, cancel_button],
            width=Dimension(preferred=80),
            modal=True,
        )

    def __pt_container__(self):
        return self.dialog
