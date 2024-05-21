from asyncio import Future
from typing import List, Optional, Union

from prompt_toolkit.formatted_text import (
    AnyFormattedText,
    merge_formatted_text,
    to_formatted_text,
)
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import (
    ConditionalContainer,
    Container,
    Dimension,
    FormattedTextControl,
)
from prompt_toolkit.layout.containers import HSplit, Window
from prompt_toolkit.layout.margins import ScrollbarMargin

from yardstick import artifact
from yardstick.cli.explore.image_labels.edit_note_dialog import EditNoteDialog
from yardstick.cli.explore.image_labels.label_json_editor_dialog import (
    LabelJsonEditorDialog,
)
from yardstick.cli.explore.image_labels.label_manager import LabelManager


class LabelSelectionPane:
    def __init__(
        self,
        label_manager: LabelManager,
        dialog_executor,
        filter=None,  # noqa: A002
    ) -> None:
        self.label_manager = label_manager
        self.dialog_executor = dialog_executor
        self.entries: List[artifact.LabelEntry] = []
        self.selected_entry = 0
        self.match: Optional[artifact.Match] = None
        # self.width = 80
        self.container: Union[HSplit, ConditionalContainer] = HSplit(
            [
                Window(
                    content=FormattedTextControl(
                        text=to_formatted_text(
                            "Match Label Details",
                            style="bold reverse",
                        ),
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
                        text=self.get_formatted_result_list,
                        focusable=True,
                        key_bindings=self._get_key_bindings(),
                    ),
                    style="class:select-label-box",
                    # width=Dimension.exact(self.width),
                    height=Dimension(preferred=15),
                    cursorline=True,
                    always_hide_cursor=False,
                    wrap_lines=True,
                    right_margins=[
                        ScrollbarMargin(display_arrows=False),
                    ],
                ),
            ],
        )

        if filter is not None:
            self.container = ConditionalContainer(content=self.container, filter=filter)

    def set_match(self, match: artifact.Match):
        self.selected_entry = 0
        self.match = match
        self._update()

    def _update(self):
        self.entries = self.label_manager.get_label_entries_by_match(match=self.match)

    def get_formatted_result_list(self) -> AnyFormattedText:
        result: List[AnyFormattedText] = []

        for i, entry in enumerate(self.entries):
            if i == self.selected_entry:
                result.append([("[SetCursorPosition]", "")])

            note = entry.note
            formatted_note = (
                to_formatted_text("[no note provided]", style="italic")
                if not note
                else to_formatted_text(note)
            )

            label_style = ""
            if entry.label == artifact.Label.TruePositive:
                label_style = "#428bff"
            elif entry.label == artifact.Label.FalsePositive:
                label_style = "#ff0066"
            elif entry.label == artifact.Label.Unclear:
                label_style = "#888888"

            result += [
                to_formatted_text(f"{i+1}. "),
                to_formatted_text(entry.label.display, label_style),
                to_formatted_text(f" [{entry.ID}]"),
                to_formatted_text(f" {entry.vulnerability_id}"),
            ]

            result += [
                to_formatted_text(f" from {entry.user}"),
                ": ",
                formatted_note,
                "\n",
                # "\n" + "━" * (self.width - 1) + "\n",
            ]

        if not result:
            result.append(to_formatted_text("[no labels for match]", style="italic"))
        return merge_formatted_text(result)

    def get_selected_entry(self):
        if self.selected_entry > len(self.entries) - 1:
            return None
        return self.entries[self.selected_entry]

    def _get_key_bindings(self) -> KeyBindings:  # noqa: C901
        kb = KeyBindings()

        @kb.add("up")
        def _go_up(event) -> None:
            if self.entries:
                self.selected_entry = (self.selected_entry - 1) % len(self.entries)

        @kb.add("down")
        def _go_down(event) -> None:
            if self.entries:
                self.selected_entry = (self.selected_entry + 1) % len(self.entries)

        @kb.add("backspace")
        @kb.add("delete")
        def _delete_entry(event) -> None:
            entry = self.get_selected_entry()
            if not entry:
                return

            self.label_manager.remove_label_entry(entry.ID)

            self._update()

        @kb.add("e")
        def _edit_note(event) -> None:
            entry = self.get_selected_entry()
            if not entry:
                return

            def done(fut: Future):
                if fut.done() and fut.result() is not None:
                    note = fut.result()
                    self.label_manager.edit_label_entry_note(entry.ID, note)
                    self._update()

            self.dialog_executor(
                dialog=EditNoteDialog(
                    title="Edit note",
                    label_text="Note:",
                    text_area=True,
                    ok_button_text="Update",
                    default_value=entry.note,
                ),
                done_callback=done,
            )

        @kb.add("j")
        def _edit_json(event) -> None:
            entry = self.get_selected_entry()
            if not entry:
                return

            def done(fut: Future):
                if fut.done() and fut.result() is not None:
                    self.label_manager.edit_label_entry_json(entry.ID, fut.result())
                    self._update()

            self.dialog_executor(
                dialog=LabelJsonEditorDialog(entry),
                done_callback=done,
            )

        return kb

    def __pt_container__(self) -> Container:
        return self.container
