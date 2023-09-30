from asyncio import Future
from concurrent.futures import ThreadPoolExecutor
from typing import List

from prompt_toolkit.application import get_app
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.filters import Condition
from prompt_toolkit.formatted_text import (
    AnyFormattedText,
    merge_formatted_text,
    to_formatted_text,
)
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Dimension
from prompt_toolkit.layout.containers import (
    ConditionalContainer,
    Container,
    HSplit,
    VSplit,
    Window,
)
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.widgets import Label

from yardstick import artifact
from yardstick.cli.explore.image_labels.cve_provider import CveDescriptions
from yardstick.cli.explore.image_labels.edit_note_dialog import EditNoteDialog
from yardstick.cli.explore.image_labels.label_json_editor_dialog import (
    LabelJsonEditorDialog,
)
from yardstick.cli.explore.image_labels.label_manager import LabelManager
from yardstick.cli.explore.image_labels.label_margin import LabelMargin
from yardstick.cli.explore.image_labels.text_area import TextArea


class Worker:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.futures = []

    def cancel(self):
        for f in self.futures:
            f.cancel()
        self.futures.clear()

    def submit(self, fn):
        self.futures.append(self.executor.submit(fn))


class FilterToolbar:
    def __init__(
        self,
        filter,  # noqa: A002
        apply_fn,
        accept_fn,
    ) -> None:
        def on_change(buf):
            apply_fn(buf.document.text)

        def on_accept(_) -> bool:
            accept_fn()
            return True

        self.accept_fn = accept_fn

        self.buffer = Buffer(
            multiline=False,
            on_text_changed=on_change,
            accept_handler=on_accept,
        )

        self.control = BufferControl(
            focusable=True,
            buffer=self.buffer,
            key_bindings=self.get_key_bindings(),
        )
        self.container = ConditionalContainer(
            content=VSplit(
                [
                    Label(
                        text="Filter by Package/CVE: ",
                        style="class:filter-title",
                        dont_extend_width=True,
                    ),
                    Window(
                        content=self.control,
                        height=1,
                        style="class:filter-toolbar-text",
                    ),
                ],
            ),
            filter=filter,
        )

    def get_key_bindings(self):
        bindings = KeyBindings()

        @bindings.add("/")
        def _done(_):
            self.accept_fn()

        return bindings

    def __pt_container__(self) -> Container:
        return self.container


class ResultSelectionPane:
    def __init__(
        self,
        label_manager: LabelManager,
        dialog_executor,
        match_setter,
        filter_spec: str = "",
    ) -> None:
        self.label_manager = label_manager
        self.dialog_executor = dialog_executor
        self.match_setter = match_setter
        self.selected_entry = 0
        self.result_filter_active = False
        self.cve_descriptions = CveDescriptions()
        self.worker = Worker()

        @Condition
        def search_filter():
            return self.result_filter_active

        self.search_field = FilterToolbar(
            filter=search_filter,
            apply_fn=self._apply_filter,
            accept_fn=self.focus,
        )

        self.text_area = TextArea(
            text=self.get_result_text(),
            read_only=True,
            focusable=True,
            key_bindings=self._get_key_bindings(),
            style="class:select-match-box",
            height=Dimension(preferred=len(self.entries)),
            width=Dimension(preferred=100),
            cursorline=True,
            wrap_lines=True,
            scrollbar=True,
            line_numbers=True,
            right_margins=[LabelMargin(self.label_manager)],
            # always_hide_cursor=True, # not exposed
        )

        if filter_spec:
            filter_spec = f"(filter: {filter_spec})"

        self.container = HSplit(
            [
                Window(
                    content=FormattedTextControl(
                        text=to_formatted_text(
                            f"Match Results {filter_spec}",
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
                self.text_area,
                self.search_field,
            ],
        )

        # load the details pane for the current selection
        self._update()

    @property
    def entries(self):
        entries = self.label_manager.match_select_entries
        if entries and self.selected_entry > len(entries):
            self.selected_entry = len(entries) - 2
        return entries

    def focus(self):
        get_app().layout.focus(self.text_area)

    def get_formatted_cve_details(self) -> AnyFormattedText:
        entry = self.get_selected_entry()
        if not entry:
            return merge_formatted_text(
                [to_formatted_text("no selection", style="italic")],
            )
        if self.cve_descriptions.is_cached(entry.match.vulnerability.id):
            text = self.cve_descriptions.get(entry.match.vulnerability.id)
        else:

            def fetch_in_background():
                if (
                    self.get_selected_entry().match.vulnerability.id
                    == entry.match.vulnerability.id
                ):
                    self.cve_descriptions.get(entry.match.vulnerability.id)
                    get_app().invalidate()

            self.worker.submit(fetch_in_background)
            text = "loading..."

        return merge_formatted_text([to_formatted_text(text)])

    def get_formatted_result_details(self) -> AnyFormattedText:
        entry = self.get_selected_entry()
        if not entry:
            return merge_formatted_text(
                [to_formatted_text("no selection", style="italic")],
            )
        return entry.get_formatted_details()

    def get_result_text(self) -> AnyFormattedText:
        result: List[AnyFormattedText] = []

        if not self.entries:
            return "no selection"

        for _, entry in enumerate(self.entries):
            result.append(entry.display)

        return "\n".join(result)  # type: ignore[arg-type]

    def get_selected_entry(self):
        if self.selected_entry >= len(self.entries):
            return None
        return self.entries[self.selected_entry]

    def _update(self):
        entry = self.get_selected_entry()
        if entry:
            self.match_setter(entry.match)
            self.worker.cancel()

    def _toggle_filter(self):
        self.result_filter_active = not self.result_filter_active
        if self.result_filter_active:
            get_app().layout.focus(self.search_field)
        else:
            self._apply_filter("")

    def _apply_filter(self, text):
        self.label_manager.apply_filter(text)
        self.text_area.text = self.get_result_text()
        self.selected_entry = 0
        self._update()
        get_app().invalidate()

    def _get_key_bindings(self) -> KeyBindings:  # noqa: C901, PLR0915
        kb = KeyBindings()

        @kb.add("up")
        def _go_up(event) -> None:
            if len(self.entries):
                selected_entry = self.selected_entry - 1
                if selected_entry >= 0:
                    self.selected_entry = selected_entry
                    self.text_area.control.move_cursor_up()
                    self._update()

        @kb.add("down")
        def _go_down(event) -> None:
            if len(self.entries):
                selected_entry = self.selected_entry + 1
                if selected_entry < len(self.entries):
                    self.selected_entry = selected_entry
                    self.text_area.control.move_cursor_down()
                    self._update()

        @kb.add("f")
        def _fp(event) -> None:
            entry = self.get_selected_entry()
            if entry:
                self.label_manager.add_label_entry(
                    entry.match,
                    artifact.Label.FalsePositive,
                )
            self._update()
            get_app().invalidate()

        @kb.add("t")
        def _tp(event) -> None:
            entry = self.get_selected_entry()
            if entry:
                self.label_manager.add_label_entry(
                    entry.match,
                    artifact.Label.TruePositive,
                )
            self._update()
            get_app().invalidate()

        @kb.add("?")
        def _unknown(event) -> None:
            entry = self.get_selected_entry()
            if entry:
                self.label_manager.add_label_entry(entry.match, artifact.Label.Unclear)
            self._update()
            get_app().invalidate()

        @kb.add("/")
        def _filter(event) -> None:
            self._toggle_filter()

        def get_single_label_entry():
            selected_entry = self.get_selected_entry()
            if not selected_entry:
                return None
            label_entries = self.label_manager.get_label_entries_by_match(
                selected_entry.match,
            )

            if not label_entries:
                return None

            return label_entries[0]

        @kb.add("e")
        def _edit_note(event) -> None:
            entry = get_single_label_entry()

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
            entry = get_single_label_entry()

            def done(fut: Future):
                if fut.done() and fut.result() is not None:
                    self.label_manager.edit_label_entry_json(entry.ID, fut.result())
                    self._update()

            self.dialog_executor(
                dialog=LabelJsonEditorDialog(entry),
                done_callback=done,
            )

        @kb.add("backspace")
        @kb.add("delete")
        def _delete_label(event) -> None:
            entry = get_single_label_entry()

            self.label_manager.remove_label_entry(entry.ID)

            self._update()

        return kb

    def __pt_container__(self) -> Container:
        return self.container
