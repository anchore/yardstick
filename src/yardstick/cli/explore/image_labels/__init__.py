from asyncio import Future, ensure_future
from typing import List, Optional

# from pygments.styles.monokai import MonokaiStyle as PygmentsStyle
from prompt_toolkit.application import Application
from prompt_toolkit.filters import has_focus
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.key_binding.bindings.focus import focus_next, focus_previous
from prompt_toolkit.layout import (
    Dimension,
    Float,
    FloatContainer,
    FormattedTextControl,
    HSplit,
    Layout,
    VSplit,
    Window,
)
from prompt_toolkit.styles import Style, style_from_pygments_cls
from pygments.styles.native import NativeStyle as PygmentsStyle

from yardstick import artifact
from yardstick.cli.explore.image_labels.display_pane import DisplayPane
from yardstick.cli.explore.image_labels.label_manager import LabelManager
from yardstick.cli.explore.image_labels.label_selection_pane import LabelSelectionPane
from yardstick.cli.explore.image_labels.result_selection_pane import ResultSelectionPane
from yardstick.cli.explore.image_labels.text_dialog import TextDialog


class Controller:
    def __init__(
        self,
        result: artifact.ScanResult,
        label_entries: List[artifact.LabelEntry],
        lineage: List[str],
        filter_spec: str = "",
    ):
        self.result = result
        self.lineage = lineage
        self.label_manager = LabelManager(result, label_entries, lineage)

        self.label_details_pane = LabelSelectionPane(
            self.label_manager,
            dialog_executor=self.show_dialog_as_float,
        )
        self.result_selection_pane = ResultSelectionPane(
            label_manager=self.label_manager,
            dialog_executor=self.show_dialog_as_float,
            match_setter=self.label_details_pane.set_match,
            filter_spec=filter_spec,
        )
        self.result_details_pane = DisplayPane(
            self.result_selection_pane.get_formatted_result_details,
            title="Result Details",
        )
        self.cve_details_pane = DisplayPane(
            self.result_selection_pane.get_formatted_cve_details,
            title="CVE Description",
            height=Dimension(preferred=8),
        )

        self.root_container = self._layout()
        self.application: Optional[Application] = None

    def show_dialog_as_float(self, dialog, done_callback):
        async def coroutine():
            float_ = Float(content=dialog)
            self.root_container.floats.append(float_)

            focused_before = self.application.layout.current_window
            self.application.layout.focus(dialog)
            result = await dialog.future
            self.application.layout.focus(focused_before)

            if float_ in self.root_container.floats:
                self.root_container.floats.remove(float_)

            return result

        ensure_future(coroutine()).add_done_callback(done_callback)

    def _layout(self):
        # note: the root container contains all floats for dialogs
        return FloatContainer(
            content=HSplit(
                [
                    # main header + image + tool info
                    Window(
                        content=FormattedTextControl(self._get_info_text),
                        height=Dimension.exact(3),
                        style="class:status",
                    ),
                    # Main content...
                    VSplit(
                        [
                            # Left side...
                            HSplit(
                                [
                                    self.result_selection_pane,
                                    # TODO: add filter here...
                                ],
                            ),
                            # Right side...
                            HSplit(
                                [
                                    self.cve_details_pane,
                                    self.label_details_pane,
                                    self.result_details_pane,
                                ],
                                width=Dimension(preferred=100),
                            ),
                        ],
                    ),
                    # Statusbar...
                    VSplit(
                        [
                            Window(
                                content=FormattedTextControl(self._get_keybinding_text),
                                # height=Dimension.exact(2),
                                height=Dimension.exact(1),
                                style="class:status",
                            ),
                            Window(
                                content=FormattedTextControl(self._get_status_text),
                                height=Dimension.exact(1),
                                style="class:status",
                                dont_extend_width=True,
                            ),
                        ],
                    ),
                ],
            ),
            floats=[],
        )

    @staticmethod
    def _styles() -> Style:
        pygments_style = dict(
            style_from_pygments_cls(pygments_style_cls=PygmentsStyle).style_rules,
        )

        style_dict = {
            "select-match-box cursor-line": "nounderline bold fg:#fcca03",
            "pane-title cursor-line": "nounderline bold reverse",
            "select-label-box cursor-line": "nounderline bold fg:#fcca03",
            "status": "reverse",
            "status.title": "bold",
            "status.key": "bold",
            "status.history-metric": "bg:#ff0066 bold",
            "filter-title": "fg:#fcca03",
            "filter-toolbar-text": "italic",
            "radio-selected": "bold fg:ansired underline",
            "radio-checked": "bold fg:ansired reverse",
        }

        style_dict.update(**pygments_style)

        return Style.from_dict(style_dict)

    def _keybindings(self):
        bindings = KeyBindings()
        bindings.add("tab")(focus_next)
        bindings.add("s-tab")(focus_previous)

        @bindings.add("c-s")
        def _save(_):
            self.label_manager.write()

        @bindings.add("c-c")
        def _exit(event):
            if self.label_manager.history.total_events():

                def done(fut: Future):
                    if fut.done() and fut.result() is True:
                        self.label_manager.write()
                    event.app.exit()

                self.show_dialog_as_float(
                    dialog=TextDialog(
                        title="Exiting...",
                        label_text="There are unsaved changes.",
                        text_area=False,
                        ok_button_text="Save",
                        cancel_button_text="Don't Save",
                    ),
                    done_callback=done,
                )
            else:
                event.app.exit()

        @bindings.add("c-z")
        def _undo(_):
            self.label_manager.undo()
            self.application.invalidate()

        @bindings.add("c-y")
        def _redo(_):
            self.label_manager.redo()
            self.application.invalidate()

        return bindings

    def _get_info_text(self):
        return [
            ("class:status.title", "Image "),
            ("class:status", self.result.config.image),
            ("class:status", "  "),
            ("class:status.title", "Tool "),
            ("class:status", f"{self.result.config.tool}"),
            ("class:status", "\n"),
            ("class:status.title", "Image Parents "),
            ("class:status", str(self.lineage)),
            ("class:status", "\n"),
            ("class:status.title", "Matches: "),
            (
                "class:status.history-metric",
                f"{len(self.label_manager.match_select_entries)}",
            ),
            ("class:status", "  "),
            ("class:status.title", "Applied Labels: "),
            ("class:status.history-metric", f"{self.label_manager.applied_labels()}"),
            ("class:status", "  "),
            ("class:status.title", "Labeled Matches: "),
            ("class:status.history-metric", f"{self.label_manager.matches_labeled()}"),
            ("class:status", "  "),
            ("class:status.title", "Unlabeled Matches: "),
            (
                "class:status.history-metric",
                f"{self.label_manager.matches_not_labeled()}",
            ),
            ("class:status", "  "),
            ("class:status.title", "F1 Score: "),
            ("class:status.history-metric", f"{self.label_manager.f1_score()}"),
            ("class:status", "  "),
        ]

    def _get_status_text(self):
        results = []

        undoneChanges = self.label_manager.history.undone_events()
        currentChanges = self.label_manager.history.total_events() - undoneChanges

        # fun, but unnecessary
        # if undoneChanges:
        #     results += [
        #         ("class:status", "undone changes: "),
        #         ("class:status.history-metric", f"{undoneChanges}"),
        #         ("class:status", "  "),
        #     ]

        if currentChanges:
            results += [
                ("class:status", "unsaved changes: "),
                ("class:status.history-metric", f"{currentChanges}"),
                ("class:status", "  "),
            ]

        return results

    def _get_keybinding_text(self):
        results = [
            ("class:status.key", " ^C"),
            ("class:status", " exit ▏"),
            ("class:status.key", "^S"),
            ("class:status", " save ▏"),
            ("class:status.key", "^Z/Y"),
            ("class:status", " undo/redo ▏"),
            ("class:status.key", "Tab"),
            ("class:status", " next pane ▏"),
        ]

        results_selected = has_focus(self.result_selection_pane)()
        labels_selected = has_focus(self.label_details_pane)()
        if results_selected:
            results += [
                ("class:status.key", "T/F/?"),
                ("class:status", " mark label ▏"),
                ("class:status.key", "E"),
                ("class:status", " edit note ▏"),
                ("class:status.key", "J"),
                ("class:status", " edit json ▏"),
                ("class:status.key", "DEL"),
                ("class:status", " delete ▏"),
                ("class:status.key", "/"),
                ("class:status", " filter ▏"),
            ]

        if labels_selected:
            results += [
                ("class:status.key", " E"),
                ("class:status", " edit label note ▏"),
                ("class:status.key", " J"),
                ("class:status", " edit label json ▏"),
                ("class:status.key", " DEL"),
                ("class:status", " delete label ▏"),
            ]

        return results

    def run(self):
        self.application: Application = Application(
            layout=Layout(
                self.root_container,
                focused_element=self.result_selection_pane,
            ),
            key_bindings=self._keybindings(),
            enable_page_navigation_bindings=True,
            mouse_support=False,  # trust me, this is better
            style=self._styles(),
            full_screen=True,
        )

        return self.application.run()


def run(
    result: artifact.ScanResult,
    label_entries: List[artifact.LabelEntry],
    lineage: List[str],
    filter_spec: str = "",
):
    Controller(result, label_entries, lineage, filter_spec).run()
