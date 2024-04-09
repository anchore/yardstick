import json
import logging
import queue
from collections import defaultdict
from threading import Lock, Thread
from typing import Dict, List, Optional, Tuple

import pygments
from prompt_toolkit.application import get_app
from prompt_toolkit.formatted_text import (
    HTML,
    AnyFormattedText,
    FormattedText,
    PygmentsTokens,
    merge_formatted_text,
    to_formatted_text,
)
from pygments.lexers.data import JsonLexer
from tabulate import tabulate

from yardstick import artifact, comparison, store
from yardstick.cli.explore.image_labels.history import Command, History
from yardstick.cli.explore.result import MatchCollection
from yardstick.label import find_labels_for_match
from yardstick.tool import get_tool

# a set of unique locks for each object
_locks: Dict[int, Lock] = defaultdict(Lock)


def synchronized(func):
    def _synchronized(self, *args, **kw):
        with _locks[self]:
            return func(self, *args, **kw)

    return _synchronized


class WorkerWithTaskInvalidation:
    def __init__(self):
        self.done = False
        self.work: queue.Queue = queue.Queue(maxsize=0)
        self.t = Thread(target=self._worker)
        self.t.daemon = True
        self.t.start()

    def _worker(self):
        while not self.done:
            fn = self.work.get()
            try:
                fn()
            except Exception:
                logging.exception("background worker failed to complete a task")

    def submit(self, fn):
        self.clear()  # keep only the most recent request for work, invalidate anything queued
        self.work.put_nowait(fn)

    def clear(self):
        # a bit of a hack, but essentially removes all items from the queue in a thread-safe fashion
        with self.work.mutex:
            self.work.queue.clear()
            self.work.all_tasks_done.notify_all()
            self.work.unfinished_tasks = 0


class MatchSelectEntry:
    def __init__(
        self,
        match: artifact.Match,
        display: str,
        labels: Optional[AnyFormattedText] = None,
    ):
        self.match = match
        self.display = display
        self.formatted_labels = labels or FormattedText()
        self.num_labels = 0

    def get_formatted_annotations(self):
        return self.formatted_labels

    def get_formatted_details(self):
        table = [
            ["<b>Vulnerability:</b>", self.match.vulnerability.id],
            ["<b>Package Name:</b>", self.match.package.name],
            ["<b>Package Version:</b>", self.match.package.version],
            ["<b>Match ID:</b>", self.match.ID],
            ["<b>Full JSON Entry:</b>", ""],
        ]
        rows = []

        for row in tabulate(table, tablefmt="plain").split("\n"):
            rows.append(HTML(row + "\n"))

        json_str = json.dumps(self.match.fullentry, indent=2)
        tokens = list(pygments.lex(json_str, lexer=JsonLexer()))
        formatted_full_entry = to_formatted_text(PygmentsTokens(tokens))
        rows.append(formatted_full_entry)

        return merge_formatted_text(rows)


class LabelManager:
    def __init__(
        self,
        result: artifact.ScanResult,
        label_entries: List[artifact.LabelEntry],
        lineage: List[str],
    ):
        self.result = result
        self.lineage = lineage
        self.collection = MatchCollection(result)
        self.filter_text = None
        # we should filter down the set of label entries that we have to only those which match with this image. This
        # is a performance enhancement to prevent matching an ALL labels for all images on every UI action.
        self.label_entries: List[artifact.LabelEntry] = (
            self._keep_only_matched_label_entries(label_entries, lineage)
        )
        self.match_select_entries_invalidated = True
        self._last_match_select_entries: List[MatchSelectEntry] = []
        self.deleted_label_entries: List[artifact.LabelEntry] = []
        self.worker = WorkerWithTaskInvalidation()
        self.comparison: Optional[comparison.AgainstLabels] = None
        self.history = History()
        self.labels_invalidated = False
        self._update_comparison()

    def apply_filter(self, text):
        self.match_select_entries_invalidated = True
        self.filter_text = text

    def _keep_only_matched_label_entries(
        self,
        label_entries,
        lineage,
    ) -> List[artifact.LabelEntry]:
        keep_label_entries = []
        all_matches = self.collection.get_matches(filter_text=None)
        for match in all_matches:
            for label_entry in find_labels_for_match(
                image=self.result.config.image,
                match=match,
                label_entries=label_entries,
                lineage=lineage,
            ):
                if label_entry not in keep_label_entries:
                    keep_label_entries.append(label_entry)
        return keep_label_entries

    @property
    def match_select_entries(self) -> List[MatchSelectEntry]:
        if self.match_select_entries_invalidated:
            self.labels_invalidated = True
            self.match_select_entries_invalidated = False
            all_matches = self.collection.get_matches(filter_text=self.filter_text)

            table: List[List[str]] = []
            entries: List[MatchSelectEntry] = []

            for match in all_matches:
                if not match.config:
                    continue

                t = get_tool(match.config.tool_name)
                package_type = t.parse_package_type(match.fullentry)  # type: ignore[union-attr]
                row_cells = [
                    match.vulnerability.id,
                    f"{match.package.name} @ {match.package.version}",
                ]
                if package_type and package_type != "unknown":
                    row_cells.append(package_type)
                table.append(row_cells)

            rows = tabulate(table, tablefmt="plain").split("\n")

            for idx, match in enumerate(all_matches):
                row = rows[idx]
                select_entry = MatchSelectEntry(match=match, display=row)
                entries.append(select_entry)

            self._last_match_select_entries = entries
            self._update()

        return self._last_match_select_entries

    def _update_comparison(self):
        try:
            self.comparison = comparison.AgainstLabels(
                result=self.result,
                label_entries=self.label_entries,
                lineage=self.lineage,
            )

            # update formatted labels
            for entry in self.match_select_entries:
                entry.formatted_labels, entry.num_labels = format_labels(
                    entry.match,
                    self.comparison,
                )
        except:  # noqa: E722
            logging.exception("could not update label pane")

        get_app().invalidate()

    def _update(self):
        if self.labels_invalidated:
            self.labels_invalidated = False
            self.worker.submit(self._update_comparison)

    def get_label_entries_by_match(
        self,
        match: artifact.Match,
    ) -> List[artifact.LabelEntry]:
        return find_labels_for_match(
            image=self.result.config.image,
            match=match,
            label_entries=self.label_entries,
            lineage=self.lineage,
        )

    def get_label_entry_by_id(
        self,
        label_entry_id: str,
    ) -> Optional[artifact.LabelEntry]:
        label_entries = [
            label for label in self.label_entries if label_entry_id == label.ID
        ]
        if len(label_entries) > 1:
            raise RuntimeError

        if not label_entries:
            return None

        return label_entries[0]

    def get_label_entry_index(self, label_entry_id: str) -> Optional[int]:
        for idx, label in enumerate(self.label_entries):
            if label_entry_id == label.ID:
                return idx
        return None

    @synchronized
    def edit_label_entry_json(self, label_entry_id: str, raw_json: str = ""):
        old_label_entry = self.get_label_entry_by_id(label_entry_id)

        def undo():
            entry_idx = self.get_label_entry_index(label_entry_id)
            if entry_idx is not None:
                self.label_entries[entry_idx] = old_label_entry

        def redo():
            entry_idx = self.get_label_entry_index(label_entry_id)
            if entry_idx is not None:
                self.label_entries[entry_idx] = artifact.LabelEntry.from_json(
                    raw_json,
                )

        self.history.record(Command(undo=undo, redo=redo))

        self._update()

    @synchronized
    def edit_label_entry_note(self, label_entry_id: str, note: str = ""):
        label_entry = self.get_label_entry_by_id(label_entry_id)
        if not label_entry:
            raise ValueError(f"no label entry found with ID {label_entry_id}")
        old_note = label_entry.note

        def undo():
            self.labels_invalidated = True
            label_entry.note = old_note

        def redo():
            self.labels_invalidated = True
            label_entry.note = note

        self.history.record(Command(undo=undo, redo=redo))

        self._update()

    @synchronized
    def add_label_entry(
        self,
        match: artifact.Match,
        label: artifact.Label,
        note: str = "",
    ):
        new_entry = artifact.LabelEntry(
            # source=MANUAL_SOURCE,
            image=artifact.ImageSpecifier(exact=self.result.config.image),
            vulnerability_id=match.vulnerability.id,
            package=match.package,
            label=label,
            note=note,
            tool=self.result.config.tool,
            lookup_effective_cve=True,
        )

        def undo():
            self.labels_invalidated = True
            # note: cannot use list.remove() since hash() of LabelEntry does not include ID
            self.label_entries = [e for e in self.label_entries if e.ID != new_entry.ID]

        def redo():
            self.labels_invalidated = True
            self.label_entries.append(new_entry)

        self.history.record(Command(undo=undo, redo=redo))

        self._update()

    @synchronized
    def remove_label_entry(self, label_entry_id: str):
        label_entry = self.get_label_entry_by_id(label_entry_id)
        if not label_entry:
            raise ValueError(f"no label entry found with ID {label_entry_id}")
        label_entry_index = self.label_entries.index(label_entry)

        def undo():
            self.labels_invalidated = True
            self.label_entries.insert(label_entry_index, label_entry)
            self.deleted_label_entries.remove(label_entry)

        def redo():
            self.labels_invalidated = True
            self.label_entries.remove(label_entry)
            self.deleted_label_entries.append(label_entry)

        self.history.record(Command(undo=undo, redo=redo))

        self._update()

    def total_labels(self):
        return len(self.label_entries)

    def applied_labels(self):
        applied = 0
        for entry in self.match_select_entries:
            applied += entry.num_labels
        return applied

    def matches_not_labeled(self):
        no_labels = 0
        for entry in self.match_select_entries:
            if not entry.num_labels:
                no_labels += 1
        return no_labels

    def matches_labeled(self):
        num_labeled = 0
        for entry in self.match_select_entries:
            if entry.num_labels:
                num_labeled += 1
        return num_labeled

    def f1_score(self):
        if self.comparison is not None:
            low = f"{self.comparison.summary.f1_score_lower_confidence:0.2f}"
            high = f"{self.comparison.summary.f1_score_upper_confidence:0.2f}"
            return f"{self.comparison.summary.f1_score:.2f} (possible range {low} - {high})"
        return "??"

    @synchronized
    def undo(self):
        self.history.undo()
        self._update()

    @synchronized
    def redo(self):
        self.history.redo()
        self._update()

    @synchronized
    def write(self):
        store.labels.append_and_update(
            new_and_modified_entries=self.label_entries,
            delete_entries=self.deleted_label_entries,
        )
        self.history.reset()


def format_labels(
    match: artifact.Match,
    comp: comparison.AgainstLabels,
) -> Tuple[AnyFormattedText, int]:
    labels = comp.labels_by_match[match.ID]
    colors = {
        artifact.Label.TruePositive: ("#0062ff", "#002a6e", "#ffffff"),
        artifact.Label.FalsePositive: ("#ff0066", "#99003d", "#ffffff"),
        artifact.Label.Unclear: ("#888888", "#444444", "#ffffff"),
    }

    result = []
    applied_labels = 0
    for label in (
        artifact.Label.TruePositive,
        artifact.Label.FalsePositive,
        artifact.Label.Unclear,
    ):
        c = labels.count(label)
        if c:
            applied_labels += c
            bg, dbg, fg = colors[label]
            result += [
                to_formatted_text(
                    " " + label.display + " ",
                    style=f"bold bg:{bg} {fg}",
                ),
                to_formatted_text(" " + str(c) + " ", style=f"bold bg:{dbg} {fg}"),
                to_formatted_text(" "),
            ]

    return merge_formatted_text(result)(), applied_labels  # type: ignore[operator, misc]
