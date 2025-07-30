import datetime
import getpass
from typing import List

import click
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, HSplit, Window, FormattedTextControl, Dimension
from prompt_toolkit.styles import Style

from yardstick import artifact, store
from yardstick.utils import is_cve_vuln_id
from yardstick.validate import Gate


def get_vulnerability_info_url(match: artifact.Match) -> str | None:
    """Extract the specific vulnerability reference URL from match data."""
    # First try to get the URL from the fullentry (Grype scan data)
    if match.fullentry and isinstance(match.fullentry, dict):
        # Look for URL in vulnerability data
        vuln_data = match.fullentry.get("vulnerability", {})
        if isinstance(vuln_data, dict):
            # Try different possible URL fields
            for url_field in ["dataSource", "url", "reference", "link"]:
                url = vuln_data.get(url_field)
                if url and isinstance(url, str):
                    return url

    # Fallback to NIST NVD for CVE IDs if no specific URL found
    if is_cve_vuln_id(match.vulnerability.id):
        return f"https://nvd.nist.gov/vuln/detail/{match.vulnerability.id.upper()}"

    return None


class InteractiveValidateController:
    """Controller for interactive validation mode that handles match presentation and labeling."""

    def __init__(self, gates: List[Gate], label_entries: List[artifact.LabelEntry]):
        self.gates = gates
        self.label_entries = label_entries
        self.current_index = 0
        self.matches_to_label = self._collect_matches_to_label()
        self.labels_to_save: List[artifact.LabelEntry] = []

    def _collect_matches_to_label(self) -> List[tuple[str, artifact.Match, str, str | None, str | None, str | None]]:
        """Collect matches that need labeling, prioritized by importance.

        Returns list of tuples: (category, match, gate_image, reference_url, namespace, fixed_version)
        Categories: "candidate_only", "reference_only", "unlabeled_both"
        """
        matches = []

        for gate in self.gates:
            if not gate.deltas:
                continue

            for delta in gate.deltas:
                category = "candidate_only" if delta.added else "reference_only"

                match = artifact.Match(
                    vulnerability=artifact.Vulnerability(id=delta.vulnerability_id),
                    package=artifact.Package(name=delta.package_name, version=delta.package_version),
                )

                # Include matches that are unlabeled OR have unknown/unclear labels
                needs_labeling = not delta.label or delta.label == "(unknown)" or delta.label == "Unclear" or "?" in delta.label

                if needs_labeling:
                    matches.append((category, match, gate.input_description.image, delta.reference_url, delta.namespace, delta.fixed_version))

        # Sort by priority: candidate_only first, then reference_only, then others
        matches.sort(key=lambda x: (0 if x[0] == "candidate_only" else 1 if x[0] == "reference_only" else 2, x[1].vulnerability.id))
        return matches

    def has_next_match(self) -> bool:
        """Check if there are more matches to label."""
        return self.current_index < len(self.matches_to_label)

    def get_current_match(self) -> tuple[str, artifact.Match, str, str | None, str | None, str | None] | None:
        """Get the current match to be labeled."""
        if not self.has_next_match():
            return None
        return self.matches_to_label[self.current_index]

    def next_match(self) -> tuple[str, artifact.Match, str, str | None, str | None, str | None] | None:
        """Move to the next match and return it."""
        if self.has_next_match():
            match_info = self.get_current_match()
            self.current_index += 1
            return match_info
        return None

    def label_current_match(self, label: artifact.Label, note: str = "") -> bool:
        """Label the current match with the given label."""
        current = self.get_current_match()
        if not current:
            return False

        _, match, image, _, _, _ = current

        label_entry = artifact.LabelEntry(
            label=label,
            vulnerability_id=match.vulnerability.id,
            image=artifact.ImageSpecifier(exact=image),
            package=match.package,
            note=note if note else None,
            user=getpass.getuser(),
            timestamp=datetime.datetime.now(),
        )

        self.labels_to_save.append(label_entry)
        return True

    def get_progress(self) -> tuple[int, int]:
        """Get current progress (current_index, total_matches)."""
        return (self.current_index, len(self.matches_to_label))

    def save_labels(self):
        """Save all collected labels to storage."""
        if self.labels_to_save:
            store.labels.save(self.labels_to_save)
            self.labels_to_save.clear()


class InteractiveValidateTUI:
    """Interactive TUI for relabeling matches that caused quality gate failure."""

    def __init__(self, gates: List[Gate], label_entries: List[artifact.LabelEntry]):
        self.controller = InteractiveValidateController(gates, label_entries)

    def run(self):
        """Run the interactive validation TUI."""
        # Debug information
        total_gates = len(self.controller.gates)
        gates_with_deltas = len([g for g in self.controller.gates if g.deltas])
        total_deltas = sum(len(g.deltas) for g in self.controller.gates)
        total_matches = len(self.controller.matches_to_label)

        click.echo(f"Debug: Found {total_gates} gates, {gates_with_deltas} with deltas")
        click.echo(f"Debug: Total deltas: {total_deltas}, matches to label: {total_matches}")

        # Show detailed debug info about first few matches
        if self.controller.matches_to_label:
            click.echo("Debug: First few matches to label:")
            for i, (category, match, image, ref_url, namespace, fixed_version) in enumerate(self.controller.matches_to_label[:3]):
                url_info = f" (URL: {ref_url})" if ref_url else ""
                namespace_info = f" (namespace: {namespace})" if namespace else ""
                fix_info = f" (fixed in: {fixed_version})" if fixed_version else ""
                click.echo(
                    f"  {i + 1}. {category}: {match.vulnerability.id} in {match.package.name}@{match.package.version} (image: {image}){url_info}{namespace_info}{fix_info}"
                )

        if total_matches == 0:
            click.echo("No unlabeled matches found that need interactive labeling.")

            # Show what deltas we did find for debugging
            if total_deltas > 0:
                click.echo("Debug: Available deltas (all labeled):")
                for gate in self.controller.gates:
                    for delta in gate.deltas[:3]:  # Show first 3
                        click.echo(
                            f"  - {delta.vulnerability_id} in {delta.package_name}@{delta.package_version} (label: {delta.label}, added: {delta.added})"
                        )
            return

        self._run_tui()

    def _run_tui(self):
        """Run the prompt_toolkit TUI."""

        def get_text():
            current_match = self.controller.get_current_match()
            current_idx, total = self.controller.get_progress()

            if not current_match:
                return [
                    ("class:title", "Interactive Relabeling Complete"),
                    ("", "\n\n"),
                    ("class:success", f"All {total} matches have been processed!"),
                    ("", "\n\n"),
                    ("class:instruction", "Press 's' to save labels, or 'q' to exit without saving"),
                ]

            category, match, image, reference_url, namespace, fixed_version = current_match
            category_display = {
                "candidate_only": "CANDIDATE ONLY",
                "reference_only": "REFERENCE ONLY",
                "unlabeled_both": "UNLABELED (BOTH SCANS)",
            }.get(category, category.upper())

            # Use the specific reference URL from the delta, or fallback to generic URL
            vuln_url = reference_url or get_vulnerability_info_url(match)

            display_items = [
                ("class:title", f"Interactive Relabeling Mode ({current_idx + 1}/{total})"),
                ("", "\n"),
                ("class:category", f"Category: {category_display}"),
                ("", "\n"),
                ("class:field", "Image: "),
                ("", image),
                ("", "\n"),
                ("class:field", "Package: "),
                ("", f"{match.package.name}@{match.package.version}"),
                ("", "\n"),
                ("class:field", "Vulnerability: "),
                ("", match.vulnerability.id),
                ("", "\n"),
            ]

            # Add namespace information if available
            if namespace:
                display_items.extend(
                    [
                        ("class:field", "Namespace: "),
                        ("class:namespace", namespace),
                        ("", "\n"),
                    ]
                )

            # Add fixed version information if available
            if fixed_version:
                # Check if this is a fix state rather than version
                if fixed_version in ["not-fixed", "wont-fix", "unknown"]:
                    display_items.extend(
                        [
                            ("class:field", "Fix Status: "),
                            ("class:fix_status", fixed_version.upper()),
                            ("", "\n"),
                        ]
                    )
                else:
                    display_items.extend(
                        [
                            ("class:field", "Fixed Version: "),
                            ("class:fixed_version", fixed_version),
                            ("", "\n"),
                        ]
                    )

            # Add vulnerability information URL if available
            if vuln_url:
                display_items.extend(
                    [
                        ("class:field", "Info URL: "),
                        ("class:url", vuln_url),
                        ("", "\n"),
                    ]
                )

            display_items.extend(
                [
                    ("class:field", "Match ID: "),
                    ("", match.ID if hasattr(match, "ID") else "generated"),
                    ("", "\n\n"),
                ]
            )

            return display_items + [
                ("class:description", "This match was found "),
                (
                    "class:highlight",
                    "only by the candidate tool"
                    if category == "candidate_only"
                    else "only by the reference tool"
                    if category == "reference_only"
                    else "by both tools but is unlabeled",
                ),
                ("class:description", " and needs to be labeled to resolve the quality gate failure."),
                ("", "\n"),
                ("class:instruction", "Use the Info URL above to research the vulnerability before labeling."),
                ("", "\n\n"),
                ("class:instruction", "How should this match be labeled?"),
                ("", "\n"),
                ("class:key", "T"),
                ("", " - True Positive (TP)   - This is a valid vulnerability"),
                ("", "\n"),
                ("class:key", "F"),
                ("", " - False Positive (FP)  - This is NOT a valid vulnerability"),
                ("", "\n"),
                ("class:key", "?"),
                ("", " - Unclear             - Needs further investigation"),
                ("", "\n\n"),
                ("class:nav", "Navigation: "),
                ("class:key", "N"),
                ("", " - Next (skip)  "),
                ("class:key", "S"),
                ("", " - Save & Exit  "),
                ("class:key", "Q"),
                ("", " - Quit without saving"),
            ]

        def create_keybindings():
            bindings = KeyBindings()

            @bindings.add("t")
            def label_true_positive(event):
                if self.controller.label_current_match(artifact.Label.TruePositive):
                    self.controller.next_match()
                    event.app.invalidate()

            @bindings.add("f")
            def label_false_positive(event):
                if self.controller.label_current_match(artifact.Label.FalsePositive):
                    self.controller.next_match()
                    event.app.invalidate()

            @bindings.add("?")
            def label_unclear(event):
                if self.controller.label_current_match(artifact.Label.Unclear):
                    self.controller.next_match()
                    event.app.invalidate()

            @bindings.add("n")
            def next_match(event):
                self.controller.next_match()
                event.app.invalidate()

            @bindings.add("s")
            def save_and_exit(event):
                self.controller.save_labels()
                click.echo("Labels saved!")
                event.app.exit()

            @bindings.add("q")
            def quit_app(event):
                event.app.exit()

            @bindings.add("c-c")
            def quit_app_ctrl_c(event):
                event.app.exit()

            return bindings

        def create_style():
            return Style.from_dict(
                {
                    "title": "bold underline",
                    "category": "bold fg:ansiblue",
                    "field": "bold",
                    "key": "bold fg:ansired",
                    "instruction": "bold fg:ansigreen",
                    "success": "bold fg:ansigreen",
                    "description": "fg:ansiwhite",
                    "highlight": "bold fg:ansiyellow",
                    "nav": "fg:ansicyan",
                    "url": "fg:ansiblue underline",
                    "namespace": "fg:ansimagenta",
                    "fixed_version": "fg:ansigreen",
                    "fix_status": "bold fg:ansired",
                }
            )

        layout = Layout(
            HSplit(
                [
                    Window(
                        content=FormattedTextControl(get_text),
                        height=Dimension(preferred=25),
                    ),
                ]
            )
        )

        app: Application = Application(
            layout=layout,
            key_bindings=create_keybindings(),
            style=create_style(),
            mouse_support=False,
            full_screen=True,
        )

        app.run()
