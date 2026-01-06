import datetime
import getpass
from typing import List

import click
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, VSplit, Window, FormattedTextControl, Dimension
from prompt_toolkit.styles import Style

import yardstick
from yardstick import artifact, store, comparison
from yardstick.utils import is_cve_vuln_id
from yardstick.validate import Gate
from yardstick.label import find_labels_for_match


def format_match_details(match: artifact.Match) -> List[tuple[str, str]]:
    """Extract and format key information from matchDetails for display."""
    if not match.fullentry or not isinstance(match.fullentry, dict):
        return [("", "No match details available")]

    match_details = match.fullentry.get("matchDetails", [])
    if not match_details or not isinstance(match_details, list):
        return [("", "No match details available")]

    formatted_details = []
    for i, detail in enumerate(match_details[:3]):  # Show first 3 details
        if not isinstance(detail, dict):
            continue

        detail_lines = [("class:match_detail_header", f"Match Detail {i + 1}:")]
        detail_lines.append(("", "\n"))

        # Show type and matcher
        if "type" in detail:
            detail_lines.append(("class:field", "  Type: "))
            detail_lines.append(("", str(detail["type"])))
            detail_lines.append(("", "\n"))

        if "matcher" in detail:
            detail_lines.append(("class:field", "  Matcher: "))
            detail_lines.append(("", str(detail["matcher"])))
            detail_lines.append(("", "\n"))

        # Show searchedBy information
        if "searchedBy" in detail:
            searched_by = detail["searchedBy"]
            if isinstance(searched_by, dict):
                detail_lines.append(("class:field", "  Searched By:"))
                detail_lines.append(("", "\n"))

                # Handle distro information
                if "distro" in searched_by and isinstance(searched_by["distro"], dict):
                    distro = searched_by["distro"]
                    detail_lines.append(("class:field", "    Distro: "))
                    distro_parts = []
                    if "type" in distro:
                        distro_parts.append(f"type={distro['type']}")
                    if "version" in distro:
                        distro_parts.append(f"version={distro['version']}")
                    detail_lines.append(("", " ".join(distro_parts)))
                    detail_lines.append(("", "\n"))

                # Handle package information
                if "package" in searched_by and isinstance(searched_by["package"], dict):
                    pkg = searched_by["package"]
                    detail_lines.append(("class:field", "    Package: "))
                    pkg_parts = []
                    if "name" in pkg:
                        pkg_parts.append(f"name={pkg['name']}")
                    if "version" in pkg:
                        pkg_parts.append(f"version={pkg['version']}")
                    detail_lines.append(("", " ".join(pkg_parts)))
                    detail_lines.append(("", "\n"))

                # Handle namespace
                if "namespace" in searched_by:
                    detail_lines.append(("class:field", "    Namespace: "))
                    detail_lines.append(("", str(searched_by["namespace"])))
                    detail_lines.append(("", "\n"))

                # Handle language (for other matcher types)
                if "language" in searched_by:
                    detail_lines.append(("class:field", "    Language: "))
                    detail_lines.append(("", str(searched_by["language"])))
                    detail_lines.append(("", "\n"))

        # Show found information
        if "found" in detail:
            found = detail["found"]
            if isinstance(found, dict):
                detail_lines.append(("class:field", "  Found:"))
                detail_lines.append(("", "\n"))

                if "vulnerabilityID" in found:
                    detail_lines.append(("class:field", "    Vuln ID: "))
                    detail_lines.append(("", str(found["vulnerabilityID"])))
                    detail_lines.append(("", "\n"))

                if "versionConstraint" in found:
                    detail_lines.append(("class:field", "    Constraint: "))
                    detail_lines.append(("", str(found["versionConstraint"])))
                    detail_lines.append(("", "\n"))

        # Show fix information if available
        if "fix" in detail:
            fix_info = detail["fix"]
            if isinstance(fix_info, dict):
                detail_lines.append(("class:field", "  Fix:"))
                detail_lines.append(("", "\n"))

                if "suggestedVersion" in fix_info:
                    detail_lines.append(("class:field", "    Suggested: "))
                    detail_lines.append(("class:fixed_version", str(fix_info["suggestedVersion"])))
                    detail_lines.append(("", "\n"))

        detail_lines.append(("", "\n"))
        formatted_details.extend(detail_lines)

    if len(match_details) > 3:
        formatted_details.append(("class:field", f"... and {len(match_details) - 3} more match details"))
        formatted_details.append(("", "\n"))

    return formatted_details


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

    def __init__(
        self,
        gates: List[Gate],
        label_entries: List[artifact.LabelEntry],
        relative_comparison: comparison.ByPreservedMatch | None = None,
        year_max_limit: int | None = None,
        year_from_cve_only: bool = False,
    ):
        self.gates = gates
        self.label_entries = label_entries
        self.relative_comparison = relative_comparison
        self.year_max_limit = year_max_limit
        self.year_from_cve_only = year_from_cve_only

        # Track which gates failed and their failure order
        self.failed_gates = [gate for gate in gates if not gate.passed()]
        self.failed_images_order = [gate.input_description.image for gate in self.failed_gates]

        # Build mapping from result_id to image to fix common match labeling bug
        self._result_id_to_image: dict[str, str] = {}
        self._build_result_id_to_image_mapping()

        self.current_index = 0
        self.matches_to_label = self._collect_matches_to_label()
        self.processing_deltas = True

        # Cache for labels needed calculation to avoid expensive recalculations
        self._labels_needed_cache: dict[str, int | None] = {}  # image -> labels_needed
        self._last_cached_image: str | None = None

        # If no relative comparison provided, try to create it
        if not self.relative_comparison and gates:
            self._create_relative_comparison()

        # If no delta matches need labeling, immediately check for common matches
        if not self.matches_to_label and self.relative_comparison:
            self._add_common_unlabeled_matches()
            self.processing_deltas = False  # We're starting directly with common matches

    def _build_result_id_to_image_mapping(self) -> None:
        """Build mapping from result_id to correct image for accurate label creation."""
        for gate in self.failed_gates:
            image = gate.input_description.image
            for config in gate.input_description.configs:
                self._result_id_to_image[config.id] = image

    def _create_relative_comparison(self) -> None:
        """Create relative comparison data for accessing common matches."""
        try:
            # Get result descriptions from the first gate
            if not self.gates or not self.gates[0].input_description.configs:
                return

            descriptions = [config.id for config in self.gates[0].input_description.configs]
            if len(descriptions) < 2:
                return

            # Create the comparison - using year filtering parameters from CLI
            self.relative_comparison = yardstick.compare_results(
                descriptions=descriptions,
                year_max_limit=self.year_max_limit,
                year_from_cve_only=self.year_from_cve_only,
                matches_filter=None,  # Could add namespace filtering if needed
            )
        except Exception as e:
            # If we can't create the comparison, just continue without common matches
            print(f"Warning: Could not create relative comparison for common matches: {e}")

    def _should_filter_match_by_year(self, match: artifact.Match) -> bool:
        """Check if a match should be filtered out based on year constraints."""
        if self.year_max_limit is None:
            return False  # No year filtering

        year = match.vulnerability.effective_year(by_cve=self.year_from_cve_only)
        if year is None:
            return False  # Include matches with unknown years

        return year > self.year_max_limit  # Filter out if year is greater than max

    def _get_image_priority(self, image: str) -> tuple[int, int]:
        """Get priority for an image based on failure status and order.

        Returns (failure_priority, failure_order) where:
        - failure_priority: 0 for failed images, 1 for non-failed images
        - failure_order: position in failed_images_order (0-based) or 999 for non-failed
        """
        if image in self.failed_images_order:
            return (0, self.failed_images_order.index(image))
        else:
            return (1, 999)  # Non-failed images get lower priority

    def _collect_matches_to_label(self) -> List[tuple[str, artifact.Match, str, str | None, str | None, str | None, str | None]]:
        """Collect matches that need labeling, prioritized by importance.

        Returns list of tuples: (category, match, gate_image, reference_url, namespace, fixed_version, result_id)
        Categories: "candidate_only", "reference_only", "common_unlabeled"
        """
        matches = []

        # First collect delta matches (candidate_only, reference_only) - only from failed gates
        for gate in self.failed_gates:
            if not gate.deltas:
                continue

            for delta in gate.deltas:
                category = "candidate_only" if delta.added else "reference_only"

                # Use the full match if available, otherwise create a minimal one
                match = (
                    delta.full_match
                    if delta.full_match
                    else artifact.Match(
                        vulnerability=artifact.Vulnerability(id=delta.vulnerability_id),
                        package=artifact.Package(name=delta.package_name, version=delta.package_version),
                    )
                )

                # Include matches that are unlabeled OR have unknown/unclear labels
                needs_labeling = not delta.label or delta.label == "(unknown)" or delta.label == "Unclear" or "?" in delta.label

                # Apply year filtering
                if needs_labeling and not self._should_filter_match_by_year(match):
                    matches.append(
                        (
                            category,
                            match,
                            gate.input_description.image,
                            delta.reference_url,
                            delta.namespace,
                            delta.fixed_version,
                            delta.result_id,
                        )
                    )

        # Sort by priority: failed images first, then category priority, then vulnerability ID, package name, package version for full determinism
        def sort_key(match_tuple):
            category, match, image, _, _, _, _ = match_tuple
            image_priority = self._get_image_priority(image)
            category_priority = 0 if category == "candidate_only" else 1 if category == "reference_only" else 2
            return (
                image_priority[0],
                image_priority[1],
                category_priority,
                match.vulnerability.id,
                match.package.name or "",
                match.package.version or "",
            )

        matches.sort(key=sort_key)
        return matches

    def has_next_match(self) -> bool:
        """Check if there are more matches to label."""
        if self.current_index < len(self.matches_to_label):
            return True

        # If we've finished processing deltas, check if we can switch to common matches
        if self.processing_deltas and self.relative_comparison:
            self._add_common_unlabeled_matches()
            self.processing_deltas = False
            return self.current_index < len(self.matches_to_label)

        return False

    def _add_common_unlabeled_matches(self) -> None:
        """Add unlabeled common matches to the list after processing deltas."""
        if not self.failed_gates:
            return

        common_matches = []

        # Process common matches for each failed gate individually
        for failed_gate in self.failed_gates:
            gate_image = failed_gate.input_description.image

            # Get the result descriptions for this specific gate
            descriptions = [config.id for config in failed_gate.input_description.configs]
            if len(descriptions) < 2:
                continue  # Need at least 2 results to have common matches

            try:
                # Create relative comparison for this specific gate's image and results
                gate_relative_comparison = yardstick.compare_results(
                    descriptions=descriptions,
                    year_max_limit=self.year_max_limit,
                    year_from_cve_only=self.year_from_cve_only,
                    matches_filter=None,
                )

                # Process common matches from this gate's specific comparison
                for equivalent_match in gate_relative_comparison.common:
                    # Use the first match from any tool as the representative
                    representative_match = None
                    for matches_list in equivalent_match.matches.values():
                        if matches_list:
                            representative_match = matches_list[0]
                            break

                    if not representative_match:
                        continue

                    # Check if this match is already labeled
                    # Need to find which result_id this representative match came from
                    representative_result_id = None
                    for result_key, matches_list in equivalent_match.matches.items():
                        if matches_list and matches_list[0] == representative_match:
                            representative_result_id = result_key
                            break

                    # Use the result_id to get the correct image for label matching
                    # This fixes the bug where common matches used wrong image context for label detection
                    correct_image_for_label_check = (
                        self._result_id_to_image.get(representative_result_id, gate_image) if representative_result_id else gate_image
                    )

                    match_labels = find_labels_for_match(
                        correct_image_for_label_check,
                        representative_match,
                        self.label_entries,
                        lineage=[],  # TODO: Could pass actual lineage if available
                        fuzzy_package_match=False,
                    )

                    # Only include if unlabeled or unclear AND not filtered by year
                    if (
                        not match_labels
                        or any(label.label in [artifact.Label.Unclear] for label in match_labels)
                        or len(set(label.label for label in match_labels)) != 1
                    ) and not self._should_filter_match_by_year(representative_match):
                        # Extract metadata like we do for deltas
                        reference_url = get_vulnerability_info_url(representative_match)
                        namespace = (
                            representative_match.fullentry.get("vulnerability", {}).get("namespace") if representative_match.fullentry else None
                        )
                        fixed_version = None
                        if representative_match.fullentry and isinstance(representative_match.fullentry, dict):
                            match_details = representative_match.fullentry.get("matchDetails", [])
                            for detail in match_details:
                                if isinstance(detail, dict) and "fix" in detail:
                                    fix_info = detail["fix"]
                                    if isinstance(fix_info, dict) and "suggestedVersion" in fix_info:
                                        fixed_version = str(fix_info["suggestedVersion"])
                                        break

                        # For common matches, use the first available result ID from this gate's comparison
                        # All result IDs in equivalent_match correspond to the same image (this gate's image)
                        result_id = None
                        for result_key, matches_list in equivalent_match.matches.items():
                            if matches_list:
                                result_id = result_key
                                break

                        # Use the correct image from result_id mapping for consistency
                        correct_image_for_match_tuple = self._result_id_to_image.get(result_id, gate_image) if result_id else gate_image

                        # Determine more accurate category based on label status
                        if not match_labels:
                            category = "common_unlabeled"
                        elif any(label.label in [artifact.Label.Unclear] for label in match_labels):
                            category = "common_unclear"
                        elif len(set(label.label for label in match_labels)) != 1:
                            category = "common_mixed"
                        else:
                            # This shouldn't happen since we only include matches that need attention
                            category = "common_unlabeled"

                        common_matches.append(
                            (
                                category,
                                representative_match,
                                correct_image_for_match_tuple,  # Use the correct image here too
                                reference_url,
                                namespace,
                                fixed_version,
                                result_id,
                            )
                        )

            except Exception as e:
                # If we can't create comparison for this gate, skip it and continue with others
                print(f"Warning: Could not create relative comparison for {gate_image}: {e}")
                continue

        # Sort common matches by image priority, then by label status (unlabeled first, then conflicting), then vulnerability ID, package name, package version for full determinism
        def sort_key(match_tuple):
            category, match, image, _, _, _, _ = match_tuple
            image_priority = self._get_image_priority(image)

            # Priority for label status: unlabeled (0) is easiest to resolve, then unclear (1), then mixed (2)
            label_priority = 0 if category == "common_unlabeled" else 1 if category == "common_unclear" else 2

            return (
                image_priority[0],
                image_priority[1],
                label_priority,
                match.vulnerability.id,
                match.package.name or "",
                match.package.version or "",
            )

        common_matches.sort(key=sort_key)
        self.matches_to_label.extend(common_matches)

    def get_current_match(self) -> tuple[str, artifact.Match, str, str | None, str | None, str | None, str | None] | None:
        """Get the current match to be labeled."""
        if not self.has_next_match():
            return None
        return self.matches_to_label[self.current_index]

    def next_match(self) -> tuple[str, artifact.Match, str, str | None, str | None, str | None, str | None] | None:
        """Move to the next match and return it."""
        if self.has_next_match():
            match_info = self.get_current_match()
            self.current_index += 1
            return match_info
        return None

    def label_current_match(self, label: artifact.Label, note: str = "") -> bool:
        """Label the current match with the given label and save immediately."""
        current = self.get_current_match()
        if not current:
            return False

        _, match, tuple_image, _, _, _, result_id = current

        # Use result_id to get the correct image, falling back to tuple image if mapping not available
        # This fixes the bug where common matches had incorrect image associations
        correct_image = self._result_id_to_image.get(result_id, tuple_image) if result_id else tuple_image

        label_entry = artifact.LabelEntry(
            label=label,
            vulnerability_id=match.vulnerability.id,
            image=artifact.ImageSpecifier(exact=correct_image),
            package=match.package,
            note=note if note else None,
            user=getpass.getuser(),
            timestamp=datetime.datetime.now(),
        )

        # Save immediately to prevent data loss
        store.labels.save([label_entry])

        # Decrement the cached labels needed count for the correct image
        self._decrement_labels_needed_cache(correct_image)

        return True

    def _decrement_labels_needed_cache(self, image: str) -> None:
        """Decrement the cached labels needed count for the given image."""
        if image in self._labels_needed_cache and self._labels_needed_cache[image] is not None:
            current_count = self._labels_needed_cache[image]
            if current_count > 0:
                self._labels_needed_cache[image] = current_count - 1

    def get_progress(self) -> tuple[int, int]:
        """Get current progress (current_index, total_matches)."""
        return (self.current_index, len(self.matches_to_label))

    def skip_to_next_image(self) -> bool:
        """Skip all remaining matches for the current image and move to the next image.

        Returns True if successfully skipped to next image, False if no next image available.
        """
        current_match = self.get_current_match()
        if not current_match:
            return False

        current_image = current_match[2]  # image is at index 2 in the tuple

        # Find the next match from a different image
        while self.current_index < len(self.matches_to_label):
            match_info = self.matches_to_label[self.current_index]
            match_image = match_info[2]  # image is at index 2

            if match_image != current_image:
                # Found a match from a different image
                return True

            # Still the same image, keep advancing
            self.current_index += 1

        # If we've finished processing deltas but haven't added common matches yet, try that
        if self.processing_deltas and self.current_index >= len(self.matches_to_label):
            self._add_common_unlabeled_matches()
            self.processing_deltas = False

            # Check if we now have matches from a different image
            while self.current_index < len(self.matches_to_label):
                match_info = self.matches_to_label[self.current_index]
                match_image = match_info[2]

                if match_image != current_image:
                    return True

                self.current_index += 1

        # No more matches or no different image found
        return False

    def get_labels_needed_for_current_image(self) -> int | None:
        """Calculate how many more labels needed for current image to pass its gate.

        Uses caching to avoid expensive recalculation on every call.
        Returns None if not applicable (no current match, gate not failing due to percentage, etc.)
        """
        current_match = self.get_current_match()
        if not current_match:
            return None

        image = current_match[2]  # image at index 2

        # Check if we've switched to a new image - if so, invalidate cache
        if self._last_cached_image != image:
            self._labels_needed_cache.clear()
            self._last_cached_image = image

        # Return cached value if available
        if image in self._labels_needed_cache:
            return self._labels_needed_cache[image]

        # Calculate and cache the result
        labels_needed = self._calculate_labels_needed_for_image(image)
        self._labels_needed_cache[image] = labels_needed
        return labels_needed

    def _calculate_labels_needed_for_image(self, image: str) -> int | None:
        """Internal method to calculate labels needed for a specific image.

        This does the expensive calculation that gets cached.
        """

        # Find the failed gate for this image
        failed_gate = next((g for g in self.failed_gates if g.input_description.image == image), None)
        if not failed_gate:
            return None

        # Check if this gate failed due to indeterminate percentage
        indeterminate_failure = any("indeterminate matches %" in reason for reason in failed_gate.reasons)
        if not indeterminate_failure:
            return None  # Not failing due to unlabeled matches

        try:
            # Get the result descriptions for this gate (same as in validate_image)
            descriptions = [config.id for config in failed_gate.input_description.configs]
            if len(descriptions) < 2:
                return None

            # Recreate the same label comparison that the gate used
            # This ensures we use the exact same calculation
            results, label_entries, comparisons_by_result_id, _ = yardstick.compare_results_against_labels(
                descriptions=descriptions,
                year_max_limit=self.year_max_limit,
                year_from_cve_only=self.year_from_cve_only,
                label_entries=self.label_entries,
                matches_filter=None,
            )

            # Find the candidate tool comparison (same logic as in Gate.__post_init__)
            candidate_tool = None
            reference_tool = None

            # Get tool designations (same logic as in validate_image)
            from yardstick.validate.validate import tool_designations

            scan_configs = [comparison.config for comparison in comparisons_by_result_id.values()]
            candidate_tool, reference_tool = tool_designations(failed_gate.config.candidate_tool_label, scan_configs)

            if not candidate_tool:
                return None

            # Find the candidate comparison for this image
            candidate_comparisons_by_image = {
                comp.config.image: comp for comp in comparisons_by_result_id.values() if comp.config.tool == candidate_tool
            }

            if image not in candidate_comparisons_by_image:
                return None

            candidate_comparison = candidate_comparisons_by_image[image]

            # Now we have the exact same comparison the gate uses!
            max_allowed_percent = failed_gate.config.max_unlabeled_percent

            # Calculate how many labels needed to get under the threshold
            total_matches = candidate_comparison.summary.total
            current_indeterminate = candidate_comparison.summary.indeterminate

            if total_matches == 0:
                return None

            # Calculate max allowed indeterminate matches (must be <= max_allowed_percent)
            max_allowed_indeterminate = int(total_matches * max_allowed_percent / 100)

            # How many matches need to be labeled to get indeterminate count down to acceptable level
            labels_needed = max(0, current_indeterminate - max_allowed_indeterminate)

            return labels_needed

        except Exception as e:
            # If we can't recreate the gate calculation, return None
            print(f"Warning: Could not calculate labels needed for {image}: {e}")
            return None


class InteractiveValidateTUI:
    """Interactive TUI for relabeling matches that caused quality gate failure."""

    def __init__(
        self,
        gates: List[Gate],
        label_entries: List[artifact.LabelEntry],
        relative_comparison: comparison.ByPreservedMatch | None = None,
        year_max_limit: int | None = None,
        year_from_cve_only: bool = False,
    ):
        self.controller = InteractiveValidateController(gates, label_entries, relative_comparison, year_max_limit, year_from_cve_only)

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
            for i, (category, match, image, ref_url, namespace, fixed_version, result_id) in enumerate(self.controller.matches_to_label[:3]):
                url_info = f" (URL: {ref_url})" if ref_url else ""
                namespace_info = f" (namespace: {namespace})" if namespace else ""
                fix_info = f" (fixed in: {fixed_version})" if fixed_version else ""
                click.echo(
                    f"  {i + 1}. {category}: {match.vulnerability.id} in {match.package.name}@{match.package.version} (image: {image}){url_info}{namespace_info}{fix_info}"
                )

        # Re-check total matches after potentially adding common matches
        total_matches_final = len(self.controller.matches_to_label)
        if total_matches_final > total_matches:
            click.echo(f"Debug: Added {total_matches_final - total_matches} common unlabeled matches")
            click.echo(f"Debug: Total matches to label: {total_matches_final}")

        if total_matches_final == 0:
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

        def get_main_text():
            current_match = self.controller.get_current_match()
            current_idx, total = self.controller.get_progress()

            if not current_match:
                return [
                    ("class:title", "Interactive Relabeling Complete"),
                    ("", "\n\n"),
                    ("class:success", f"All {total} matches have been processed and saved!"),
                    ("", "\n\n"),
                    ("class:instruction", "Press 'q' to exit"),
                ]

            category, match, image, reference_url, namespace, fixed_version, result_id = current_match
            category_display = {
                "candidate_only": "CANDIDATE ONLY",
                "reference_only": "REFERENCE ONLY",
                "unlabeled_both": "UNLABELED (BOTH SCANS)",
                "common_unlabeled": "COMMON (UNLABELED)",
                "common_unclear": "COMMON (HAS UNCLEAR LABELS)",
                "common_mixed": "COMMON (MIXED LABELS)",
            }.get(category, category.upper())

            # Use the specific reference URL from the delta, or fallback to generic URL
            vuln_url = reference_url or get_vulnerability_info_url(match)

            # Create progress bar
            progress_width = 40
            completed = current_idx
            progress_ratio = completed / total if total > 0 else 0
            filled_width = int(progress_ratio * progress_width)
            empty_width = progress_width - filled_width
            progress_bar = "█" * filled_width + "░" * empty_width

            # Get labels needed for current image to show progress towards gate pass
            labels_needed = self.controller.get_labels_needed_for_current_image()

            display_items = [
                ("class:title", f"Interactive Relabeling Mode ({current_idx + 1}/{total})"),
                ("", "\n"),
                ("class:field", "Progress: "),
                ("class:progress_filled", progress_bar[:filled_width]),
                ("class:progress_empty", progress_bar[filled_width:]),
                ("", f" {completed}/{total} ({int(progress_ratio * 100)}%)"),
                ("", "\n"),
            ]

            # Add labels needed info on its own line if available
            if labels_needed is not None:
                if labels_needed == 0:
                    display_items.extend(
                        [
                            ("class:success", "✓ This image will pass quality gate"),
                            ("", "\n"),
                        ]
                    )
                else:
                    display_items.extend(
                        [
                            ("", "Need "),
                            ("class:highlight", str(labels_needed)),
                            ("", f" more label{'s' if labels_needed != 1 else ''} for this image to pass quality gate"),
                            ("", "\n"),
                        ]
                    )

            display_items.extend(
                [
                    ("", "\n"),
                    ("class:category", f"Category: {category_display}"),
                    ("", "\n"),
                    ("class:field", "Image: "),
                    ("", image),
                    ("", "\n"),
                ]
            )

            display_items.extend(
                [
                    ("class:field", "Result ID: "),
                    ("", result_id or "unknown"),
                    ("", "\n"),
                    ("class:field", "Package: "),
                    ("", f"{match.package.name}@{match.package.version}"),
                    ("", "\n"),
                    ("class:field", "Vulnerability: "),
                    ("", match.vulnerability.id),
                    ("", "\n"),
                ]
            )

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

            # For common matches with existing labels, show what labels already exist
            if category.startswith("common_") and category != "common_unlabeled":
                from yardstick.label import find_labels_for_match

                existing_labels = find_labels_for_match(
                    image=image, match=match, label_entries=self.controller.label_entries, lineage=[], fuzzy_package_match=False
                )

                if existing_labels:
                    label_counts = {}
                    for label in existing_labels:
                        label_counts[label.label] = label_counts.get(label.label, 0) + 1

                    label_summary = ", ".join([f"{count} {label.value}" for label, count in label_counts.items()])
                    display_items.extend(
                        [
                            ("class:field", "Existing Labels: "),
                            ("class:highlight", label_summary),
                            ("", "\n"),
                        ]
                    )

                    # Show detailed label information with UUIDs for inspection
                    display_items.extend(
                        [
                            ("class:field", "Label Details:"),
                            ("", "\n"),
                        ]
                    )

                    for i, label in enumerate(existing_labels, 1):
                        user_info = f" by {label.user}" if label.user else ""
                        time_info = f" at {label.timestamp.strftime('%Y-%m-%d %H:%M')}" if label.timestamp else ""
                        display_items.extend(
                            [
                                ("", f"  {i}. "),
                                ("class:highlight", label.label.value),
                                ("", user_info),
                                ("", time_info),
                                ("", "\n"),
                                ("", "     UUID: "),
                                ("class:uuid", label.ID),
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
                    else "by both tools but is unlabeled"
                    if category == "common_unlabeled"
                    else "by both tools but has unclear labels that need resolution"
                    if category == "common_unclear"
                    else "by both tools but has conflicting labels that need resolution"
                    if category == "common_mixed"
                    else "by both tools but needs labeling",
                ),
                ("class:description", ". Please provide a definitive label to resolve the quality gate failure."),
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
                ("", " - Skip to next image  "),
                ("class:key", "Q"),
                ("", " - Quit"),
            ]

        def get_match_details_text():
            current_match = self.controller.get_current_match()
            if not current_match:
                return [("", "")]

            _, match, _, _, _, _, _ = current_match

            details_header = [
                ("class:match_detail_title", "Match Details"),
                ("", "\n"),
                ("", "─" * 40),
                ("", "\n\n"),
            ]

            match_details = format_match_details(match)
            return details_header + match_details

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
            def skip_to_next_image(event):
                if self.controller.skip_to_next_image():
                    event.app.invalidate()
                else:
                    # No next image available, could show a message or just do nothing
                    pass

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
                    "progress_filled": "fg:ansigreen",
                    "progress_empty": "fg:ansigray",
                    "match_detail_title": "bold underline fg:ansicyan",
                    "match_detail_header": "bold fg:ansiyellow",
                    "uuid": "fg:ansigray",
                }
            )

        layout = Layout(
            VSplit(
                [
                    Window(
                        content=FormattedTextControl(get_main_text),
                        width=Dimension(preferred=80),
                    ),
                    Window(
                        content=FormattedTextControl(get_match_details_text),
                        width=Dimension(preferred=60),
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
