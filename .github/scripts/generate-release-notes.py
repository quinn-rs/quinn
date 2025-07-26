#!/usr/bin/env python3
"""
Generate release notes from template and changelog.
"""

import re
import sys
import subprocess
from datetime import datetime


def get_contributors(from_tag, to_tag):
    """Get list of contributors between two tags."""
    try:
        # Get unique contributors
        result = subprocess.run(
            ["git", "shortlog", "-sn", f"{from_tag}..{to_tag}"],
            capture_output=True,
            text=True,
            check=True
        )
        
        contributors = []
        for line in result.stdout.strip().split('\n'):
            if line:
                # Extract contributor name (skip the commit count)
                parts = line.strip().split('\t', 1)
                if len(parts) > 1:
                    contributors.append(f"- {parts[1]}")
        
        return '\n'.join(contributors) if contributors else "- No new contributors in this release"
    except:
        return "- Contributors list unavailable"


def get_previous_tag(current_tag):
    """Get the previous release tag."""
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0", f"{current_tag}^"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except:
        return None


def generate_release_notes(version, changelog, template_file):
    """Generate release notes from template."""
    # Read template
    with open(template_file, 'r') as f:
        template = f.read()
    
    # Extract version number without 'v'
    version_number = version.lstrip('v')
    
    # Get previous tag
    previous_tag = get_previous_tag(version)
    if not previous_tag:
        previous_tag = "BEGINNING"
    
    # Get contributors
    contributors = get_contributors(previous_tag, version)
    
    # Check for breaking changes
    breaking_changes_warning = ""
    if "BREAKING" in changelog or "⚠" in changelog:
        breaking_changes_warning = "⚠️ **This release contains breaking changes!**\n\n"
    
    # Replace placeholders
    release_notes = template
    release_notes = release_notes.replace("{{ VERSION }}", version)
    release_notes = release_notes.replace("{{ VERSION_NUMBER }}", version_number)
    release_notes = release_notes.replace("{{ BREAKING_CHANGES_WARNING }}", breaking_changes_warning)
    release_notes = release_notes.replace("{{ CHANGELOG }}", changelog)
    release_notes = release_notes.replace("{{ CONTRIBUTORS }}", contributors)
    release_notes = release_notes.replace("{{ PREVIOUS_TAG }}", previous_tag)
    
    # Clean up any remaining placeholders
    release_notes = re.sub(r'\{\{[^}]+\}\}', '', release_notes)
    
    return release_notes


def main():
    if len(sys.argv) != 4:
        print("Usage: generate-release-notes.py <version> <changelog-file> <template-file>")
        sys.exit(1)
    
    version = sys.argv[1]
    changelog_file = sys.argv[2]
    template_file = sys.argv[3]
    
    # Read changelog
    with open(changelog_file, 'r') as f:
        changelog = f.read()
    
    # Generate release notes
    release_notes = generate_release_notes(version, changelog, template_file)
    
    # Output to stdout
    print(release_notes)


if __name__ == "__main__":
    main()