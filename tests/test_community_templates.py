"""Schema and OpSec validation for GitHub issue and pull request templates (Spec 013)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
GITHUB_DIR = ROOT / ".github"
ISSUE_DIR = GITHUB_DIR / "ISSUE_TEMPLATE"
REPO_URL_PREFIX = "https://github.com/TulparLemon/Malaz/"

REQUIRED_FILES = (
    ISSUE_DIR / "config.yml",
    ISSUE_DIR / "bug_report.yml",
    ISSUE_DIR / "false_positive.yml",
    ISSUE_DIR / "feature_request.yml",
    GITHUB_DIR / "PULL_REQUEST_TEMPLATE.md",
)


def test_all_required_community_templates_exist() -> None:
    missing = [str(p.relative_to(ROOT)) for p in REQUIRED_FILES if not p.is_file()]
    assert missing == []


def test_issue_config_redirects_security_and_forbids_blank_issues() -> None:
    data = yaml.safe_load((ISSUE_DIR / "config.yml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert data.get("blank_issues_enabled") is False

    links = data.get("contact_links")
    assert isinstance(links, list) and len(links) >= 2
    urls: list[str] = []
    for entry in links:
        assert isinstance(entry, dict)
        for field in ("name", "url", "about"):
            val = entry.get(field)
            assert isinstance(val, str) and val.strip(), f"missing {field} in {entry}"
        assert entry["url"].startswith(REPO_URL_PREFIX), entry["url"]
        urls.append(entry["url"])

    assert any(u.endswith("/SECURITY.md") for u in urls), urls
    assert any(u.endswith("/docs/USAGE.md") for u in urls), urls


@pytest.mark.parametrize(
    ("filename", "expected_keywords"),
    [
        ("bug_report.yml", ("confidential", "malware")),
        ("false_positive.yml", ("confidential", "malware")),
        ("feature_request.yml", ("offline", "gpl-3.0-or-later")),
    ],
)
def test_issue_forms_follow_github_schema_and_checkbox_rules(
    filename: str, expected_keywords: tuple[str, ...]
) -> None:
    data = yaml.safe_load((ISSUE_DIR / filename).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    for field in ("name", "description", "title", "body"):
        assert data.get(field), f"{filename}: missing {field}"
    assert isinstance(data["body"], list) and data["body"]

    required_checkbox_labels: list[str] = []
    for item in data["body"]:
        assert isinstance(item, dict)
        if item.get("type") == "checkboxes":
            # GitHub Issue Forms reject 'validations' on checkboxes; required goes per option.
            assert "validations" not in item, (
                f"{filename}: type=checkboxes must not define 'validations'"
            )
            options = item.get("attributes", {}).get("options", [])
            assert isinstance(options, list) and options
            for opt in options:
                if opt.get("required") is True:
                    required_checkbox_labels.append(str(opt.get("label", "")).lower())

    assert required_checkbox_labels, f"{filename}: missing required checkbox option"
    combined = " ".join(required_checkbox_labels)
    for kw in expected_keywords:
        assert kw in combined, f"{filename}: expected '{kw}' in required checkbox: {combined}"


def test_pull_request_template_uses_canonical_github_urls_and_gates() -> None:
    text = (GITHUB_DIR / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    assert "GPL-3.0-or-later" in text
    assert "arch_gate.py" in text
    assert "check_doc_claims.py" in text

    md_links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", text)
    assert md_links, "PR template should link core repository docs"
    for target in md_links:
        assert target.startswith(REPO_URL_PREFIX), (
            f"PR template link must be canonical GitHub HTTPS URL, got: {target}"
        )
