import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity

RULE_FAKE_RELEASE = "README_FAKE_RELEASE_LINK"
RULE_INSTALLER_NON_RELEASE = "README_INSTALLER_FROM_NON_RELEASE_HOST"
RULE_RAW_SOURCE_ARCHIVE = "README_RAW_SOURCE_ARCHIVE_DOWNLOAD"
RULE_DEFEAT_SECURITY = "README_DEFEAT_SECURITY_WARNING"

README_RULE_IDS = (
    RULE_FAKE_RELEASE,
    RULE_INSTALLER_NON_RELEASE,
    RULE_RAW_SOURCE_ARCHIVE,
    RULE_DEFEAT_SECURITY,
)

_BADGE_LINK_RE = re.compile(r"\[!\[([^\]]+)\]\([^)]+\)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", re.I)
_MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", re.I)
_RAW_URL_RE = re.compile(r"https?://[^\s<>)\"']+", re.I)
_DOC_FILENAMES = {"README.md", "README", "index.html"}
_DOC_SUFFIXES = {".md", ".markdown", ".html", ".htm"}
_CONTEXT_WORD_RE = re.compile(r"\b(releases?|downloads?|install(?:er|ation)?|setup|binary|binaries)\b", re.I)
_INSTALLER_WORD_RE = re.compile(r"\b(installer|setup|binary|binaries|\.exe|\.msi)\b", re.I)
_RISKY_PAYLOAD_RE = re.compile(r"\.(exe|msi|zip|7z|rar|ps1|bat|cmd|vbs|scr)(?:[?#].*)?$", re.I)
_RAW_SOURCE_RE = re.compile(
    r"^https?://(?:raw\.githubusercontent\.com/[^/]+/[^/]+/|github\.com/[^/]+/[^/]+/(?:raw|blob)/)",
    re.I,
)


@dataclass(frozen=True)
class _Link:
    label: str
    url: str
    context: str


class ReadmeLinkPoisoningRule:
    rule_ids = README_RULE_IDS

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        if not _is_documentation_path(relative_path):
            return []
        current_slug = _github_origin_slug(root)
        findings: list[Finding] = []
        seen: set[str] = set()
        for link in _extract_links(text):
            self._append_link_findings(findings, seen, text, link, current_slug)
        self._append_security_warning_finding(findings, seen, text, relative_path)
        return [
            Finding(
                rule_id=finding.rule_id,
                severity=finding.severity,
                title=finding.title,
                file=relative_path.as_posix(),
                line=finding.line,
                evidence=finding.evidence,
                why_it_matters=finding.why_it_matters,
                recommendation=finding.recommendation,
            )
            for finding in findings
        ]

    def _append_link_findings(
        self,
        findings: list[Finding],
        seen: set[str],
        text: str,
        link: _Link,
        current_slug: str | None,
    ) -> None:
        context = f"{link.label} {link.context}"
        has_release_context = bool(_CONTEXT_WORD_RE.search(context))
        has_installer_context = bool(_INSTALLER_WORD_RE.search(context))
        raw_source = _is_raw_source_url(link.url)
        release_page = _is_expected_release_page(link.url, current_slug)
        release_asset = _is_expected_release_asset(link.url, current_slug)
        risky_payload = _has_risky_payload_extension(link.url)

        if has_release_context and not raw_source and not release_page:
            _append_once(
                findings,
                seen,
                _link_finding(
                    RULE_FAKE_RELEASE,
                    "Suspicious README release or download link",
                    text,
                    link,
                    _link_evidence(link),
                    "Release or download wording points away from the expected GitHub Releases page.",
                    "Verify the release/download target before trusting repository documentation.",
                ),
            )

        if (has_installer_context or risky_payload and has_release_context and not raw_source) and not release_asset:
            _append_once(
                findings,
                seen,
                _link_finding(
                    RULE_INSTALLER_NON_RELEASE,
                    "Installer or download target is not a release asset",
                    text,
                    link,
                    _link_evidence(link),
                    "Installer/download wording points to a target that is not shaped like a GitHub Releases asset.",
                    "Prefer repository release assets and inspect documentation-controlled links manually.",
                ),
            )

        if raw_source and (has_release_context or risky_payload):
            _append_once(
                findings,
                seen,
                _link_finding(
                    RULE_RAW_SOURCE_ARCHIVE,
                    "README download points to a raw source URL",
                    text,
                    link,
                    f"raw archive -> {_short_url(link.url)}",
                    "Raw source URLs can bypass release-asset review and confuse users about provenance.",
                    "Treat raw source download links as untrusted and prefer verified release assets.",
                ),
            )

    def _append_security_warning_finding(
        self,
        findings: list[Finding],
        seen: set[str],
        text: str,
        relative_path: Path,
    ) -> None:
        phrase = _security_warning_phrase(text)
        if phrase is None:
            return
        _append_once(
            findings,
            seen,
            Finding(
                rule_id=RULE_DEFEAT_SECURITY,
                severity=Severity.MEDIUM,
                title="README asks users to bypass security warnings",
                file=relative_path.as_posix(),
                line=line_number(text, phrase.split(" ... ")[0]),
                evidence=f"security warning bypass phrase: {phrase}",
                why_it_matters=(
                    "Repository documentation that encourages bypassing OS, browser, antivirus, Defender, "
                    "or SmartScreen warnings can be social engineering."
                ),
                recommendation="Do not follow bypass instructions without independent user review.",
            ),
        )


def _is_documentation_path(relative_path: Path) -> bool:
    normalized = relative_path.as_posix()
    return (
        relative_path.name in _DOC_FILENAMES
        or relative_path.suffix.lower() in _DOC_SUFFIXES
        and (normalized.startswith("docs/") or normalized.startswith("documentation/"))
    )


def _extract_links(text: str) -> list[_Link]:
    links: list[_Link] = []
    for match in _BADGE_LINK_RE.finditer(text):
        links.append(_Link(match.group(1), _clean_url(match.group(2)), _line_context(text, match.start())))
    for match in _MARKDOWN_LINK_RE.finditer(text):
        links.append(_Link(match.group(1), _clean_url(match.group(2)), _line_context(text, match.start())))
    for match in _RAW_URL_RE.finditer(text):
        url = _clean_url(match.group(0))
        if not any(link.url == url for link in links):
            links.append(_Link(url, url, _line_context(text, match.start())))
    return links


def _line_context(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    return " ".join(text[start:end].split())


def _clean_url(url: str) -> str:
    return url.strip().rstrip(".,;:")


def _github_origin_slug(root: Path) -> str | None:
    config = root / ".git" / "config"
    if not config.is_file():
        return None
    text = config.read_text(encoding="utf-8", errors="ignore")
    match = re.search(
        r"url\s*=\s*(?:https://github\.com/|git@github\.com:)([^/\s]+/[^/\s]+?)(?:\.git)?\s*$",
        text,
        re.M,
    )
    if not match:
        return None
    return match.group(1).lower()


def _is_expected_release_page(url: str, current_slug: str | None) -> bool:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return False
    path = parsed.path.strip("/").lower()
    parts = path.split("/")
    if len(parts) < 3 or parts[2] != "releases":
        return False
    slug = f"{parts[0]}/{parts[1]}"
    return current_slug is None or slug == current_slug


def _is_expected_release_asset(url: str, current_slug: str | None) -> bool:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return False
    path = parsed.path.strip("/").lower()
    parts = path.split("/")
    if len(parts) < 5 or parts[2:4] != ["releases", "download"]:
        return False
    slug = f"{parts[0]}/{parts[1]}"
    return current_slug is None or slug == current_slug


def _is_raw_source_url(url: str) -> bool:
    return bool(_RAW_SOURCE_RE.search(url))


def _has_risky_payload_extension(url: str) -> bool:
    return bool(_RISKY_PAYLOAD_RE.search(urlparse(url).path))


def _link_finding(
    rule_id: str,
    title: str,
    text: str,
    link: _Link,
    evidence: str,
    why_it_matters: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.MEDIUM,
        title=title,
        file="",
        line=line_number(text, link.url),
        evidence=evidence,
        why_it_matters=why_it_matters,
        recommendation=recommendation,
    )


def _link_evidence(link: _Link) -> str:
    label = " ".join(link.label.split())
    if len(label) > 80:
        label = f"{label[:77]}..."
    return f"{label} -> {_short_url(link.url)}"


def _short_url(url: str) -> str:
    return url if len(url) <= 160 else f"{url[:157]}..."


def _security_warning_phrase(text: str) -> str | None:
    lowered = text.lower()
    phrase_pairs = (
        ("more info", "run anyway"),
        ("windows defender", "run anyway"),
        ("smartscreen", "run anyway"),
        ("defender", "bypass"),
        ("defender", "ignore"),
        ("defender", "allow"),
        ("unblock", "installer"),
        ("unblock", "downloaded"),
        ("trusted file", "installer"),
        ("disable antivirus", "install"),
        ("disable real-time protection", "install"),
    )
    for first, second in phrase_pairs:
        first_index = lowered.find(first)
        second_index = lowered.find(second)
        if first_index >= 0 and second_index >= 0 and abs(first_index - second_index) <= 240:
            return f"{first} ... {second}"
    return None


def _append_once(findings: list[Finding], seen: set[str], finding: Finding) -> None:
    if finding.rule_id in seen:
        return
    seen.add(finding.rule_id)
    findings.append(finding)
