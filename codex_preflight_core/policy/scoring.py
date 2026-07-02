from codex_preflight_core.scanner.finding import Severity

SEVERITY_SCORES = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
