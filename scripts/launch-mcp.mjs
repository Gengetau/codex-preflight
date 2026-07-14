import { existsSync, readFileSync, readdirSync } from "node:fs";
import { delimiter, join } from "node:path";
import { spawn, spawnSync } from "node:child_process";

const PYTHON_OVERRIDE = "CODEX_PREFLIGHT_PYTHON";

function expectedPackageVersion() {
  try {
    const manifestPath = join(process.cwd(), ".codex-plugin", "plugin.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (typeof manifest.version !== "string" || manifest.version.length === 0) {
      return null;
    }
    return manifest.version.split("+codex.", 1)[0];
  } catch {
    return null;
  }
}

function addCandidate(candidates, command, prefix = []) {
  if (!command) {
    return;
  }
  const key = [command, ...prefix].join("\0");
  if (!candidates.some((candidate) => candidate.key === key)) {
    candidates.push({ command, prefix, key });
  }
}

function addWindowsInstallCandidates(candidates, root, relativeParent) {
  if (!root) {
    return;
  }
  const parent = join(root, ...relativeParent);
  if (!existsSync(parent)) {
    return;
  }
  for (const entry of readdirSync(parent, { withFileTypes: true })) {
    if (!entry.isDirectory()) {
      continue;
    }
    const executable = join(parent, entry.name, "python.exe");
    if (existsSync(executable)) {
      addCandidate(candidates, executable);
    }
  }
}

function pythonCandidates() {
  const override = process.env[PYTHON_OVERRIDE];
  if (override) {
    return [{ command: override, prefix: [], key: override }];
  }

  const candidates = [];
  if (process.platform === "win32") {
    addCandidate(candidates, "py", ["-3"]);
    addCandidate(candidates, "python");
    addCandidate(candidates, "python3");
    addWindowsInstallCandidates(candidates, process.env.LOCALAPPDATA, ["Programs", "Python"]);
    addWindowsInstallCandidates(candidates, process.env.LOCALAPPDATA, ["Python"]);
  } else {
    addCandidate(candidates, "python3");
    addCandidate(candidates, "python");
  }

  for (const directory of (process.env.PATH ?? "").split(delimiter)) {
    if (!directory) {
      continue;
    }
    const executable = join(directory, process.platform === "win32" ? "python.exe" : "python3");
    if (existsSync(executable)) {
      addCandidate(candidates, executable);
    }
  }
  return candidates;
}

function resolvePython(expectedVersion) {
  const probe =
    "from importlib.metadata import version; import codex_preflight_mcp; import mcp; " +
    `raise SystemExit(0 if version('codex-preflight') == ${JSON.stringify(expectedVersion)} else 1)`;
  for (const candidate of pythonCandidates()) {
    const result = spawnSync(candidate.command, [...candidate.prefix, "-c", probe], {
      env: process.env,
      stdio: "ignore",
      timeout: 5000,
      windowsHide: true,
    });
    if (result.status === 0) {
      return candidate;
    }
  }
  return null;
}

const expectedVersion = expectedPackageVersion();
if (!expectedVersion) {
  process.stderr.write("Codex Preflight MCP could not read the plugin manifest version.\n");
  process.exit(1);
}

const python = resolvePython(expectedVersion);
if (!python) {
  process.stderr.write(
    `Codex Preflight MCP could not find Python with codex-preflight[mcp]==${expectedVersion}.\n` +
      'Install it with `python -m pip install "codex-preflight[mcp]"`, or set ' +
      `${PYTHON_OVERRIDE} to that Python executable.\n`,
  );
  process.exit(1);
}

const child = spawn(
  python.command,
  [...python.prefix, "-m", "codex_preflight_mcp.server", ...process.argv.slice(2)],
  {
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
  },
);

child.on("error", (error) => {
  process.stderr.write(`Codex Preflight MCP failed to start: ${error.message}\n`);
  process.exit(1);
});

child.on("exit", (code) => {
  process.exit(code ?? 1);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    if (!child.killed) {
      child.kill(signal);
    }
  });
}
