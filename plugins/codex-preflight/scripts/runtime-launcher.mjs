import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const RUNTIME_SCHEMA = "codex-preflight-runtime/v1";
const DEV_RUNTIME_FLAG = "CODEX_PREFLIGHT_ALLOW_DEV_RUNTIME";
const DEV_PYTHON = "CODEX_PREFLIGHT_DEV_PYTHON";

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`${label} is missing or invalid: ${error.message}`);
  }
}

function runtimeKey() {
  const platforms = {
    win32: "windows",
    linux: "linux",
    darwin: "macos",
  };
  const architectures = {
    x64: "x64",
    arm64: "arm64",
  };
  const platform = platforms[process.platform];
  const architecture = architectures[process.arch];
  return platform && architecture ? `${platform}-${architecture}` : null;
}

function pluginRoot(importMetaUrl) {
  return dirname(dirname(fileURLToPath(importMetaUrl)));
}

function resolveBundledRuntime(root) {
  const key = runtimeKey();
  if (!key) {
    throw new Error(`unsupported host platform: ${process.platform}/${process.arch}`);
  }

  const pluginManifest = readJson(resolve(root, ".codex-plugin", "plugin.json"), "plugin manifest");
  const runtimeRoot = resolve(root, "runtime");
  const runtimeManifest = readJson(
    resolve(runtimeRoot, "runtime-manifest.json"),
    "runtime manifest",
  );

  if (runtimeManifest.schemaVersion !== RUNTIME_SCHEMA) {
    throw new Error("runtime manifest schema is unsupported");
  }
  if (runtimeManifest.pluginVersion !== pluginManifest.version) {
    throw new Error("runtime manifest version does not match the installed plugin");
  }

  const entry = runtimeManifest.runtimes?.[key];
  if (!entry || typeof entry.path !== "string" || typeof entry.sha256 !== "string") {
    throw new Error(`bundled runtime is unavailable for ${key}`);
  }
  if (!/^[0-9a-f]{64}$/u.test(entry.sha256)) {
    throw new Error(`bundled runtime digest is invalid for ${key}`);
  }

  const executable = resolve(runtimeRoot, entry.path);
  const rel = relative(runtimeRoot, executable);
  if (!rel || rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`bundled runtime path escapes the plugin for ${key}`);
  }
  if (!existsSync(executable)) {
    throw new Error(`bundled runtime executable is missing for ${key}`);
  }

  const digest = createHash("sha256").update(readFileSync(executable)).digest("hex");
  if (digest !== entry.sha256) {
    throw new Error(`bundled runtime digest mismatch for ${key}`);
  }
  return executable;
}

function launch(command, args) {
  const child = spawn(command, args, {
    cwd: process.cwd(),
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
  });
  child.on("error", (error) => {
    process.stderr.write(`Codex Preflight runtime failed to start: ${error.message}\n`);
    process.exit(1);
  });
  child.on("exit", (code) => {
    process.exit(code ?? 1);
  });
}

export function launchRole(role, args, importMetaUrl) {
  if (!new Set(["mcp", "hook"]).has(role)) {
    process.stderr.write(`Codex Preflight runtime role is invalid: ${role}\n`);
    process.exit(1);
  }

  const root = pluginRoot(importMetaUrl);
  try {
    launch(resolveBundledRuntime(root), [role, ...args]);
    return;
  } catch (error) {
    const devAllowed = process.env[DEV_RUNTIME_FLAG] === "1";
    const devPython = process.env[DEV_PYTHON];
    if (devAllowed && devPython) {
      const moduleName = role === "mcp" ? "codex_preflight_mcp.server" : "codex_preflight_guardian.pre_tool_use";
      launch(devPython, ["-m", moduleName, ...args]);
      return;
    }
    process.stderr.write(
      `Codex Preflight could not start its bundled ${role} runtime: ${error.message}. ` +
        "Reinstall a complete plugin package for this platform.\n",
    );
    process.exit(1);
  }
}
