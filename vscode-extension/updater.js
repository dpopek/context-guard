"use strict";

const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { isValidSemver, escapeMarkdownCodeSpan } = require("./view_model");

const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const UPDATE_RETRY_BACKOFF_MS = 60 * 60 * 1000;
const UPDATE_STEP_TIMEOUT_MS = 120000;
const STDERR_TAIL_CHARS = 500;

function resolvePluginRoot(env = process.env, extDir = __dirname, homeDir = os.homedir()) {
  const effectiveHome = typeof homeDir === "string" && homeDir ? homeDir : os.homedir();
  if (env && typeof env.CONTEXT_GUARD_HOME === "string") {
    const rawEnv = env.CONTEXT_GUARD_HOME.trim();
    if (rawEnv) {
      if (rawEnv === "~") return path.resolve(effectiveHome);
      if (rawEnv.startsWith("~/") || rawEnv.startsWith("~\\")) {
        return path.resolve(effectiveHome, rawEnv.slice(2));
      }
      return path.resolve(rawEnv);
    }
  }
  if (typeof extDir === "string" && extDir) {
    try {
      const breadcrumbPath = path.join(extDir, "plugin_root.json");
      if (fs.existsSync(breadcrumbPath)) {
        const parsed = JSON.parse(fs.readFileSync(breadcrumbPath, "utf8"));
        if (parsed && typeof parsed.plugin_root === "string" && parsed.plugin_root.trim()) {
          return path.resolve(parsed.plugin_root.trim());
        }
      }
    } catch (_err) {
      // Fail open on missing, unreadable, or malformed plugin_root.json.
    }
    try {
      const parentDir = path.resolve(extDir, "..");
      if (
        fs.existsSync(path.join(parentDir, "plugin.json")) &&
        fs.existsSync(path.join(parentDir, "hooks", "pre_tool_use.py"))
      ) {
        return parentDir;
      }
    } catch (_err) {
      // Ignore filesystem probe errors and fall through to home fallback.
    }
  }
  return path.join(effectiveHome, ".gemini", "config", "plugins", "context-guard");
}

function updateBadge(update) {
  const state = update && update.state;
  if (
    state === "update_available" &&
    isValidSemver(update.latest) &&
    (!update.local || isValidSemver(update.local))
  ) {
    return {
      prefix: "$(cloud-download) ",
      tooltipLine: `$(cloud-download) **Update available:** \`${escapeMarkdownCodeSpan(update.local || "?")}\` → \`${escapeMarkdownCodeSpan(update.latest)}\` &nbsp; [Update](command:contextGuard.update)`,
    };
  }
  if (
    state === "install_pending" &&
    (!update.local || isValidSemver(update.local)) &&
    (!update.installed || update.installed === "none" || isValidSemver(update.installed))
  ) {
    return {
      prefix: "$(cloud-download) ",
      tooltipLine: `$(cloud-download) **Installer not run** for \`${escapeMarkdownCodeSpan(update.local || "?")}\` (installed: \`${escapeMarkdownCodeSpan(update.installed || "none")}\`) &nbsp; [Run installer](command:contextGuard.update)`,
    };
  }
  return { prefix: "", tooltipLine: "" };
}

function updateNotice(update) {
  const state = update && update.state;
  if (
    state === "update_available" &&
    isValidSemver(update.latest) &&
    (!update.local || isValidSemver(update.local))
  ) {
    return {
      key: `contextGuard.notified.update.${update.latest}`,
      message: `Context-Guard ${update.latest} is available (you have ${update.local || "an older version"}).`,
      button: "Update",
    };
  }
  if (state === "install_pending" && isValidSemver(update.local)) {
    return {
      key: `contextGuard.notified.install.${update.local}`,
      message: `Context-Guard ${update.local} is checked out but the installer has not run for it.`,
      button: "Run installer",
    };
  }
  return null;
}

function pythonCandidates(platform = process.platform, env = process.env) {
  const candidates = [];
  if (env && typeof env.CONTEXT_GUARD_PYTHON === "string" && env.CONTEXT_GUARD_PYTHON.trim()) {
    candidates.push([env.CONTEXT_GUARD_PYTHON.trim(), []]);
  }
  if (platform === "win32") {
    candidates.push(["python", []], ["py", ["-3"]], ["python3", []]);
  } else {
    candidates.push(["python3", []], ["python", []]);
  }
  return candidates;
}

function updateSteps(state, pluginRoot, latest) {
  const rawScript = path.join(pluginRoot, "bin", "install_harnesses.py");
  const scriptPath = typeof pluginRoot === "string" && pluginRoot.startsWith("/") ? rawScript.replace(/\\/g, "/") : rawScript;
  const installer = ["python3", [scriptPath, "--install"]];
  if (state === "update_available") {
    if (!isValidSemver(latest)) return [];
    const tag = `v${latest}`;
    return [
      ["git", ["-C", pluginRoot, "fetch", "origin", "tag", tag, "--no-tags"]],
      ["git", ["-C", pluginRoot, "merge", "--ff-only", tag]],
      installer,
    ];
  }
  if (state === "install_pending") return [installer];
  return [];
}

function isUpdateStale(update, nowMs) {
  const checked = update && typeof update.checked_at === "string" ? Date.parse(update.checked_at) : NaN;
  return !Number.isFinite(checked) || nowMs - checked >= UPDATE_CHECK_INTERVAL_MS;
}

function isUpdateAttemptRecent(lockPath, nowMs = Date.now()) {
  try {
    const stat = fs.statSync(lockPath);
    return Number.isFinite(stat.mtimeMs) && nowMs - stat.mtimeMs < UPDATE_RETRY_BACKOFF_MS;
  } catch (_err) {
    return false;
  }
}

function tailText(text, limit) {
  const trimmed = String(text || "").trim();
  return trimmed.length > limit ? `…${trimmed.slice(-limit)}` : trimmed;
}

function updateStepEnv(baseEnv) {
  const env = baseEnv || {};
  return {
    ...env,
    GIT_TERMINAL_PROMPT: "0",
    GCM_INTERACTIVE: "never",
    GIT_SSH_COMMAND: env.GIT_SSH_COMMAND || "ssh -o BatchMode=yes",
  };
}

function runUpdateStep([command, args]) {
  const options = { timeout: UPDATE_STEP_TIMEOUT_MS, env: updateStepEnv(process.env), windowsHide: true };
  const attempts =
    command === "python3"
      ? pythonCandidates().map(([pyBin, prefixArgs]) => [pyBin, [...prefixArgs, ...args]])
      : [[command, args]];
  return new Promise((resolve, reject) => {
    const tryExec = (idx, lastErrMsg) => {
      if (idx >= attempts.length) {
        reject(new Error(lastErrMsg));
        return;
      }
      const [cmdBin, cmdArgs] = attempts[idx];
      childProcess.execFile(cmdBin, cmdArgs, options, (err, _stdout, stderr) => {
        if (err) {
          const msg = `${cmdBin} ${cmdArgs.join(" ")}: ${tailText(stderr || err.message, STDERR_TAIL_CHARS)}`;
          if (idx + 1 < attempts.length && (err.code === "ENOENT" || err.code === 9009)) {
            tryExec(idx + 1, msg);
          } else {
            reject(new Error(msg));
          }
        } else {
          resolve();
        }
      });
    };
    tryExec(0, `${command} ${args.join(" ")}: failed`);
  });
}

function spawnUpdateCheckIfStale(update, pluginRoot, lockPath) {
  if (!pluginRoot) return;
  const scriptPath = path.join(pluginRoot, "bin", "update_check.py");
  if (!fs.existsSync(scriptPath)) return;
  const nowMs = Date.now();
  if (!isUpdateStale(update, nowMs) || isUpdateAttemptRecent(lockPath, nowMs)) return;
  const cands = pythonCandidates();
  const trySpawn = (idx) => {
    if (idx >= cands.length) return;
    const [pyBin, prefixArgs] = cands[idx];
    const child = childProcess.spawn(pyBin, [...prefixArgs, scriptPath], {
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    });
    let settled = false;
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      if (idx + 1 < cands.length) trySpawn(idx + 1);
      else console.warn(`context-guard: update check not started: ${err}`);
    });
    child.on("exit", (code) => {
      if (settled) return;
      settled = true;
      if (code === 9009 && idx + 1 < cands.length) trySpawn(idx + 1);
    });
    child.unref();
  };
  trySpawn(0);
}

function hasContextGuardHook(configPath) {
  try {
    if (!fs.existsSync(configPath)) return false;
    const parsed = JSON.parse(fs.readFileSync(configPath, "utf8"));
    if (!parsed || typeof parsed !== "object" || !parsed.hooks || typeof parsed.hooks !== "object") return false;
    const serialized = JSON.stringify(parsed.hooks);
    return serialized.includes("/hooks/pre_tool_use.py") || serialized.includes("\\\\hooks\\\\pre_tool_use.py");
  } catch (_err) {
    return false;
  }
}

function isDirWritable(targetPath) {
  try {
    fs.accessSync(targetPath, fs.constants.W_OK);
    return true;
  } catch (_err) {
    return false;
  }
}

function probeDoctor(pluginRoot, homeDir = os.homedir()) {
  const root = typeof pluginRoot === "string" && pluginRoot ? pluginRoot : "";
  const effectiveHome = typeof homeDir === "string" && homeDir ? homeDir : os.homedir();
  let antigravityOk = false;
  let telemetryWritable = false;
  if (root) {
    try {
      antigravityOk =
        fs.existsSync(path.join(root, "plugin.json")) &&
        (fs.existsSync(path.join(root, "hooks.json")) || fs.existsSync(path.join(root, "hooks", "hooks.json")));
      const telemetryDir = path.join(root, "telemetry");
      if (fs.existsSync(telemetryDir)) telemetryWritable = isDirWritable(telemetryDir);
      else if (fs.existsSync(root)) telemetryWritable = isDirWritable(root);
    } catch (_err) {
      antigravityOk = false;
      telemetryWritable = false;
    }
  }
  const harnesses = {
    antigravity: antigravityOk,
    claude: hasContextGuardHook(path.join(effectiveHome, ".claude", "settings.json")),
    cursor: hasContextGuardHook(path.join(effectiveHome, ".cursor", "hooks.json")),
    codex: hasContextGuardHook(path.join(effectiveHome, ".codex", "hooks.json")),
  };
  const registeredCount = Object.values(harnesses).filter(Boolean).length;
  const totalHarnesses = 4;
  return {
    ok: Boolean(antigravityOk && telemetryWritable),
    telemetryWritable,
    harnesses,
    registeredCount,
    totalHarnesses,
  };
}

module.exports = {
  UPDATE_CHECK_INTERVAL_MS,
  UPDATE_RETRY_BACKOFF_MS,
  UPDATE_STEP_TIMEOUT_MS,
  STDERR_TAIL_CHARS,
  resolvePluginRoot,
  updateBadge,
  updateNotice,
  pythonCandidates,
  updateSteps,
  isUpdateStale,
  isUpdateAttemptRecent,
  tailText,
  updateStepEnv,
  runUpdateStep,
  spawnUpdateCheckIfStale,
  probeDoctor,
};
