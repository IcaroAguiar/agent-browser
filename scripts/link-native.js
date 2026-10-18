/**
 * Points package-manager bin entries for agent-browser at the native binary,
 * so later invocations skip the Node.js launcher entirely.
 *
 * Run by postinstall when install scripts are allowed, and by the launcher on
 * its first invocation when they are not (npm 12, pnpm and bun block
 * dependency install scripts by default). Every step is best effort, and an
 * entry is only rewritten when it provably targets this package's launcher.
 */

import {
  chmodSync,
  copyFileSync,
  existsSync,
  linkSync,
  lstatSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'fs';
import { basename, dirname, join, resolve } from 'path';
import { platform } from 'os';

/**
 * Ensures the binary lives in this package's own bin/ directory and returns
 * that path. Bin entries must target files inside the package that owns them:
 * npm only removes such links on uninstall, and bun refuses to replace a
 * global bin entry that points into another package.
 */
export function materializeBinary(packageRoot, binary, target) {
  const binDir = join(packageRoot, 'bin');
  if (dirname(resolve(binary)) === resolve(binDir)) return binary;

  const destination = join(binDir, target.binaryName);
  const staged = `${destination}.install-${process.pid}`;
  try {
    try {
      linkSync(binary, staged);
    } catch {
      copyFileSync(binary, staged);
    }
    if (platform() !== 'win32') chmodSync(staged, 0o755);
    renameSync(staged, destination);
  } finally {
    rmSync(staged, { force: true });
  }
  return destination;
}

function isLauncherSymlink(entry, launcher) {
  try {
    return lstatSync(entry).isSymbolicLink() && realpathSync(entry) === realpathSync(launcher);
  } catch {
    return false;
  }
}

// npm, yarn and bun link bin entries as symlinks on macOS and Linux.
function relinkSymlink(entry, binary) {
  const staged = join(dirname(entry), `.${basename(entry)}-${process.pid}`);
  try {
    symlinkSync(binary, staged);
    renameSync(staged, entry);
    return true;
  } catch {
    rmSync(staged, { force: true });
    return false;
  }
}

function shellQuote(value) {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * pnpm writes a shell shim that runs `node <launcher>`, named in a
 * `# cmd-shim-target=` comment. The comment is kept so pnpm still recognizes
 * the shim as its own when it updates or removes the package.
 */
export function pnpmShimPaths(invokedPath) {
  const match = invokedPath.match(
    /^(.*)[\\/]global[\\/][^\\/]+[\\/](?:[^\\/]+[\\/])?node_modules[\\/]agent-browser[\\/]bin[\\/]agent-browser\.js$/,
  );
  if (!match) return [];
  return [join(match[1], 'bin', 'agent-browser'), join(match[1], 'agent-browser')];
}

function relinkPnpmShim(shim, invokedPath, binary) {
  let content;
  try {
    content = readFileSync(shim, 'utf8');
  } catch {
    return false;
  }
  const marker = `# cmd-shim-target=${invokedPath}`;
  if (!content.split('\n').includes(marker)) return false;

  const staged = `${shim}.install-${process.pid}`;
  try {
    writeFileSync(staged, `#!/bin/sh\n${marker}\nexec ${shellQuote(binary)} "$@"\n`, { mode: 0o755 });
    renameSync(staged, shim);
    return true;
  } catch {
    rmSync(staged, { force: true });
    return false;
  }
}

/**
 * npm on Windows generates .cmd/.ps1 shims that run node on the launcher.
 * They live in the global prefix, next to node_modules\agent-browser.
 */
function relinkWindowsShims(packageRoot, linked) {
  const nodeModules = dirname(packageRoot);
  if (basename(packageRoot) !== 'agent-browser' || basename(nodeModules) !== 'node_modules') return false;
  const prefix = dirname(nodeModules);
  const cmdShim = join(prefix, 'agent-browser.cmd');
  const ps1Shim = join(prefix, 'agent-browser.ps1');

  let content;
  try {
    content = readFileSync(cmdShim, 'utf8');
  } catch {
    return false;
  }
  if (!content.includes('node_modules\\agent-browser\\bin\\agent-browser.js')) return false;

  try {
    const relativeBinaryPath = `node_modules\\agent-browser\\bin\\${basename(linked())}`;
    writeFileSync(cmdShim, `@ECHO off\r\n"%~dp0${relativeBinaryPath}" %*\r\n`);
    if (existsSync(ps1Shim)) {
      writeFileSync(
        ps1Shim,
        `#!/usr/bin/env pwsh\r\n$basedir = Split-Path $MyInvocation.MyCommand.Definition -Parent\r\n& "$basedir\\${relativeBinaryPath}" $args\r\nexit $LASTEXITCODE\r\n`,
      );
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Rewrites every bin entry that runs the launcher so it runs `binary`.
 *
 * - packageRoot: this package's directory (real path)
 * - binary: the native binary found by findNativeBinary
 * - target: the nativeTarget for this host
 * - entries: paths that may be symlinks to the launcher (e.g. process.argv[1])
 *
 * Returns true when at least one entry now runs the native binary.
 */
export function linkNative({ packageRoot, binary, target, entries = [] }) {
  const launcher = join(packageRoot, 'bin', 'agent-browser.js');
  const linked = () => materializeBinary(packageRoot, binary, target);

  if (platform() === 'win32') {
    return relinkWindowsShims(packageRoot, linked);
  }

  let changed = false;
  for (const entry of entries) {
    if (isLauncherSymlink(entry, launcher)) {
      try {
        changed = relinkSymlink(entry, linked()) || changed;
      } catch {
        // Read-only or root-owned install: keep using the launcher.
      }
    }
    // pnpm's store is shared between projects, so the shim runs the binary
    // where the platform package installed it instead of copying it.
    for (const shim of pnpmShimPaths(entry)) {
      changed = relinkPnpmShim(shim, entry, realpathSafe(binary)) || changed;
    }
  }
  return changed;
}

function realpathSafe(path) {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}
