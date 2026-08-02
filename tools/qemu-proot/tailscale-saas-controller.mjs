#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";

let terminalFailureReported = false;
function reportTerminalFailure() {
  if (terminalFailureReported) return;
  terminalFailureReported = true;
  process.stderr.write("secret-safe provider controller failed\n");
  process.exit(70);
}
process.on("uncaughtException", reportTerminalFailure);
process.on("unhandledRejection", reportTerminalFailure);

const action = process.argv[2];
const credentialPath = fs.realpathSync(process.argv[3] ?? "");
const workspace = fs.realpathSync(process.argv[4] ?? "");

if (!new Set(["prepare", "consume", "discover", "ssh", "cleanup"]).has(action)) {
  throw new Error("expected prepare, consume, discover, ssh, or cleanup");
}
if (
  path.basename(workspace) !== "workspace" ||
  !/^liskov-tailscale-saas\.[A-Za-z0-9]+$/.test(path.basename(path.dirname(workspace))) ||
  path.dirname(path.dirname(workspace)) !== "/tmp"
) {
  throw new Error("unsafe local test workspace path");
}

const credentialDirectory = path.dirname(credentialPath);
if ((fs.statSync(credentialDirectory).mode & 0o777) !== 0o700) {
  throw new Error("unsafe credential directory permissions");
}
if ((fs.statSync(credentialPath).mode & 0o777) !== 0o600) {
  throw new Error("unsafe credential file permissions");
}
if ((fs.statSync(workspace).mode & 0o777) !== 0o700) {
  throw new Error("unsafe local test workspace permissions");
}

const credential = JSON.parse(fs.readFileSync(credentialPath, "utf8"));
if (
  credential.kind !== "tailscale" ||
  typeof credential.tailnet !== "string" ||
  credential.tag !== "tag:liskov-runtime" ||
  typeof credential.oauthClientId !== "string" ||
  typeof credential.oauthClientSecret !== "string"
) {
  throw new Error("invalid local canary credential contract");
}

const statePath = `${workspace}/control-state.json`;
const authKeyPath = `${workspace}/authkey`;
const hostnamePath = `${workspace}/hostname`;

function emit(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function readState() {
  if ((fs.statSync(statePath).mode & 0o777) !== 0o600) {
    throw new Error("unsafe control-state permissions");
  }
  return JSON.parse(fs.readFileSync(statePath, "utf8"));
}

function writeState(state) {
  fs.writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
  fs.chmodSync(statePath, 0o600);
}

async function oauthToken() {
  const form = new URLSearchParams({
    grant_type: "client_credentials",
    scope: "auth_keys devices:core",
  });
  const response = await fetch("https://api.tailscale.com/api/v2/oauth/token", {
    method: "POST",
    headers: {
      authorization:
        "Basic " +
        Buffer.from(
          `${credential.oauthClientId}:${credential.oauthClientSecret}`,
        ).toString("base64"),
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form,
  });
  if (!response.ok) throw new Error(`oauth status ${response.status}`);
  const body = await response.json();
  if (typeof body.access_token !== "string") {
    throw new Error("oauth token missing");
  }
  return body.access_token;
}

function providerBase() {
  return (
    "https://api.tailscale.com/api/v2/tailnet/" +
    encodeURIComponent(credential.tailnet)
  );
}

async function providerRequest(token, requestPath, options = {}) {
  return fetch(requestPath, {
    ...options,
    headers: {
      authorization: `Bearer ${token}`,
      ...(options.body ? { "content-type": "application/json" } : {}),
    },
  });
}

async function listInventory(token) {
  const [keysResponse, devicesResponse] = await Promise.all([
    providerRequest(token, `${providerBase()}/keys`),
    providerRequest(token, `${providerBase()}/devices`),
  ]);
  if (!keysResponse.ok || !devicesResponse.ok) {
    throw new Error(
      `inventory status ${keysResponse.status}/${devicesResponse.status}`,
    );
  }
  const keysBody = await keysResponse.json();
  const devicesBody = await devicesResponse.json();
  return {
    keys: Array.isArray(keysBody) ? keysBody : (keysBody.keys ?? []),
    devices: Array.isArray(devicesBody)
      ? devicesBody
      : (devicesBody.devices ?? []),
  };
}

function localTailnetMatches() {
  const local = JSON.parse(
    execFileSync("tailscale", ["status", "--json"], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    }),
  );
  return (
    local.BackendState === "Running" &&
    local.Self?.Online === true &&
    local.CurrentTailnet?.Name === credential.tailnet
  );
}

function matchingDevices(devices, state) {
  return devices.filter((device) => {
    const names = [device.hostname, device.name, device.dnsName]
      .filter((value) => typeof value === "string")
      .map((value) => value.replace(/\.$/, "").split(".")[0]);
    return (
      names.includes(state.hostname) &&
      Array.isArray(device.tags) &&
      device.tags.includes(credential.tag) &&
      !state.baselineDeviceIds.includes(String(device.id))
    );
  });
}

if (action === "prepare") {
  if (
    fs.existsSync(statePath) ||
    fs.existsSync(authKeyPath) ||
    fs.existsSync(hostnamePath)
  ) {
    throw new Error("local canary state already exists");
  }
  if (!localTailnetMatches()) throw new Error("local client tailnet mismatch");

  const token = await oauthToken();
  const before = await listInventory(token);
  const runtimeHostname = `liskov-prt-${randomBytes(6).toString("hex")}`;
  const requestBody = {
    capabilities: {
      devices: {
        create: {
          reusable: false,
          ephemeral: true,
          preauthorized: true,
          tags: [credential.tag],
        },
      },
    },
    expirySeconds: 900,
    description: "Liskov local QEMU PRoot Runtime SSH canary",
  };
  const response = await providerRequest(token, `${providerBase()}/keys`, {
    method: "POST",
    body: JSON.stringify(requestBody),
  });
  if (!response.ok) throw new Error(`create key status ${response.status}`);
  const created = await response.json();
  if (typeof created.key !== "string" || typeof created.id !== "string") {
    throw new Error("create key response missing fields");
  }

  try {
    fs.writeFileSync(authKeyPath, created.key, { mode: 0o600, flag: "wx" });
    fs.writeFileSync(hostnamePath, runtimeHostname, {
      mode: 0o600,
      flag: "wx",
    });
    writeState({
      keyId: created.id,
      hostname: runtimeHostname,
      baselineDeviceIds: before.devices.map((device) => String(device.id)),
      deviceId: null,
    });
  } catch (error) {
    await providerRequest(
      token,
      `${providerBase()}/keys/${encodeURIComponent(created.id)}`,
      { method: "DELETE" },
    );
    for (const localPath of [authKeyPath, hostnamePath, statePath]) {
      if (fs.existsSync(localPath)) fs.unlinkSync(localPath);
    }
    throw error;
  }

  emit({
    prepared: true,
    credentialPermissionsValid: true,
    localTailnetMatch: true,
    oneOff: true,
    ephemeral: true,
    preauthorized: true,
    expirySeconds: 900,
    baselineKeyCount: before.keys.length,
    baselineTaggedDeviceCount: before.devices.filter(
      (device) =>
        Array.isArray(device.tags) && device.tags.includes(credential.tag),
    ).length,
  });
} else if (action === "consume") {
  readState();
  const existed = fs.existsSync(authKeyPath);
  if (existed) fs.unlinkSync(authKeyPath);
  emit({ authKeyFileRemoved: existed, credentialEnvironmentPresent: false });
} else if (action === "discover") {
  const state = readState();
  const token = await oauthToken();
  const inventory = await listInventory(token);
  const matches = matchingDevices(inventory.devices, state);
  if (matches.length !== 1) {
    emit({ registered: false, exactCandidateCount: matches.length });
    process.exit(2);
  }

  state.deviceId = String(matches[0].id);
  writeState(state);
  emit({
    registered: true,
    exactCandidateCount: 1,
    exactTag: true,
    deviceIdentityPersistedLocally: true,
    currentTaggedDeviceCount: inventory.devices.filter(
      (device) =>
        Array.isArray(device.tags) && device.tags.includes(credential.tag),
    ).length,
  });
} else if (action === "ssh") {
  const state = readState();
  if (typeof state.deviceId !== "string") {
    throw new Error("device not discovered");
  }
  if (!localTailnetMatches()) throw new Error("local client tailnet mismatch");

  const remoteScript = [
    "printf 'LISKOV_LOCAL_UID='; id -u",
    "if [ \"$(pwd)\" = /root ] && [ \"$HOME\" = /root ]; then echo LISKOV_LOCAL_ROOT=1; else echo LISKOV_LOCAL_ROOT=0; fi",
    "if grep -q '^ID=debian$' /etc/os-release; then echo LISKOV_LOCAL_ROOTFS=1; else echo LISKOV_LOCAL_ROOTFS=0; fi",
    "if [ ! -e /data/data ] && [ ! -e /sdcard ] && [ ! -e /storage/emulated ]; then echo LISKOV_LOCAL_ANDROID_ISOLATED=1; else echo LISKOV_LOCAL_ANDROID_ISOLATED=0; fi",
    "exit",
  ].join("\n");

  const result = await new Promise((resolve, reject) => {
    const child = spawn("tailscale", ["ssh", `root@${state.hostname}`], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderrBytes = 0;
    let bounded = true;
    const timer = setTimeout(() => child.kill("SIGKILL"), 45_000);
    child.stdout.on("data", (chunk) => {
      if (Buffer.byteLength(stdout) + chunk.length > 1024 * 1024) {
        bounded = false;
        child.kill("SIGKILL");
      } else {
        stdout += chunk.toString("utf8");
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 1024 * 1024) {
        bounded = false;
        child.kill("SIGKILL");
      }
    });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, bounded, stderrBytes });
    });
    child.stdin.end(`${remoteScript}\n`);
  });

  const resultEvidence = {
    localTailnetMatch: true,
    sshExitZero: result.code === 0,
    outputBounded: result.bounded,
    stderrPresent: result.stderrBytes > 0,
    rootUid: /(?:^|\n)LISKOV_LOCAL_UID=0(?:\r?\n|$)/.test(result.stdout),
    rootHome: /(?:^|\n)LISKOV_LOCAL_ROOT=1(?:\r?\n|$)/.test(result.stdout),
    maintainedRootfs:
      /(?:^|\n)LISKOV_LOCAL_ROOTFS=1(?:\r?\n|$)/.test(result.stdout),
    androidPathsAbsent:
      /(?:^|\n)LISKOV_LOCAL_ANDROID_ISOLATED=1(?:\r?\n|$)/.test(result.stdout),
  };
  emit(resultEvidence);
  if (
    !resultEvidence.sshExitZero ||
    !resultEvidence.outputBounded ||
    !resultEvidence.rootUid ||
    !resultEvidence.rootHome ||
    !resultEvidence.maintainedRootfs ||
    !resultEvidence.androidPathsAbsent
  ) {
    process.exit(2);
  }
} else if (action === "cleanup") {
  const state = readState();
  const token = await oauthToken();
  let deviceDeleteStatus = null;
  let keyDeleteStatus = null;
  let deviceId = state.deviceId;

  if (typeof deviceId !== "string") {
    const current = await listInventory(token);
    const matches = matchingDevices(current.devices, state);
    if (matches.length > 1) {
      throw new Error("exact provider cleanup candidate is ambiguous");
    }
    if (matches.length === 1) deviceId = String(matches[0].id);
  }

  if (typeof deviceId === "string") {
    const response = await providerRequest(
      token,
      `https://api.tailscale.com/api/v2/device/${encodeURIComponent(deviceId)}`,
      { method: "DELETE" },
    );
    deviceDeleteStatus = response.status;
    if (!response.ok && response.status !== 404) {
      throw new Error(`delete device status ${response.status}`);
    }
  }
  if (typeof state.keyId === "string") {
    const response = await providerRequest(
      token,
      `${providerBase()}/keys/${encodeURIComponent(state.keyId)}`,
      { method: "DELETE" },
    );
    keyDeleteStatus = response.status;
    if (!response.ok && response.status !== 404) {
      throw new Error(`delete key status ${response.status}`);
    }
  }

  const after = await listInventory(token);
  const deviceAbsent =
    typeof deviceId !== "string" ||
    !after.devices.some((device) => String(device.id) === deviceId);
  const keyAbsent =
    typeof state.keyId !== "string" ||
    !after.keys.some((key) => String(key.id) === state.keyId);
  if (!deviceAbsent || !keyAbsent) {
    throw new Error("exact provider cleanup incomplete");
  }

  for (const localPath of [authKeyPath, hostnamePath, statePath]) {
    if (fs.existsSync(localPath)) fs.unlinkSync(localPath);
  }
  emit({
    exactDeviceAbsent: deviceAbsent,
    exactKeyAbsent: keyAbsent,
    deviceDeleteAccepted:
      deviceDeleteStatus === null || [200, 204, 404].includes(deviceDeleteStatus),
    keyDeleteAccepted:
      keyDeleteStatus === null || [200, 204, 404].includes(keyDeleteStatus),
    localSecretFilesRemoved: true,
    remainingTaggedDeviceCount: after.devices.filter(
      (device) =>
        Array.isArray(device.tags) && device.tags.includes(credential.tag),
    ).length,
  });
}
