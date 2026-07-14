import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as sshConnectionHelpers from "./ssh-connections.mjs";

import {
  beginSingleFlight,
  buildProfilePayload,
  cloneLaunchSpec,
  filterSshProfiles,
  formatSshEndpoint,
  getSshLauncherAddActionId,
  getSshLauncherActiveProfileId,
  getSshLauncherProfiles,
  getSshLauncherTargetProfile,
  isSshLauncherAddActionId,
  moveSshLauncherActiveProfileId,
  normalizeLaunchSpec,
  pushRecentProfileId,
  removeSshProfileById,
  resolveSshLaunchProfile,
  serializeLaunchSpec,
  terminalBytes,
  finishSingleFlight,
  invalidateSingleFlight,
  withAuthType,
} from "./ssh-connections.mjs";

const profiles = [
  {
    id: "one",
    name: "Production API",
    host: "api.example.com",
    port: 22,
    username: "deploy",
    authType: "agent",
  },
  {
    id: "two",
    name: "数据库",
    host: "10.0.0.8",
    port: 2222,
    username: "postgres",
    authType: "key",
  },
];

const srcDir = dirname(fileURLToPath(import.meta.url));
const readSource = (fileName) => readFileSync(join(srcDir, fileName), "utf8");

test("filters SSH profiles by name, host, username, and endpoint", () => {
  assert.deepEqual(filterSshProfiles(profiles, "PRODUCTION"), [profiles[0]]);
  assert.deepEqual(filterSshProfiles(profiles, "10.0.0.8"), [profiles[1]]);
  assert.deepEqual(filterSshProfiles(profiles, "postgres@10"), [profiles[1]]);
  assert.deepEqual(filterSshProfiles(profiles, "2222"), [profiles[1]]);
  assert.deepEqual(filterSshProfiles(profiles, ""), profiles);
});

test("formats ordinary and IPv6 SSH endpoints", () => {
  assert.equal(formatSshEndpoint(profiles[0]), "deploy@api.example.com");
  assert.equal(
    formatSshEndpoint({ username: "root", host: "2001:db8::1", port: 2200 }),
    "root@[2001:db8::1]:2200"
  );
});

test("recent SSH profile ids move to the front, deduplicate, and trim", () => {
  assert.deepEqual(pushRecentProfileId(["one", "two", "one"], "two", 3), ["two", "one"]);
  assert.deepEqual(pushRecentProfileId(["one", "two"], "three", 2), ["three", "one"]);
  assert.deepEqual(pushRecentProfileId(["one"], "  ", 3), ["one"]);
});

test("launcher defaults to recently used SSH profiles in recent-first order", () => {
  assert.deepEqual(getSshLauncherProfiles(profiles, "", ["two", "missing", "one"]), [
    profiles[1],
    profiles[0],
  ]);
  assert.deepEqual(getSshLauncherProfiles(profiles, "", []), profiles);
});

test("launcher search falls back to all matches while keeping recent results first", () => {
  assert.deepEqual(getSshLauncherProfiles(profiles, "o", ["two"]), [profiles[1], profiles[0]]);
  assert.deepEqual(getSshLauncherProfiles(profiles, "production", ["two"]), [profiles[0]]);
});

test("launcher keyboard selection defaults to the first match and wraps with arrows", () => {
  const visibleProfiles = getSshLauncherProfiles(profiles, "", ["two", "one"]);
  assert.equal(getSshLauncherActiveProfileId(visibleProfiles, ""), "two");
  assert.equal(moveSshLauncherActiveProfileId(visibleProfiles, "two", 1), "one");
  assert.equal(
    moveSshLauncherActiveProfileId(visibleProfiles, "one", 1),
    getSshLauncherAddActionId()
  );
  assert.equal(
    moveSshLauncherActiveProfileId(visibleProfiles, getSshLauncherAddActionId(), 1),
    "two"
  );
  assert.equal(
    moveSshLauncherActiveProfileId(visibleProfiles, "two", -1),
    getSshLauncherAddActionId()
  );
});

test("launcher enter target uses the active match or falls back to the first one", () => {
  const visibleProfiles = getSshLauncherProfiles(profiles, "o", ["two"]);
  assert.equal(getSshLauncherTargetProfile(visibleProfiles, "one")?.id, "one");
  assert.equal(getSshLauncherTargetProfile(visibleProfiles, "missing")?.id, "two");
  assert.equal(getSshLauncherTargetProfile(visibleProfiles, getSshLauncherAddActionId()), null);
  assert.equal(getSshLauncherTargetProfile([], "missing"), null);
});

test("launcher can select add action when there are no profile matches", () => {
  assert.equal(getSshLauncherActiveProfileId([], ""), getSshLauncherAddActionId());
  assert.equal(isSshLauncherAddActionId(getSshLauncherActiveProfileId([], "")), true);
});

test("launcher key actions select profiles cyclically and enter opens the active target", () => {
  const resolveKeyAction = sshConnectionHelpers.resolveSshLauncherKeyAction;
  assert.equal(typeof resolveKeyAction, "function");

  const visibleProfiles = getSshLauncherProfiles(profiles, "", ["two", "one"]);
  assert.deepEqual(resolveKeyAction(visibleProfiles, "two", "ArrowDown"), {
    kind: "select",
    activeProfileId: "one",
    profile: null,
  });
  assert.deepEqual(resolveKeyAction(visibleProfiles, "two", "ArrowUp"), {
    kind: "select",
    activeProfileId: getSshLauncherAddActionId(),
    profile: null,
  });
  assert.deepEqual(resolveKeyAction(visibleProfiles, getSshLauncherAddActionId(), "Enter"), {
    kind: "add",
    activeProfileId: getSshLauncherAddActionId(),
    profile: null,
  });
  assert.deepEqual(resolveKeyAction(visibleProfiles, "one", "Enter"), {
    kind: "connect",
    activeProfileId: "one",
    profile: profiles[0],
  });
});

test("SSH launcher keyboard handling is not limited to the search input", () => {
  const mainSource = readSource("main.js");
  assert.equal(
    /document\.addEventListener\(\s*"keydown",\s*handleSshConnectionsLauncherKeyDown/.test(
      mainSource
    ),
    true
  );
  assert.equal(
    /sshConnectionsSearchInput\.addEventListener\("keydown"/.test(mainSource),
    false
  );
});

test("SSH delete action does not depend on native confirmation dialogs", () => {
  const mainSource = readSource("main.js");
  const deleteSource =
    /const deleteCurrentSshProfile = async \(\) => \{[\s\S]*?\n\};/.exec(mainSource)?.[0] ||
    "";
  assert.notEqual(deleteSource, "");
  assert.equal(deleteSource.includes("window.confirm"), false);
});

test("recent add row exposes the same active visual state as profile rows", () => {
  const styles = readSource("styles.css");
  assert.equal(/\.ssh-connections-add-row\.active\b/.test(styles), true);
});

test("removes a deleted SSH profile from the loaded list", () => {
  assert.deepEqual(removeSshProfileById(profiles, "one"), [profiles[1]]);
  assert.deepEqual(removeSshProfileById(profiles, "missing"), profiles);
  assert.deepEqual(removeSshProfileById(null, "one"), []);
});

test("migrates legacy cwd into a local launch spec", () => {
  assert.deepEqual(normalizeLaunchSpec(null, "/tmp/demo"), {
    kind: "local",
    cwd: "/tmp/demo",
  });
});

test("normalizes local and SSH launch specs without leaking unrelated fields", () => {
  assert.deepEqual(
    normalizeLaunchSpec({ kind: "local", cwd: " /tmp/demo ", profileId: "secret" }),
    { kind: "local", cwd: "/tmp/demo" }
  );
  assert.deepEqual(
    normalizeLaunchSpec({ kind: "ssh", profileId: " profile-1 ", cwd: "/private" }),
    { kind: "ssh", profileId: "profile-1" }
  );
});

test("serializes SSH launch specs without cwd or profile contents", () => {
  assert.deepEqual(
    serializeLaunchSpec({
      kind: "ssh",
      profileId: "profile-1",
      cwd: "/must-not-persist",
      password: "must-not-persist",
      host: "must-not-persist",
    }),
    { kind: "ssh", profileId: "profile-1" }
  );
});

test("clones launch specs by value", () => {
  const source = { kind: "ssh", profileId: "profile-1" };
  const cloned = cloneLaunchSpec(source);
  assert.deepEqual(cloned, source);
  assert.notEqual(cloned, source);
});

test("keeps a missing SSH profile launch spec for later recovery", () => {
  assert.deepEqual(resolveSshLaunchProfile({ kind: "ssh", profileId: "gone" }, profiles), {
    launchSpec: { kind: "ssh", profileId: "gone" },
    profile: null,
    error: "SSH 连接不存在或已被删除。",
  });
});

test("resolves an existing SSH profile", () => {
  assert.deepEqual(resolveSshLaunchProfile({ kind: "ssh", profileId: "two" }, profiles), {
    launchSpec: { kind: "ssh", profileId: "two" },
    profile: profiles[1],
    error: null,
  });
});

test("converts terminal payloads into bytes without UTF-8 round trips", () => {
  const input = new Uint8Array([0, 0x80, 0xff, 10]);
  assert.deepEqual(terminalBytes([0, 0x80, 0xff, 10]), input);
  assert.equal(terminalBytes(input), input);
});

test("switching authentication clears incompatible form fields", () => {
  const base = {
    authType: "password",
    identityFile: "/tmp/id_ed25519",
    password: "secret",
  };
  assert.deepEqual(withAuthType(base, "key"), {
    authType: "key",
    identityFile: "/tmp/id_ed25519",
    password: "",
  });
  assert.deepEqual(withAuthType(base, "agent"), {
    authType: "agent",
    identityFile: "",
    password: "",
  });
});

test("builds a trimmed Agent profile payload", () => {
  assert.deepEqual(
    buildProfilePayload({
      id: "profile-1",
      name: " Production ",
      host: " api.example.com ",
      port: "22",
      username: " deploy ",
      authType: "agent",
      identityFile: "/ignored",
      connectTimeout: "15",
      password: "ignored",
    }),
    {
      profile: {
        id: "profile-1",
        name: "Production",
        host: "api.example.com",
        port: 22,
        username: "deploy",
        authType: "agent",
        identityFile: null,
        connectTimeout: 15,
      },
      password: null,
    }
  );
});

test("preserves password bytes and omits an empty password to mean keep", () => {
  const base = {
    id: "profile-2",
    name: "Password host",
    host: "host.example.com",
    port: 22,
    username: "root",
    authType: "password",
    identityFile: "",
    connectTimeout: 10,
  };
  assert.equal(buildProfilePayload({ ...base, password: " p a s s " }).password, " p a s s ");
  assert.equal(buildProfilePayload({ ...base, password: "" }).password, null);
});

test("includes identity file only for key authentication", () => {
  const payload = buildProfilePayload({
    name: "Key host",
    host: "host.example.com",
    port: "2222",
    username: "root",
    authType: "key",
    identityFile: " ~/.ssh/id_ed25519 ",
    connectTimeout: "20",
    password: "",
  });
  assert.deepEqual(payload, {
    profile: {
      id: null,
      name: "Key host",
      host: "host.example.com",
      port: 2222,
      username: "root",
      authType: "key",
      identityFile: "~/.ssh/id_ed25519",
      connectTimeout: 20,
    },
    password: null,
  });
});

test("single-flight state rejects overlap and ignores stale completion", () => {
  const first = beginSingleFlight(null);
  assert.deepEqual(first, {
    generation: 1,
    state: { generation: 1, inFlight: true },
  });
  assert.equal(beginSingleFlight(first.state), null);

  const invalidated = invalidateSingleFlight(first.state);
  assert.deepEqual(invalidated, { generation: 2, inFlight: false });
  assert.equal(finishSingleFlight(invalidated, first.generation), invalidated);

  const second = beginSingleFlight(invalidated);
  assert.deepEqual(
    finishSingleFlight(second.state, second.generation),
    { generation: 3, inFlight: false }
  );
});

test("close and reopen invalidate stale operation completion", () => {
  const isSingleFlightCurrent = sshConnectionHelpers.isSingleFlightCurrent;
  assert.equal(typeof isSingleFlightCurrent, "function");

  const first = beginSingleFlight(null);
  assert.equal(isSingleFlightCurrent(first.state, first.generation), true);

  const closed = invalidateSingleFlight(first.state);
  assert.equal(isSingleFlightCurrent(closed, first.generation), false);

  const reopened = invalidateSingleFlight(closed);
  const second = beginSingleFlight(reopened);
  assert.equal(isSingleFlightCurrent(second.state, first.generation), false);
  assert.equal(isSingleFlightCurrent(second.state, second.generation), true);

  const afterStaleFinish = finishSingleFlight(second.state, first.generation);
  assert.equal(afterStaleFinish, second.state);
  assert.equal(isSingleFlightCurrent(afterStaleFinish, second.generation), true);
});
