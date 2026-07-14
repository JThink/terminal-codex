const SSH_AUTH_TYPES = new Set(["agent", "key", "password"]);
const DEFAULT_RECENT_SSH_PROFILE_LIMIT = 8;
const SSH_LAUNCHER_ADD_ACTION_ID = "__add_ssh_connection__";

const text = (value) => (typeof value === "string" ? value.trim() : "");

const normalizeAuthType = (value) =>
  SSH_AUTH_TYPES.has(value) ? value : "agent";

export const beginSingleFlight = (state) => {
  if (state?.inFlight) {
    return null;
  }
  const generation = (Number.isInteger(state?.generation) ? state.generation : 0) + 1;
  return {
    generation,
    state: { generation, inFlight: true },
  };
};

export const finishSingleFlight = (state, generation) => {
  if (state?.generation !== generation) {
    return state;
  }
  return { generation, inFlight: false };
};

export const isSingleFlightCurrent = (state, generation) =>
  state?.generation === generation && state.inFlight === true;

export const invalidateSingleFlight = (state) => ({
  generation: (Number.isInteger(state?.generation) ? state.generation : 0) + 1,
  inFlight: false,
});

export const formatSshEndpoint = (profile) => {
  const username = text(profile?.username);
  const rawHost = text(profile?.host);
  const host = rawHost.includes(":") && !rawHost.startsWith("[") ? `[${rawHost}]` : rawHost;
  const port = Number(profile?.port);
  const authority = username ? `${username}@${host}` : host;
  return Number.isInteger(port) && port > 0 && port !== 22
    ? `${authority}:${port}`
    : authority;
};

export const filterSshProfiles = (profiles, query) => {
  const source = Array.isArray(profiles) ? profiles : [];
  const needle = text(query).toLocaleLowerCase();
  if (!needle) {
    return source.slice();
  }
  return source.filter((profile) => {
    const haystack = [
      profile?.name,
      profile?.host,
      profile?.username,
      profile?.port,
      formatSshEndpoint(profile),
    ]
      .filter((value) => value != null)
      .join(" ")
      .toLocaleLowerCase();
    return haystack.includes(needle);
  });
};

export const normalizeRecentProfileIds = (
  recentIds,
  limit = DEFAULT_RECENT_SSH_PROFILE_LIMIT
) => {
  const max = Number.isInteger(limit) && limit > 0 ? limit : DEFAULT_RECENT_SSH_PROFILE_LIMIT;
  const unique = [];
  const seen = new Set();
  for (const candidate of Array.isArray(recentIds) ? recentIds : []) {
    const id = text(candidate);
    if (!id || seen.has(id)) {
      continue;
    }
    unique.push(id);
    seen.add(id);
    if (unique.length >= max) {
      break;
    }
  }
  return unique;
};

export const pushRecentProfileId = (
  recentIds,
  profileId,
  limit = DEFAULT_RECENT_SSH_PROFILE_LIMIT
) => {
  const id = text(profileId);
  const normalized = normalizeRecentProfileIds(recentIds, limit);
  if (!id) {
    return normalized;
  }
  return normalizeRecentProfileIds(
    [id, ...normalized.filter((candidate) => candidate !== id)],
    limit
  );
};

export const orderSshProfilesByRecent = (profiles, recentIds) => {
  const source = Array.isArray(profiles) ? profiles : [];
  const ordered = [];
  const seen = new Set();
  const profileById = new Map();
  for (const profile of source) {
    const id = text(profile?.id);
    if (id && !profileById.has(id)) {
      profileById.set(id, profile);
    }
  }
  for (const id of normalizeRecentProfileIds(recentIds, Number.MAX_SAFE_INTEGER)) {
    const profile = profileById.get(id);
    if (!profile || seen.has(id)) {
      continue;
    }
    ordered.push(profile);
    seen.add(id);
  }
  for (const profile of source) {
    const id = text(profile?.id);
    if (id && seen.has(id)) {
      continue;
    }
    ordered.push(profile);
    if (id) {
      seen.add(id);
    }
  }
  return ordered;
};

export const getSshLauncherProfiles = (profiles, query, recentIds) => {
  const filtered = filterSshProfiles(profiles, query);
  if (text(query)) {
    return orderSshProfilesByRecent(filtered, recentIds);
  }
  const normalizedRecentIds = new Set(
    normalizeRecentProfileIds(recentIds, Number.MAX_SAFE_INTEGER)
  );
  const recentProfiles = orderSshProfilesByRecent(filtered, recentIds).filter((profile) =>
    normalizedRecentIds.has(text(profile?.id))
  );
  return recentProfiles.length ? recentProfiles : filtered;
};

export const removeSshProfileById = (profiles, profileId) => {
  const removedId = text(profileId);
  return Array.isArray(profiles)
    ? profiles.filter((profile) => text(profile?.id) !== removedId)
    : [];
};

export const getSshLauncherAddActionId = () => SSH_LAUNCHER_ADD_ACTION_ID;

export const isSshLauncherAddActionId = (value) =>
  text(value) === SSH_LAUNCHER_ADD_ACTION_ID;

export const getSshLauncherActiveProfileId = (profiles, activeProfileId) => {
  const visibleProfiles = Array.isArray(profiles) ? profiles : [];
  const activeId = text(activeProfileId);
  if (isSshLauncherAddActionId(activeId)) {
    return SSH_LAUNCHER_ADD_ACTION_ID;
  }
  if (activeId && visibleProfiles.some((profile) => text(profile?.id) === activeId)) {
    return activeId;
  }
  return text(visibleProfiles[0]?.id) || SSH_LAUNCHER_ADD_ACTION_ID;
};

export const moveSshLauncherActiveProfileId = (profiles, activeProfileId, offset) => {
  const visibleProfiles = Array.isArray(profiles) ? profiles : [];
  const step = Number(offset);
  if (!Number.isFinite(step) || step === 0) {
    return getSshLauncherActiveProfileId(visibleProfiles, activeProfileId);
  }
  const activeId = getSshLauncherActiveProfileId(visibleProfiles, activeProfileId);
  const itemCount = visibleProfiles.length + 1;
  const currentIndex = isSshLauncherAddActionId(activeId)
    ? visibleProfiles.length
    : Math.max(
        0,
        visibleProfiles.findIndex((profile) => text(profile?.id) === activeId)
      );
  const nextIndex = (currentIndex + Math.sign(step) + itemCount) % itemCount;
  return nextIndex === visibleProfiles.length
    ? SSH_LAUNCHER_ADD_ACTION_ID
    : text(visibleProfiles[nextIndex]?.id) || SSH_LAUNCHER_ADD_ACTION_ID;
};

export const getSshLauncherTargetProfile = (profiles, activeProfileId) => {
  const visibleProfiles = Array.isArray(profiles) ? profiles : [];
  const activeId = getSshLauncherActiveProfileId(visibleProfiles, activeProfileId);
  if (isSshLauncherAddActionId(activeId)) {
    return null;
  }
  return (
    visibleProfiles.find((profile) => text(profile?.id) === activeId) ||
    visibleProfiles[0] ||
    null
  );
};

export const normalizeLaunchSpec = (launchSpec, legacyCwd = null) => {
  if (launchSpec?.kind === "ssh") {
    return {
      kind: "ssh",
      profileId: text(launchSpec.profileId),
    };
  }
  const cwd = text(launchSpec?.kind === "local" ? launchSpec.cwd : legacyCwd);
  return {
    kind: "local",
    cwd: cwd || null,
  };
};

export const serializeLaunchSpec = (launchSpec) => {
  const normalized = normalizeLaunchSpec(launchSpec);
  return normalized.kind === "ssh"
    ? { kind: "ssh", profileId: normalized.profileId }
    : { kind: "local", cwd: normalized.cwd };
};

export const cloneLaunchSpec = (launchSpec) => serializeLaunchSpec(launchSpec);

export const resolveSshLaunchProfile = (launchSpec, profiles) => {
  const normalized = normalizeLaunchSpec(launchSpec);
  if (normalized.kind !== "ssh") {
    return {
      launchSpec: normalized,
      profile: null,
      error: "当前窗格不是 SSH 连接。",
    };
  }
  const profile = (Array.isArray(profiles) ? profiles : []).find(
    (candidate) => candidate?.id === normalized.profileId
  );
  return {
    launchSpec: normalized,
    profile: profile || null,
    error: profile ? null : "SSH 连接不存在或已被删除。",
  };
};

export const terminalBytes = (data) => {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (Array.isArray(data)) {
    return Uint8Array.from(data);
  }
  if (typeof data === "string") {
    return new TextEncoder().encode(data);
  }
  return new Uint8Array();
};

export const withAuthType = (form, authType) => {
  const nextAuthType = normalizeAuthType(authType);
  return {
    ...form,
    authType: nextAuthType,
    identityFile: nextAuthType === "key" ? form?.identityFile || "" : "",
    password: nextAuthType === "password" ? form?.password || "" : "",
  };
};

export const buildProfilePayload = (form) => {
  const authType = normalizeAuthType(form?.authType);
  const password = typeof form?.password === "string" ? form.password : "";
  return {
    profile: {
      id: text(form?.id) || null,
      name: text(form?.name),
      host: text(form?.host),
      port: Number(form?.port),
      username: text(form?.username),
      authType,
      identityFile: authType === "key" ? text(form?.identityFile) || null : null,
      connectTimeout: Number(form?.connectTimeout),
    },
    password: authType === "password" && password.length ? password : null,
  };
};
