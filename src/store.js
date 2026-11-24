import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

function emptyState() {
  return {
    accounts: {},
    sessions: {},
    flows: {},
    codes: {},
    refreshTokens: {},
  };
}

function rid(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

/**
 * Tiny single-process JSON store. Good enough for a personal/homelab
 * deployment; swap for SQLite/Postgres before multi-instance use.
 */
export class Store {
  constructor(file) {
    this.file = file;
    this.state = emptyState();
    this.load();
  }

  load() {
    try {
      const raw = fs.readFileSync(this.file, "utf8");
      const parsed = JSON.parse(raw);
      this.state = { ...emptyState(), ...parsed };
      for (const key of Object.keys(emptyState())) {
        if (!this.state[key] || typeof this.state[key] !== "object") {
          this.state[key] = {};
        }
      }
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
      this.save();
    }
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  // --- accounts ---------------------------------------------------------

  getAccount(uid) {
    return this.state.accounts[uid] || null;
  }

  findAccount(issuer, sub) {
    return (
      Object.values(this.state.accounts).find(
        (a) => a.issuer === issuer && a.sub === sub,
      ) || null
    );
  }

  putAccount(account) {
    this.state.accounts[account.uid] = account;
    this.save();
    return account;
  }

  // --- sessions ---------------------------------------------------------

  createSession(uid, ttlMs) {
    const sid = rid();
    const now = Date.now();
    const session = { sid, uid, createdAt: now, expiresAt: now + ttlMs };
    this.state.sessions[sid] = session;
    this.save();
    return session;
  }

  getSession(sid) {
    const session = this.state.sessions[sid];
    if (!session) return null;
    if (session.expiresAt < Date.now()) {
      delete this.state.sessions[sid];
      this.save();
      return null;
    }
    return session;
  }

  deleteSession(sid) {
    if (this.state.sessions[sid]) {
      delete this.state.sessions[sid];
      this.save();
    }
  }

  // --- OIDC login flows -------------------------------------------------

  createFlow(flow) {
    this.state.flows[flow.state] = flow;
    this.save();
    return flow;
  }

  getFlow(state) {
    const flow = this.state.flows[state];
    if (!flow) return null;
    if (flow.expiresAt < Date.now()) {
      delete this.state.flows[state];
      this.save();
      return null;
    }
    return flow;
  }

  deleteFlow(state) {
    if (this.state.flows[state]) {
      delete this.state.flows[state];
      this.save();
    }
  }

  // --- OAuth codes ------------------------------------------------------

  createCode(code) {
    this.state.codes[code.code] = code;
    this.save();
    return code;
  }

  consumeCode(code) {
    const entry = this.state.codes[code];
    if (!entry) return null;
    delete this.state.codes[code];
    this.save();
    return entry;
  }

  // --- refresh tokens ---------------------------------------------------

  createRefresh(token) {
    this.state.refreshTokens[token.token] = token;
    this.save();
    return token;
  }

  getRefresh(token) {
    const entry = this.state.refreshTokens[token];
    if (!entry) return null;
    if (entry.expiresAt < Date.now()) {
      delete this.state.refreshTokens[token];
      this.save();
      return null;
    }
    return entry;
  }

  deleteRefresh(token) {
    if (this.state.refreshTokens[token]) {
      delete this.state.refreshTokens[token];
      this.save();
    }
  }

  cleanup() {
    const now = Date.now();
    let changed = false;
    for (const [key, value] of Object.entries(this.state.sessions)) {
      if (value.expiresAt < now) {
        delete this.state.sessions[key];
        changed = true;
      }
    }
    for (const [key, value] of Object.entries(this.state.flows)) {
      if (value.expiresAt < now) {
        delete this.state.flows[key];
        changed = true;
      }
    }
    for (const [key, value] of Object.entries(this.state.codes)) {
      if (value.expiresAt < now) {
        delete this.state.codes[key];
        changed = true;
      }
    }
    for (const [key, value] of Object.entries(this.state.refreshTokens)) {
      if (value.expiresAt < now) {
        delete this.state.refreshTokens[key];
        changed = true;
      }
    }
    if (changed) this.save();
  }
}
