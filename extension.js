'use strict';

const vscode = require('vscode');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const { Client } = require('ssh2');
const SSHConfig = require('ssh-config');

// How long to wait for the TCP reachability probe before declaring a host
// offline. This is a LAN device, not the internet — an online host answers in
// milliseconds, so a short budget keeps an offline host from stalling anything.
// NOTE: this probe only applies to hosts reached *directly*. Hosts reached via
// ProxyJump are not directly reachable from here, so they skip the probe and
// rely on ssh2's own readyTimeout instead (see connectThroughJumps below).
const REACH_TIMEOUT_MS = 800;

// Quick "is the SSH port even open?" check, done before handing off to ssh2 so an
// offline LAN device fails in ~1s instead of hanging on the OS connect timeout.
// Resolves true if we can open a TCP socket to host:port, false otherwise.
function probeReachable(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false)); // EHOSTUNREACH / ECONNREFUSED / etc.
    socket.connect(port, host);
  });
}

// ---------------------------------------------------------------------------
// ~/.ssh/config parsing
// ---------------------------------------------------------------------------

function sshConfigPath() {
  return path.join(os.homedir(), '.ssh', 'config');
}

function loadConfig() {
  try {
    return SSHConfig.parse(fs.readFileSync(sshConfigPath(), 'utf8'));
  } catch (e) {
    return SSHConfig.parse('');
  }
}

function listHostAliases(cfg) {
  const out = [];
  for (const line of cfg) {
    if (line.param && line.param.toLowerCase() === 'host') {
      const vals = Array.isArray(line.value) ? line.value : [line.value];
      for (const v of vals) {
        // Guard against blank/undefined tokens and non-string values some
        // ssh-config versions can hand back (e.g. malformed "Host" lines) —
        // without this, a later .sort(...localeCompare...) throws on them.
        if (typeof v !== 'string' || !v) continue;
        if (!/[*?!]/.test(v)) out.push(v);
      }
    }
  }
  return [...new Set(out)];
}

// Safe string sort: coerces both sides to string first so a stray
// non-string entry never blows up .localeCompare.
function sortAliases(list) {
  return [...list].sort((a, b) => String(a).localeCompare(String(b), undefined, { sensitivity: 'base' }));
}

function expandHome(p) {
  if (p && p.startsWith('~')) return path.join(os.homedir(), p.slice(1));
  return p;
}

// Resolve a ~/.ssh/config Host alias into an ssh2 connect config. Does NOT
// resolve ProxyJump itself — that's handled by connectThroughJumps — it's just
// surfaced on the returned object as `_proxyJump` so callers can decide.
function resolveHostConfig(alias, cfg) {
  const c = cfg.compute(alias) || {};
  const host = c.HostName || alias;
  const port = c.Port ? parseInt(c.Port, 10) : 22;
  const username = c.User || os.userInfo().username;

  const identityFiles = c.IdentityFile
    ? (Array.isArray(c.IdentityFile) ? c.IdentityFile : [c.IdentityFile])
    : [];
  let privateKey;
  for (const f of identityFiles) {
    try {
      privateKey = fs.readFileSync(expandHome(f));
      break;
    } catch (e) { /* missing key file, try next */ }
  }

  const conf = {
    host,
    port,
    username,
    tryKeyboard: true,
    readyTimeout: 15000,
    // Detect a silently-dead peer (host powered off) in ~10s rather than ~45s.
    keepaliveInterval: 5000,
    keepaliveCountMax: 2,
    // 'none' first so passwordless/open hosts connect with zero prompts.
    authHandler: ['none', 'agent', 'publickey', 'keyboard-interactive', 'password'],
  };
  if (privateKey) conf.privateKey = privateKey;
  if (process.env.SSH_AUTH_SOCK) conf.agent = process.env.SSH_AUTH_SOCK;
  conf._proxyJump = c.ProxyJump || null;
  conf._alias = alias;
  return conf;
}

// Kept for backwards compatibility with any external callers.
function connectConfigFor(alias) {
  return resolveHostConfig(alias, loadConfig());
}

// ---------------------------------------------------------------------------
// ProxyJump support
// ---------------------------------------------------------------------------

// Connect a bare ssh2 Client with a given config (config may include a `sock`
// duplex stream instead of host/port, which is how we tunnel through jumps).
function connectClient(conf) {
  return new Promise((resolve, reject) => {
    const client = new Client();
    client.on('keyboard-interactive', (name, instr, lang, prompts, finish) => {
      finish(prompts.map(() => ''));
    });
    client.once('ready', () => resolve(client));
    client.once('error', reject);
    client.connect(conf);
  });
}

// Ask an already-connected client to open a direct-tcpip channel to
// destHost:destPort. The resulting stream is handed to the *next* client in
// the chain as its `sock`, so from ssh2's point of view it's just a socket.
function forwardThrough(client, destHost, destPort) {
  return new Promise((resolve, reject) => {
    client.forwardOut('127.0.0.1', 0, destHost, destPort, (err, stream) => {
      if (err) return reject(err);
      resolve(stream);
    });
  });
}

// Walk the ProxyJump chain for `alias` (each hop may itself specify a
// ProxyJump, chained back to back like OpenSSH does) and connect hop by hop,
// tunnelling each new client's traffic through the previous one via
// forwardOut. Returns { client, jumpClients }: `client` is the final,
// already-sftp-ready-to-open connection to the target host; `jumpClients`
// are the intermediate hosts kept alive for the lifetime of the tunnel.
async function connectThroughJumps(alias, cfg) {
  const chain = [];
  let current = alias;
  const seen = new Set();
  while (true) {
    if (seen.has(current)) {
      throw new Error(`SSH Explorer: ProxyJump cycle detected involving "${current}".`);
    }
    seen.add(current);
    const conf = resolveHostConfig(current, cfg);
    chain.unshift(conf);
    if (!conf._proxyJump) break;
    // ProxyJump can list multiple comma-separated hops ("jump1,jump2"); only
    // the first is the next hop closer to us — jump2 would come from jump1's
    // own ProxyJump entry in ~/.ssh/config, which the loop picks up naturally
    // once we resolve jump1.
    let next = conf._proxyJump.split(',')[0].trim();
    if (next.includes('@')) next = next.split('@').pop(); // best-effort: user@alias
    current = next;
  }
  // chain[0] = outermost jump host (the one we can reach directly),
  // chain[chain.length - 1] = the actual target host.
  const jumpClients = [];
  let sock;
  for (let i = 0; i < chain.length; i++) {
    const conf = { ...chain[i] };
    delete conf['_proxyJump'];
    delete conf['_alias'];
    if (sock) conf['sock'] = sock;

    if (!sock) {
      // Only the first hop is checked with the fast TCP probe — it's the only
      // one directly reachable from this machine.
      const reachable = await probeReachable(conf.host, conf.port, REACH_TIMEOUT_MS);
      if (!reachable) {
        throw vscode.FileSystemError.Unavailable(
          `SSH Explorer: jump host ${chain[i]._alias} (${conf.host}:${conf.port}) is offline or unreachable.`);
      }
    }

    const client = await connectClient(conf);
    if (i === chain.length - 1) {
      return { client, jumpClients };
    }
    jumpClients.push(client);
    const nextConf = chain[i + 1];
    sock = await forwardThrough(client, nextConf.host, nextConf.port);
  }
  throw new Error('SSH Explorer: empty ProxyJump chain.');
}

function getWorkspaceRoot(alias) {
  const folders = vscode.workspace.workspaceFolders || [];

  const folder = folders.find(f =>
    f.uri.scheme === "sshx" &&
    f.uri.authority === alias
  );

  return folder ? folder.uri.path : "/";
}

// ---------------------------------------------------------------------------
// Auto-opened hidden shell terminals (one real `ssh <alias>` session per host)
// ---------------------------------------------------------------------------
//
// This reuses the *system* ssh binary and ~/.ssh/config (including any
// ProxyJump directives) rather than piggybacking on the ssh2/SFTP connection,
// since ssh2 doesn't give us a normal interactive PTY. The terminal is created

const sshExplorerTerminals = new Map(); // alias -> vscode.Terminal

function createSshExplorerTerminal(alias, rootPath = "/") {

  const existing = vscode.window.terminals.find(
    t => t.name === `SSH Explorer: ${alias}`
  );

  if (existing) {
    return;
  }

  const term = vscode.window.createTerminal({
    name: `SSH Explorer: ${alias}`,
    isTransient: true
  });

  sshExplorerTerminals.set(alias, term);

  term.onDidCloseTerminal?.(() => {
    sshExplorerTerminals.delete(alias);
  });

  const escaped = rootPath.replace(/'/g, "'\\''");

  term.hide();
  term.sendText(`ssh -t ${alias}`, true);

  setTimeout(() => {
    term.sendText(`cd '${escaped}'`, true);
    term.sendText("clear", true);
  }, 2000);

  setTimeout(() => {
    term.show(true);
  }, 3000);
}

function disposeSshExplorerTerminal(alias) {
  const term = sshExplorerTerminals.get(alias);
  if (term) {
    try { term.dispose(); } catch (e) { /* already gone */ }
    sshExplorerTerminals.delete(alias);
  }
}

function openTerminal(provider) {
  return async function (preselectedAlias) {
    let alias = preselectedAlias;

    if (typeof alias !== "string" || !alias) {
      const active = [...provider.conns.keys()];

      if (!active.length) {
        vscode.window.showInformationMessage(
          "SSH Explorer: no active connections."
        );
        return;
      }

      alias = await vscode.window.showQuickPick(active, {
        placeHolder: "Open terminal for which host?"
      });

      if (!alias) {
        return;
      }
    }

    const existing = vscode.window.terminals.find(t => t.name === `SSH Explorer: ${alias}`);

    if (existing && existing.exitStatus === undefined) {
      existing.show(true);
      return;
    }

    const rootPath = getWorkspaceRoot(alias); // hoặc "/"

    createSshExplorerTerminal(alias, rootPath);

    const term = sshExplorerTerminals.get(alias);
    if (term) {
      term.show(true);
    }
  }
}

// ---------------------------------------------------------------------------
// One reconnecting SSH/SFTP connection per host alias
// ---------------------------------------------------------------------------

class Connection {
  constructor(alias) {
    this.alias = alias;
    this.client = null;
    this.sftp = null;
    this.jumpClients = [];
    this.pending = null;
  }

  getSftp() {
    if (this.sftp) return Promise.resolve(this.sftp);
    if (this.pending) return this.pending;
    this.pending = this._connect();
    this.pending.finally(() => { this.pending = null; });
    return this.pending;
  }

  async _connect() {
    const cfg = loadConfig();
    const conf = resolveHostConfig(this.alias, cfg);

    let client;
    let jumpClients = [];

    if (!conf._proxyJump) {
      // Direct path: fail fast if the device isn't on the LAN, instead of
      // waiting on ssh2's connect.
      const reachable = await probeReachable(conf.host, conf.port, REACH_TIMEOUT_MS);
      if (!reachable) {
        throw vscode.FileSystemError.Unavailable(
          `SSH Explorer: ${this.alias} (${conf.host}:${conf.port}) is offline or unreachable.`);
      }
      const direct = { ...conf };
      delete direct['_proxyJump'];
      delete direct['_alias'];
      client = await connectClient(direct);
    } else {
      // Tunnel through the ProxyJump chain.
      const result = await connectThroughJumps(this.alias, cfg);
      client = result.client;
      jumpClients = result.jumpClients;
    }

    return new Promise((resolve, reject) => {
      client.sftp((err, sftp) => {
        if (err) {
          client.end();
          jumpClients.forEach((c) => { try { c.end(); } catch (e) { } });
          return reject(err);
        }
        this.client = client;
        this.jumpClients = jumpClients;
        this.sftp = sftp;
        client.on('error', () => this._reset());
        client.on('close', () => this._reset());
        resolve(sftp);
      });
    });
  }

  _reset() {
    this.sftp = null;
    this.client = null;
    this.jumpClients.forEach((c) => { try { c.end(); } catch (e) { } });
    this.jumpClients = [];
  }

  end() {
    if (this.client) { try { this.client.end(); } catch (e) { } }
    this._reset();
  }
}

// ---------------------------------------------------------------------------
// FileSystemProvider over SFTP
// ---------------------------------------------------------------------------

// Hard ceiling for any single filesystem operation. Without this, a request
// issued the moment a host dies hangs on the OS TCP timeout (minutes).
const OP_TIMEOUT_MS = 12000;

function fileTypeFromAttrs(a) {
  if (a.isDirectory && a.isDirectory()) return vscode.FileType.Directory;
  if (a.isFile && a.isFile()) return vscode.FileType.File;
  return vscode.FileType.Unknown;
}

function makeStat(a, type) {
  const mtime = (a.mtime || 0) * 1000;
  return { type, ctime: mtime, mtime, size: a.size || 0 };
}

function toFsError(err, uri) {
  const code = err && err.code;
  const msg = (err && err.message) || '';
  if (code === 2 || /no such file/i.test(msg)) return vscode.FileSystemError.FileNotFound(uri);
  if (code === 3 || /permission denied/i.test(msg)) return vscode.FileSystemError.NoPermissions(uri);
  return err;
}

class SSHFileSystemProvider {
  constructor() {
    this._emitter = new vscode.EventEmitter();
    this.onDidChangeFile = this._emitter.event;
    this.conns = new Map();

    // Offline hosts get a "!" badge in the Explorer (via FileDecorationProvider)
    // instead of error popups. _offline holds the authorities currently down.
    this._offline = new Set();
    this._decoEmitter = new vscode.EventEmitter();
    this.onDidChangeFileDecorations = this._decoEmitter.event;

    // Fired whenever a host's online/offline state changes, so the sidebar
    // status Tree View can refresh its icons independently of the Explorer.
    this._statusEmitter = new vscode.EventEmitter();
    this.onDidChangeHostStatus = this._statusEmitter.event;
  }

  conn(authority) {
    let c = this.conns.get(authority);
    if (!c) { c = new Connection(authority); this.conns.set(authority, c); }
    return c;
  }

  knownAuthorities() {
    return [...this.conns.keys()];
  }

  isOffline(authority) {
    return this._offline.has(authority);
  }

  isConnected(authority) {
    const c = this.conns.get(authority);
    return !!(c && c.sftp);
  }

  // Get an SFTP handle, recording the host's online/offline state as a side
  // effect so the Explorer badge and sidebar status view stay in sync. Also
  // kicks off the hidden auto-terminal on a fresh, successful connection.
  // Throws (quietly handled by callers) when the host is unreachable.
  async _sftp(uri) {
    const wasConnected = this.isConnected(uri.authority);
    try {
      const sftp = await this.conn(uri.authority).getSftp();
      this._setOffline(uri.authority, false);
      if (!wasConnected) {
        const remotePath = getWorkspaceRoot(uri.authority) || "/";

        createSshExplorerTerminal(uri.authority, remotePath);
      }

      return sftp;
    } catch (e) {
      this._setOffline(uri.authority, true);
      disposeSshExplorerTerminal(uri.authority);
      throw e;
    }
  }

  // Flip a host's offline state and refresh its Explorer badge if it changed.
  _setOffline(authority, offline) {
    if (offline === this._offline.has(authority)) {
      this._statusEmitter.fire(authority);
      return;
    }
    if (offline) this._offline.add(authority); else this._offline.delete(authority);
    const uris = (vscode.workspace.workspaceFolders || [])
      .filter((f) => f.uri.scheme === 'sshx' && f.uri.authority === authority)
      .map((f) => f.uri);
    this._decoEmitter.fire(uris.length ? uris : undefined);
    this._statusEmitter.fire(authority);
  }

  // FileDecorationProvider: show a "!" next to an offline host's folder.
  provideFileDecoration(uri) {
    if (uri.scheme === 'sshx' && this._offline.has(uri.authority)) {
      return {
        badge: '!',
        tooltip: 'SSH Explorer: host is offline or unreachable',
        color: new vscode.ThemeColor('list.warningForeground'),
        propagate: false, // don't bubble up to the parent — show a single "!"
      };
    }
    return undefined;
  }

  // Kick off a connection in the background and refresh the tree once it's ready.
  // Used so the Explorer never blocks on connect — it renders immediately and
  // fills in when (if) the host answers. Offline hosts just get the "!" badge.
  _warm(uri) {
    this._sftp(uri).then(
      () => this._emitter.fire([{ type: vscode.FileChangeType.Changed, uri }]),
      () => { } // unreachable: badge already set by _sftp; no spinner, no popup
    );
  }

  // Backstop for the two operations VS Code calls automatically: if a host dies
  // mid-session, keepalive (~10s) normally rejects in-flight calls, but this
  // guarantees the UI can never freeze on stat/readDirectory.
  _withTimeout(uri, promise) {
    promise.catch(() => { }); // swallow a late rejection if the timeout already won
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        this.disconnect(uri.authority);
        this._setOffline(uri.authority, true);
        reject(vscode.FileSystemError.Unavailable(
          `SSH Explorer: ${uri.authority} is not responding (timed out after ${OP_TIMEOUT_MS / 1000}s).`));
      }, OP_TIMEOUT_MS);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
  }

  disconnect(authority) {
    const c = this.conns.get(authority);
    if (c) { c.end(); this.conns.delete(authority); }
    disposeSshExplorerTerminal(authority);
    this._statusEmitter.fire(authority);
  }

  watch() { return new vscode.Disposable(() => { }); }

  // stat/readDirectory are timeout-guarded (auto-called, must never freeze the UI).
  // Data/bulk ops run uncapped so large transfers aren't cut off; they rely on
  // keepalive to fail on a dead host.
  stat(uri) { return this._withTimeout(uri, this._stat(uri)); }
  readDirectory(uri) { return this._withTimeout(uri, this._readDirectory(uri)); }
  readFile(uri) { return this._readFile(uri); }
  writeFile(uri, content) { return this._writeFile(uri, content); }
  createDirectory(uri) { return this._createDirectory(uri); }
  delete(uri, options) { return this._delete(uri, options); }
  rename(oldUri, newUri) { return this._rename(oldUri, newUri); }

  async _stat(uri) {
    const conn = this.conn(uri.authority);
    const p = uri.path || '/';
    // Not connected yet → don't block. Render the root as a directory instantly so
    // the folder node shows, and connect in the background. Deeper paths aren't
    // known until connected, so report them as not-found (quiet) for now.
    if (!conn.sftp) {
      this._warm(uri);
      if (p === '/' || p === '') {
        return { type: vscode.FileType.Directory, ctime: 0, mtime: 0, size: 0 };
      }
      throw vscode.FileSystemError.FileNotFound(uri);
    }
    const sftp = conn.sftp;
    return new Promise((resolve, reject) => {
      sftp.lstat(p, (err, st) => {
        if (err) return reject(toFsError(err, uri));
        if (st.isSymbolicLink && st.isSymbolicLink()) {
          sftp.stat(p, (e2, st2) => {
            if (e2) return resolve(makeStat(st, vscode.FileType.SymbolicLink));
            resolve(makeStat(st2, fileTypeFromAttrs(st2) | vscode.FileType.SymbolicLink));
          });
        } else {
          resolve(makeStat(st, fileTypeFromAttrs(st)));
        }
      });
    });
  }

  async _readDirectory(uri) {
    const conn = this.conn(uri.authority);
    // Connect on expand: each time a not-yet-connected host is unfolded, actually
    // try to reach it. The fast probe bounds this to ~1s, so an offline host falls
    // through to an empty tree + "!" badge instead of blocking. (We don't rely on
    // a background refresh event — VS Code doesn't reliably re-list a folder from
    // one, which is why it previously only filled in after a manual refresh.)
    let sftp = conn.sftp;
    if (!sftp) {
      try {
        sftp = await this._sftp(uri);
      } catch (e) {
        return []; // offline/unreachable: empty tree; _sftp already set the badge
      }
    }
    const dir = uri.path || '/';
    const list = await new Promise((resolve, reject) => {
      sftp.readdir(dir, (err, l) => err ? reject(toFsError(err, uri)) : resolve(l));
    });
    const base = dir.replace(/\/+$/, '');
    return Promise.all(list.map((e) => new Promise((resolve) => {
      const a = e.attrs;
      if (a.isSymbolicLink && a.isSymbolicLink()) {
        // Resolve the link target so symlinked dirs are expandable.
        sftp.stat(base + '/' + e.filename, (err, st) => {
          const t = err ? vscode.FileType.Unknown : fileTypeFromAttrs(st);
          resolve([e.filename, t | vscode.FileType.SymbolicLink]);
        });
      } else {
        resolve([e.filename, fileTypeFromAttrs(a)]);
      }
    })));
  }

  async _readFile(uri) {
    let sftp;
    try {
      sftp = await this._sftp(uri);
    } catch (e) {
      // Host offline/unreachable. Report not-found rather than a loud "Unavailable"
      // so background language servers (Pylance, etc.) skip the file quietly
      // instead of popping a notification. The "!" badge already signals the state.
      throw vscode.FileSystemError.FileNotFound(uri);
    }
    return new Promise((resolve, reject) => {
      const chunks = [];
      const stream = sftp.createReadStream(uri.path);
      stream.on('data', (d) => chunks.push(d));
      stream.on('error', (e) => reject(toFsError(e, uri)));
      stream.on('end', () => resolve(new Uint8Array(Buffer.concat(chunks))));
    });
  }

  async _writeFile(uri, content) {
    const sftp = await this._sftp(uri);
    await new Promise((resolve, reject) => {
      const ws = sftp.createWriteStream(uri.path);
      ws.on('error', (e) => reject(toFsError(e, uri)));
      ws.on('close', () => resolve());
      ws.end(Buffer.from(content));
    });
    this._emitter.fire([{ type: vscode.FileChangeType.Changed, uri }]);
  }

  async _createDirectory(uri) {
    const sftp = await this._sftp(uri);
    await new Promise((resolve, reject) => {
      sftp.mkdir(uri.path, (err) => err ? reject(toFsError(err, uri)) : resolve());
    });
  }

  async _delete(uri, options) {
    const sftp = await this._sftp(uri);
    await this._rm(sftp, uri.path, options && options.recursive, uri);
    this._emitter.fire([{ type: vscode.FileChangeType.Deleted, uri }]);
  }

  async _rm(sftp, p, recursive, uri) {
    const st = await new Promise((resolve, reject) =>
      sftp.lstat(p, (e, s) => e ? reject(toFsError(e, uri)) : resolve(s)));
    if (st.isDirectory && st.isDirectory()) {
      if (recursive) {
        const list = await new Promise((resolve, reject) =>
          sftp.readdir(p, (e, l) => e ? reject(toFsError(e, uri)) : resolve(l)));
        const base = p.replace(/\/+$/, '');
        for (const e of list) await this._rm(sftp, base + '/' + e.filename, true, uri);
      }
      await new Promise((resolve, reject) =>
        sftp.rmdir(p, (e) => e ? reject(toFsError(e, uri)) : resolve()));
    } else {
      await new Promise((resolve, reject) =>
        sftp.unlink(p, (e) => e ? reject(toFsError(e, uri)) : resolve()));
    }
  }

  async _rename(oldUri, newUri) {
    const sftp = await this._sftp(oldUri);
    await new Promise((resolve, reject) =>
      sftp.rename(oldUri.path, newUri.path, (e) => e ? reject(toFsError(e, oldUri)) : resolve()));
    this._emitter.fire([
      { type: vscode.FileChangeType.Deleted, uri: oldUri },
      { type: vscode.FileChangeType.Created, uri: newUri },
    ]);
  }
}

// ---------------------------------------------------------------------------
// Sidebar status Tree View (Activity Bar icon showing per-host state)
// ---------------------------------------------------------------------------

class HostStatusItem extends vscode.TreeItem {
  constructor(alias, provider) {
    super(alias, vscode.TreeItemCollapsibleState.None);

    const offline = provider.isOffline(alias);
    const connected = provider.isConnected(alias);

    if (offline) {
      this.iconPath = new vscode.ThemeIcon(
        "debug-disconnect",
        new vscode.ThemeColor("list.warningForeground")
      );
      this.description = "offline";
    } else if (connected) {
      this.iconPath = new vscode.ThemeIcon(
        "vm-active",
        new vscode.ThemeColor("charts.green")
      );
      this.description = "connected";
    } else {
      this.iconPath = new vscode.ThemeIcon("vm-outline");
      this.description = "not connected";
    }

    this.contextValue = "sshExplorerHost";
    this.alias = alias.alias;

    // Click vào host -> mở terminal
    this.command = {
      command: "sshExplorer.openTerminal",
      title: "Open Terminal",
      arguments: [alias]
    };
  }
}

class HostStatusTreeProvider {
  constructor(provider) {
    this.provider = provider;
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    provider.onDidChangeHostStatus(() => this._onDidChangeTreeData.fire());
  }

  getTreeItem(element) { return element; }

  getChildren() {
    const aliases = this.provider.knownAuthorities();
    if (!aliases.length) return [];
    return sortAliases(aliases).map((a) => new HostStatusItem(a, this.provider));
  }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function openHost() {
  const aliases = sortAliases(listHostAliases(loadConfig()));
  if (!aliases.length) {
    vscode.window.showErrorMessage('SSH Explorer: no Host entries found in ~/.ssh/config');
    return;
  }
  const alias = await vscode.window.showQuickPick(aliases, {
    placeHolder: 'Pick an SSH host from ~/.ssh/config',
  });
  if (!alias) return;

  const root = await vscode.window.showInputBox({
    prompt: `Remote folder to open on ${alias}`,
    value: '/',
  });
  if (root === undefined) return;
  const rootPath = root.startsWith('/') ? root : '/' + root;

  const uri = vscode.Uri.parse(`sshx://${alias}${rootPath}`);
  const idx = vscode.workspace.workspaceFolders ? vscode.workspace.workspaceFolders.length : 0;
  vscode.workspace.updateWorkspaceFolders(idx, 0, { uri, name: `${alias}${rootPath === '/' ? '' : ':' + rootPath}` });
}

function makeDisconnect(provider) {
  return async function disconnectHost(preselectedAlias) {
    let alias = preselectedAlias;

    if (typeof alias !== "string" || !alias) {
      const active = [...provider.conns.keys()];

      if (!active.length) {
        vscode.window.showInformationMessage(
          "SSH Explorer: no active connections."
        );
        return;
      }

      alias = await vscode.window.showQuickPick(active, {
        placeHolder: "Open terminal for which host?"
      });

      if (!alias) {
        return;
      }
    }
  
    provider.disconnect(alias);
    vscode.window.showInformationMessage(`SSH Explorer: disconnected ${alias}.`);
  };
}


function activate(context) {
  const provider = new SSHFileSystemProvider();
  const statusTree = new HostStatusTreeProvider(provider);

  context.subscriptions.push(
    vscode.workspace.registerFileSystemProvider('sshx', provider, { isCaseSensitive: true }),
    vscode.window.registerFileDecorationProvider(provider),
    vscode.window.registerTreeDataProvider('sshExplorerHosts', statusTree),
    vscode.commands.registerCommand('sshExplorer.openHost', openHost),
    vscode.commands.registerCommand('sshExplorer.disconnectHost', makeDisconnect(provider)),
    vscode.commands.registerCommand("sshExplorer.openTerminal", openTerminal(provider)),
  );
}

function deactivate() {
  for (const alias of sshExplorerTerminals.keys()) {
    disposeSshExplorerTerminal(alias);
  }
}

module.exports = { activate, deactivate };