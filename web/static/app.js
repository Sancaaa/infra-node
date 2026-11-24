'use strict';

// The whole UI in one file, read top to bottom, built the way k3s manager's is:
//   1. helpers        h(), icons, the row menu, dialogs, api()
//   2. login          the page before anybody is known
//   3. pages          Hosts, Groups, Code, Overview, Access, Secrets, Playbooks, History, Users, Profile
//   4. shell          the sidebar, the router, start
//
// Nothing here is a security boundary: the server checks the session and the
// role on every request (internal/web). Hiding a button is only politeness.
// Every text from the server goes in as a text node (h() never builds HTML).

// ---------------------------------------------------------------- helpers

// h("div", {class: "x"}, "text", child) builds a DOM element. Strings become
// text nodes, never HTML: user names, targets and detail text come from people
// and machines and must show up as plain text.
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs || {})) {
    if (value != null && value !== false) el.setAttribute(name, value);
  }
  for (const child of children.flat(Infinity)) {
    if (child != null && child !== false) el.append(child);
  }
  return el;
}

function icon(pathData) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  const path = document.createElementNS(ns, 'path');
  path.setAttribute('d', pathData);
  svg.append(path);
  return svg;
}
const ICON_HOSTS = 'M3 3h10v4H3zM3 9h10v4H3zM5.5 5h.01M5.5 11h.01';
const ICON_HISTORY = 'M2.5 8a5.5 5.5 0 1 0 1.7-4M2.5 2.5v3h3M8 5v3.2l2 1.3';
const ICON_USERS = 'M6 7.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zM1.5 13.5c0-2.5 2-4 4.5-4s4.5 1.5 4.5 4M11 3a2.3 2.3 0 0 1 0 4.4M12 9.7c1.6.4 2.5 1.6 2.5 3.8';
const ICON_PROFILE = 'M8 7.5a2.7 2.7 0 1 0 0-5.4 2.7 2.7 0 0 0 0 5.4zM2.5 14c0-2.6 2.5-4.2 5.5-4.2s5.5 1.6 5.5 4.2';
const ICON_SETTINGS = 'M8 10.2a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4zM8 1.8v1.6M8 12.6v1.6M1.8 8h1.6M12.6 8h1.6M3.6 3.6l1.1 1.1M11.3 11.3l1.1 1.1M3.6 12.4l1.1-1.1M11.3 4.7l1.1-1.1';
const ICON_COPY = 'M6 6h7v7.5H6zM3 10V2.5h7';
const ICON_CHECK = 'M3 8.5l3.2 3L13 4.5';
const ICON_MORE = 'M3 8h1.2M7.4 8h1.2M11.8 8h1.2';

function button(label, className, onClick) {
  const b = h('button', { class: className, type: 'button' }, label);
  b.addEventListener('click', onClick);
  return b;
}

const ICON_CLOSE = 'M4 4l8 8M12 4l-8 8';

function iconOnly(label, pathData, onClick) {
  const b = h('button', { class: 'icon-button', type: 'button', title: label, 'aria-label': label }, icon(pathData));
  b.addEventListener('click', onClick);
  return b;
}

function pageHead(title, description, ...actions) {
  return h('header', { class: 'page-head' },
    h('div', {}, h('h1', {}, title), description ? h('p', { class: 'desc' }, description) : null),
    h('div', { class: 'page-actions' }, actions));
}

function sectionHead(title, description, ...actions) {
  return h('div', { class: 'section-head' },
    h('div', {}, h('h2', {}, title), description ? h('div', { class: 'sub' }, description) : null),
    h('div', { class: 'page-actions' }, actions));
}

function field(label, control, hint) {
  return h('label', { class: 'field' }, h('span', {}, label), control, hint ? h('span', { class: 'hint' }, hint) : null);
}

function input(attrs) {
  return h('input', { class: 'input', ...attrs });
}

function th(text, className) {
  return h('th', { class: className || null }, text);
}

function emptyText(text) {
  return h('div', { class: 'empty small' }, text);
}

function notice(text) {
  return h('div', { class: 'notice' }, text);
}

function dot(kind) {
  return h('span', { class: 'dot' + (kind && kind !== 'ok' ? ' ' + kind : '') });
}

function when(unixSeconds) {
  return unixSeconds ? new Date(unixSeconds * 1000).toLocaleString() : '—';
}

// "5 minutes ago", for when a host was last seen.
function ago(unixSeconds) {
  const sec = Math.max(0, Math.round(Date.now() / 1000 - unixSeconds));
  const unit = (n, word) => n + ' ' + word + (n === 1 ? '' : 's') + ' ago';
  if (sec < 60) return 'just now';
  if (sec < 3600) return unit(Math.floor(sec / 60), 'minute');
  if (sec < 86400) return unit(Math.floor(sec / 3600), 'hour');
  return unit(Math.floor(sec / 86400), 'day');
}

function until(unixSeconds) {
  if (!unixSeconds) return '—';
  const sec = Math.round(unixSeconds - Date.now() / 1000);
  if (sec <= 30) return 'soon';
  if (sec < 3600) { const m = Math.ceil(sec / 60); return 'in ' + m + (m === 1 ? ' minute' : ' minutes'); }
  if (sec < 86400) { const hr = Math.round(sec / 3600); return 'in ' + hr + (hr === 1 ? ' hour' : ' hours'); }
  return when(unixSeconds);
}

// A number and a thin bar (design.md §5): warning from 80 %, danger from 95 %.
// The width is set through the element's style object: an inline style
// attribute would be refused by the Content-Security-Policy, this is not.
function usage(percent, text) {
  const fill = h('div', { class: 'bar-fill' });
  fill.style.width = Math.min(100, Math.max(0, percent)) + '%';
  return h('div', { class: 'usage' + (percent >= 95 ? ' danger' : percent >= 80 ? ' warn' : '') },
    h('div', { class: 'usage-text' }, text), h('div', { class: 'bar' }, fill));
}

// One number of the Overview: a figure and what it counts.
function stat(value, label, kind) {
  return h('div', { class: 'stat' },
    h('div', { class: 'stat-number' + (kind ? ' ' + kind : '') }, value),
    h('div', { class: 'stat-label' }, label));
}

// A short note in the corner while something slow runs (a connection to a host
// takes a few seconds). Call the function it returns to remove it.
function toast(text) {
  const el = h('div', { class: 'toast', role: 'status' }, text);
  document.body.append(el);
  return () => el.remove();
}

// The clipboard API only works on https and localhost; the old way is the
// fallback. The helper box goes inside the open dialog: the rest of the page
// cannot be focused while a dialog is modal.
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) { /* not allowed here */ }
  const box = h('textarea', { class: 'clipboard-helper', readonly: '' });
  box.value = text;
  (document.querySelector('dialog[open]') || document.body).append(box);
  box.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (err) { /* ok stays false */ }
  box.remove();
  return ok;
}

function copyButton(label, getText) {
  const b = h('button', { class: 'btn btn-small', type: 'button' }, icon(ICON_COPY), label);
  b.addEventListener('click', async () => {
    const ok = await copyText(getText());
    b.replaceChildren(icon(ok ? ICON_CHECK : ICON_COPY), ok ? 'Copied' : 'Could not copy');
    setTimeout(() => b.replaceChildren(icon(ICON_COPY), label), 1500);
  });
  return b;
}

// A line to copy: the text, and a Copy button.
function codeBlock(text) {
  return h('div', { class: 'code-block' }, h('pre', {}, text), copyButton('Copy', () => text));
}

// -------------------------------------------------------- show-command mode

// The command behind an action is a helper, not the page: the switch at the
// bottom of the sidebar is off by default, and when it is on, an action's result
// shows the command that ran. A per-browser preference, so localStorage (which
// may be unavailable, hence the try).
const COMMANDS_KEY = 'infra-manager-commands';
let showCommands = false;
try { showCommands = localStorage.getItem(COMMANDS_KEY) === 'on'; } catch (err) { /* keep the default */ }

function applyCommandsSwitch() {
  document.body.classList.toggle('hide-commands', !showCommands);
}

function commandsSwitch() {
  const box = h('input', { type: 'checkbox', checked: showCommands });
  box.addEventListener('change', () => {
    showCommands = box.checked;
    try { localStorage.setItem(COMMANDS_KEY, showCommands ? 'on' : 'off'); } catch (err) { /* not saved, still applied */ }
    applyCommandsSwitch();
  });
  return h('label', { class: 'toggle' }, box, 'Show commands');
}

// One command, as a person would type it. A muted part (-o) is only there so the
// dashboard can read the answer: leave it out when you type it yourself.
function cmdBlock(shown) {
  const line = h('div', { class: 'cmd-line' }, '$ ' + shown.command,
    shown.extra ? h('span', { class: 'cmd-extra', title: 'Added by the dashboard so it can read the answer. Leave it out when you type the command.' }, ' ' + shown.extra) : null);
  return h('div', { class: 'code-block' }, line, copyButton('Copy', () => shown.command));
}

// "Ran": under a result, hidden unless Show commands is on.
function ranBlock(commands) {
  const list = (commands || []).filter(Boolean);
  if (list.length === 0) return null;
  return h('div', { class: 'cmd' }, h('div', { class: 'cmd-label' }, 'Ran'), list.map(cmdBlock));
}

// A dialog with only a Close button: for something to read.
function infoDialog(title, ...body) {
  const dlg = h('dialog', { class: 'dialog' },
    h('h2', { class: 'dialog-title' }, title), body,
    h('div', { class: 'dialog-actions end' }, button('Close', 'btn btn-primary', () => dlg.close())));
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
}

// Sizes and times, for the Hosts page. They are numbers from the host's own
// report, so they only ever go through Number() and toFixed().
function gigabytes(bytes) {
  return (bytes / 1024 ** 3).toFixed(bytes < 10 * 1024 ** 3 ? 1 : 0) + ' GB';
}

function duration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return days + ' d ' + hours + ' h';
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? hours + ' h ' + minutes + ' min' : minutes + ' min';
}

function rootDisk(facts) {
  const disks = (facts && facts.disks) || [];
  return disks.find((d) => d.mount === '/') || disks[0];
}

// The menu of a "⋯" button. At most one is open at a time.
let openMenu = null;

function closeMenu() {
  if (!openMenu) return;
  openMenu.menu.remove();
  openMenu = null;
}

// items: [{label, run, danger}]
function rowMenu(items, label) {
  const anchor = h('div', { class: 'menu-anchor' });
  const trigger = h('button', { class: 'icon-button', type: 'button', title: label || 'More actions', 'aria-label': label || 'More actions' }, icon(ICON_MORE));
  trigger.addEventListener('click', () => {
    const wasOpen = openMenu && openMenu.anchor === anchor;
    closeMenu();
    if (wasOpen) return;
    const menu = h('div', { class: 'menu', role: 'menu' },
      items.filter(Boolean).map((item) => button(item.label, 'menu-item' + (item.danger ? ' danger-text' : ''), () => {
        closeMenu();
        item.run();
      })));
    anchor.append(menu);
    openMenu = { anchor, menu };
  });
  anchor.append(trigger);
  return anchor;
}

document.addEventListener('mousedown', (event) => {
  if (openMenu && !event.target.closest('.menu-anchor')) closeMenu();
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') closeMenu();
});

// One place for talking to the server. It never throws on an HTTP error: the
// caller looks at ok / status / data. A 401 anywhere but the login itself means
// the session is over (it expired, or somebody ended it), so it goes back to
// the login page at once.
async function api(method, path, body) {
  const options = { method };
  if (body !== undefined) {
    options.headers = { 'Content-Type': 'application/json' };
    options.body = JSON.stringify(body);
  }
  let resp;
  try {
    resp = await fetch(path, options);
  } catch (err) {
    return { ok: false, status: 0, data: { error: 'Cannot reach the server.' } };
  }
  let data = null;
  try { data = await resp.json(); } catch (err) { /* no body, or not JSON */ }
  if (!data || typeof data !== 'object') data = {};
  if (!resp.ok && !data.error) data.error = 'Request failed (HTTP ' + resp.status + ').';
  if (resp.status === 401 && path !== '/api/login') sessionEnded();
  return { ok: resp.ok, status: resp.status, data };
}

// A pop-up form on the browser's own <dialog>. onSubmit returns an error
// sentence to show (the dialog stays open), or nothing when it worked.
// Returned by onSubmit when the dialog should stay open: it showed a result.
const KEEP_OPEN = Symbol('keep the dialog open');

function openDialog({ title, body, submitLabel, danger = false, wide = false, busyLabel = 'Working…', onSubmit }) {
  const error = h('div', { class: 'form-error', role: 'alert' });
  const submit = h('button', { class: danger ? 'btn btn-danger' : 'btn btn-primary', type: 'submit' }, submitLabel);
  const cancel = button(submitLabel ? 'Cancel' : 'Close', 'btn', () => dlg.close());
  const form = h('form', {}, h('h2', { class: 'dialog-title' }, title), body, error,
    h('div', { class: 'dialog-actions' }, cancel, submitLabel ? submit : null));
  const dlg = h('dialog', { class: wide ? 'dialog dialog-wide' : 'dialog' }, form);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    submit.disabled = true;
    submit.textContent = busyLabel; // a connection to a host can take a few seconds
    error.textContent = '';
    const message = await onSubmit();
    if (message === KEEP_OPEN) {
      submit.disabled = false;
      submit.textContent = submitLabel;
      return;
    }
    if (message) {
      error.textContent = message;
      submit.disabled = false;
      submit.textContent = submitLabel;
      return;
    }
    dlg.close();
  });
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  return dlg;
}

// ------------------------------------------------------------------- login

const view = document.getElementById('view');
const nav = document.getElementById('nav');
let me = null; // the person who is logged in, from /api/me

function showLogin(message) {
  me = null;
  document.body.classList.add('logged-out');
  document.querySelectorAll('dialog').forEach((d) => d.close());

  const name = input({ type: 'text', name: 'username', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: '' });
  const password = input({ type: 'password', name: 'password', autocomplete: 'current-password', required: '' });
  const error = h('div', { class: 'form-error', role: 'alert' }, message || '');
  const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Log in');
  const form = h('form', { class: 'login' },
    h('h1', {}, 'infra-node'),
    h('p', { class: 'desc' }, 'Log in to manage your hosts.'),
    field('User name', name),
    field('Password', password),
    error, submit);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    submit.disabled = true;
    error.textContent = '';
    const username = name.value;
    const pass = password.value;
    const r = await api('POST', '/api/login', { username, password: pass });
    if (!r.ok) {
      error.textContent = r.data.error;
      password.value = '';
      submit.disabled = false;
      return;
    }
    if (r.data.totp_setup) {
      showTOTPSetup(username, pass, r.data.secret, r.data.otpauth_uri);
      return;
    }
    if (r.data.totp_required) {
      showTOTPCode(username, pass);
      return;
    }
    me = r.data;
    showApp();
  });

  view.replaceChildren(form);
  nav.replaceChildren();
  document.getElementById('sidebar-foot').replaceChildren();
  name.focus();
}

function showTOTPSetup(username, password, secret, otpauthURI) {
  const code = input({ type: 'text', name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '8', placeholder: '123456', required: '' });
  const error = h('div', { class: 'form-error', role: 'alert' });
  const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Verify and log in');
  const back = button('Back', 'btn', () => showLogin());
  const form = h('form', { class: 'login login-wide' },
    h('h1', {}, 'infra-node'),
    h('p', { class: 'desc' }, 'Set up two-factor authentication before signing in. Add this key to an authenticator app, then enter the 6-digit code.'),
    h('div', { class: 'cmd-label-plain' }, 'Secret key (Base32)'),
    codeBlock(secret),
    h('div', { class: 'cmd-label-plain' }, 'Authenticator URI'),
    codeBlock(otpauthURI),
    field('One-time code', code, '6 digits from your authenticator app.'),
    error, submit, back);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    submit.disabled = true;
    error.textContent = '';
    const r = await api('POST', '/api/login', { username, password, code: code.value });
    if (!r.ok) {
      error.textContent = r.data.error;
      code.value = '';
      code.focus();
      submit.disabled = false;
      return;
    }
    me = r.data;
    showApp();
  });

  view.replaceChildren(form);
  code.focus();
}

function showTOTPCode(username, password) {
  const code = input({ type: 'text', name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '8', placeholder: '123456', required: '' });
  const error = h('div', { class: 'form-error', role: 'alert' });
  const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Log in');
  const back = button('Back', 'btn', () => showLogin());
  const form = h('form', { class: 'login' },
    h('h1', {}, 'infra-node'),
    h('p', { class: 'desc' }, 'Enter the 6-digit code from your authenticator app.'),
    field('One-time code', code),
    error, submit, back);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    submit.disabled = true;
    error.textContent = '';
    const r = await api('POST', '/api/login', { username, password, code: code.value });
    if (!r.ok) {
      error.textContent = r.data.error;
      code.value = '';
      code.focus();
      submit.disabled = false;
      return;
    }
    me = r.data;
    showApp();
  });

  view.replaceChildren(form);
  code.focus();
}

function sessionEnded() {
  if (me) showLogin('Your session ended. Log in again.');
}

// ------------------------------------------------------------------- pages

function check(control, label) {
  return h('label', { class: 'check' }, control, label);
}

function isAdmin() { return me.role === 'admin'; }
function canOperate() { return me.role === 'operator' || me.role === 'admin'; }

const STATUS = {
  online: { dot: 'ok', text: 'Online' },
  offline: { dot: 'bad', text: 'Offline' },
  auth_failed: { dot: 'warn', text: 'Key refused' },
  key_changed: { dot: 'bad', text: 'Host key changed' },
  rebooting: { dot: 'warn', text: 'Rebooting' },
  unknown: { dot: 'off', text: 'Not checked' },
};

// The command that puts the dashboard's key on a host, for a person to run by
// hand. The key has no quote in it (base64, spaces, a fixed comment), so it can
// sit in single quotes. printf starts with a newline so that a file whose last
// line has none does not get the key glued to it; grep makes a second run
// harmless.
function authorizeCommand(publicKey) {
  const quoted = "'" + publicKey + "'";
  return 'umask 077; mkdir -p ~/.ssh; grep -qxF ' + quoted + ' ~/.ssh/authorized_keys 2>/dev/null || printf \'\\n%s\\n\' ' +
    quoted + ' >> ~/.ssh/authorized_keys';
}

async function hostsPage(container) {
  const r = await api('GET', '/api/hosts');
  if (!r.ok) {
    container.replaceChildren(pageHead('Hosts'), notice(r.data.error));
    return;
  }
  const hosts = r.data.hosts;
  const checkComp = canOperate() && hosts.some((x) => x.config && (x.config.state === 'applied' || x.config.state === 'drifted'))
    ? button('Check compliance', 'btn', runComplianceCheck) : null;
  const add = isAdmin() ? button('Add host', 'btn btn-primary', addHostDialog) : null;

  container.replaceChildren(...[
    pageHead('Hosts', 'The machines this dashboard manages and configures.', checkComp, add),
    ...hosts.filter((host) => host.status === 'key_changed').map(keyChangedNotice),
    hosts.length === 0
      ? h('div', { class: 'empty' },
        h('div', { class: 'name' }, 'No hosts yet'),
        h('div', {}, isAdmin() ? 'Add the first one: its address, a user and a password.' : 'Hosts that an admin adds will show up here, with their status.'),
        add)
      : h('table', {},
        h('thead', {}, h('tr', {}, th('Name'), th('Address'), th('Groups', 'col-hide'), th('Status'), th('Configuration', 'col-hide'), th('OS', 'col-hide'), th('Load', 'col-hide'), th('RAM', 'col-hide'), th('Disk', 'col-hide'), th('', 'col-act'))),
        h('tbody', {}, hosts.map(hostRow))),
  ].filter(Boolean));
}

// A host whose key changed is the one thing on this page that may be an
// attack, so it is said above the table, not only in a cell.
function keyChangedNotice(host) {
  return h('div', { class: 'notice danger-box' },
    h('strong', {}, host.name),
    ' showed a different SSH key than the one the dashboard saved, so every connection to it is refused. ' +
    'That is expected if the machine was reinstalled, and not if somebody is pretending to be it. ',
    isAdmin() ? button('Review the new key…', 'btn btn-small', () => trustKeyDialog(host)) : 'An admin has to review it.');
}

function hostRow(host) {
  const status = STATUS[host.status] || STATUS.unknown;
  const facts = host.facts;
  const health = host.health;
  // What a host last reported is shown while it answers; when it does not, a
  // number from an hour ago would look like a fact.
  const live = host.status === 'online' && health;
  const memUsed = live ? health.mem_total_kb - health.mem_avail_kb : 0;

  // What needs a look, as small tags under the status.
  const tags = [];
  if (live) {
    if (health.failed.length) tags.push(h('span', { class: 'tag tag-warn', title: health.failed.join(', ') }, health.failed.length + ' failed'));
    if (health.reboot_required) tags.push(h('span', { class: 'tag tag-warn' }, 'reboot needed'));
    if (health.updates > 0) tags.push(h('span', { class: 'tag' }, health.updates + ' updates'));
  }

  return h('tr', {},
    h('td', { class: 'name' }, host.name,
      host.machine_id ? h('span', { class: 'tag', title: 'Managed by Proxmox machine ' + host.machine_name }, 'proxmox') : null,
      host.sudo_ok ? null : h('span', { class: 'tag tag-warn', title: 'sudo asks for a password, so this host can be looked at but not configured' }, 'no sudo')),
    h('td', {}, host.address + (host.port === 22 ? '' : ':' + host.port), h('div', { class: 'sub' }, 'as ' + host.user)),
    h('td', { class: 'col-hide' }, (host.groups || []).length ? host.groups.map((g) => h('span', { class: 'tag' }, g)) : h('span', { class: 'sub' }, '—')),
    h('td', { title: host.status_detail || null }, dot(status.dot), status.text,
      host.status !== 'online' && host.last_seen ? h('div', { class: 'sub' }, 'last seen ' + ago(host.last_seen)) : null,
      tags.length ? h('div', {}, tags) : null),
    h('td', { class: 'col-hide' }, configCell(host)),
    h('td', { class: 'col-hide' }, (facts && facts.os) || '—'),
    h('td', { class: 'col-hide num' }, live ? [health.load1.toFixed(2), facts && facts.cpus ? h('div', { class: 'sub' }, facts.cpus + ' CPU') : null] : '—'),
    h('td', { class: 'col-hide' }, live && health.mem_total_kb
      ? usage(100 * memUsed / health.mem_total_kb, gigabytes(memUsed * 1024) + ' / ' + gigabytes(health.mem_total_kb * 1024)) : '—'),
    h('td', { class: 'col-hide' }, live && health.disk_size_kb
      ? usage(100 * health.disk_used_kb / health.disk_size_kb, gigabytes(health.disk_used_kb * 1024) + ' / ' + gigabytes(health.disk_size_kb * 1024)) : '—'),
    h('td', { class: 'col-act' }, rowMenu([
      { label: 'Details', run: () => detailsDialog(host) },
      canOperate() && { label: 'Check now', run: () => checkNow(host) },
      canOperate() && { label: 'Restart a service…', run: () => restartDialog(host) },
      canOperate() && { label: 'Service logs…', run: () => logsDialog(host) },
      canOperate() && { label: 'Reboot…', danger: true, run: () => rebootDialog(host) },
      isAdmin() && { label: 'Run a command…', run: () => runDialog(host) },
      host.config && host.config.state === 'drifted' && { label: canOperate() ? 'Profile drift & Fix…' : 'See profile drift…', run: () => profileDriftDialog(host.id, host.name, host.config.drift) },
      canOperate() && { label: isAdmin() ? 'Profile…' : 'See the profile…', run: () => profileDialog({ title: 'Profile of ' + host.name, url: '/api/hosts/' + host.id + '/profile', intro: 'The roles this host is configured with, on top of those of its groups.' }) },
      canOperate() && { label: 'Preview…', run: () => previewDialog(host.name, { host_id: host.id }) },
      canOperate() && { label: 'Apply…', run: () => applyDialog(host.name, { host_id: host.id }) },
      canOperate() && { label: 'Update packages…', run: () => patchDialog('host ' + host.name, { host_id: host.id }) },
      canOperate() && { label: 'Ping with Ansible', run: () => pingDialog(host.name, { host_id: host.id }) },
      canOperate() && { label: 'Ansible facts…', run: () => factsDialog(host) },
      canOperate() && { label: 'Variables…', run: () => varsDialog({ title: 'Variables of ' + host.name, url: '/api/hosts/' + host.id + '/vars' }) },
      isAdmin() && { label: 'Edit…', run: () => editHostDialog(host) },
      isAdmin() && host.status === 'key_changed' && { label: 'Trust the new key…', run: () => trustKeyDialog(host) },
      isAdmin() && { label: 'Remove…', danger: true, run: () => removeHostDialog(host) },
    ])));
}

async function checkNow(host) {
  const done = toast('Checking ' + host.name + '…');
  const r = await api('POST', '/api/hosts/' + host.id + '/check');
  done();
  if (!r.ok) infoDialog('The check failed', h('p', {}, r.data.error));
  route();
}

// The four fields every host has. Names are checked again on the server, which
// is the one that decides; the page only saves a round trip.
function hostFields(host) {
  const name = input({ type: 'text', value: host.name || '', autocapitalize: 'none', spellcheck: 'false', required: '', placeholder: 'web-1' });
  const address = input({ type: 'text', value: host.address || '', autocapitalize: 'none', spellcheck: 'false', required: '', placeholder: '192.168.1.20 or web-1.lab' });
  const port = input({ type: 'number', value: String(host.port || 22), min: '1', max: '65535', required: '' });
  const user = input({ type: 'text', value: host.user || '', autocapitalize: 'none', spellcheck: 'false', required: '', placeholder: 'root or deploy' });
  return {
    name, address, port, user,
    nodes: [
      field('Name', name, 'What the dashboard calls it: lowercase letters, digits, dot, dash or underscore.'),
      h('div', { class: 'row' }, field('Address', address), field('SSH port', port)),
      field('SSH user', user, 'The account the dashboard logs in as.'),
    ],
  };
}

function sudoOption() {
  const box = h('input', { type: 'checkbox', checked: true });
  return {
    box,
    node: [
      check(box, 'Let the dashboard use sudo without a password'),
      h('p', { class: 'hint' }, 'Needed to configure the host later. Only done when sudo asks for a password: the dashboard writes ' +
        '/etc/sudoers.d/infra-manager-<user>, checked with visudo before it is put in place.'),
    ],
  };
}

function showWarnings(title, warnings) {
  if (warnings && warnings.length) infoDialog(title, warnings.map((w) => h('p', {}, w)));
}

function addHostDialog() {
  const f = hostFields({ port: 22 });
  const method = h('select', { class: 'input' },
    h('option', { value: 'password' }, 'Password (used once)'),
    h('option', { value: 'key' }, 'I added the key myself'));
  const password = input({ type: 'password', autocomplete: 'off', required: '' });
  const sudo = sudoOption();

  const passwordBlock = h('div', {},
    field('Password', password, 'Used once to put the dashboard\'s key on the host, then forgotten. It is never stored.'),
    sudo.node);
  const commandBox = h('div', {}, h('div', { class: 'sub' }, 'Loading the key…'));
  const keyBlock = h('div', { hidden: true },
    h('p', {}, 'Run this on the host, logged in as that user. Then press Add host: the dashboard tests the login.'),
    commandBox);
  api('GET', '/api/ssh-key').then((r) =>
    commandBox.replaceChildren(r.ok ? codeBlock(authorizeCommand(r.data.public_key)) : notice(r.data.error)));

  method.addEventListener('change', () => {
    passwordBlock.hidden = method.value !== 'password';
    keyBlock.hidden = method.value !== 'key';
    password.required = method.value === 'password';
  });

  openDialog({
    title: 'Add host',
    submitLabel: 'Add host',
    busyLabel: 'Connecting…',
    body: [f.nodes, field('How does the dashboard get in?', method), passwordBlock, keyBlock],
    onSubmit: async () => {
      const body = { name: f.name.value, address: f.address.value, port: Number(f.port.value), user: f.user.value, method: method.value };
      if (method.value === 'password') {
        body.password = password.value;
        body.sudo_nopasswd = sudo.box.checked;
      }
      const r = await api('POST', '/api/hosts', body);
      password.value = '';
      if (!r.ok) return r.data.error;
      route();
      showWarnings('Host added, with a note', r.data.warnings);
      return null;
    },
  });
}

function editHostDialog(host) {
  const f = hostFields(host);
  const owned = Boolean(host.machine_id);
  if (owned) {
    f.address.disabled = true;
    f.address.title = 'Owned by Proxmox machine ' + host.machine_name;
  }
  const password = input({ type: 'password', autocomplete: 'off' });
  const sudo = sudoOption();
  openDialog({
    title: 'Edit ' + host.name,
    submitLabel: 'Save',
    busyLabel: 'Connecting…',
    body: [
      f.nodes,
      owned ? h('p', { class: 'sub' }, 'The address is owned by the Proxmox machine ' + host.machine_name + ' and cannot be edited here.') : null,
      h('div', { class: 'dialog-group' },
        h('h3', {}, 'Install the dashboard\'s key again'),
        h('p', { class: 'sub' }, 'Only if the host lost the key (it was reinstalled, or its authorized_keys was changed). ' +
          'Enter its password: it is used once and forgotten. Leave it empty otherwise.'),
        field('Password', password),
        sudo.node),
    ],
    onSubmit: async () => {
      const r = await api('POST', '/api/hosts/' + host.id + '/edit', {
        name: f.name.value, address: owned ? host.address : f.address.value, port: Number(f.port.value), user: f.user.value,
        password: password.value, sudo_nopasswd: sudo.box.checked,
      });
      password.value = '';
      if (!r.ok) return r.data.error;
      route();
      showWarnings('Saved, with a note', r.data.warnings);
      return null;
    },
  });
}

function factRows(rows) {
  return h('dl', { class: 'facts' }, rows.map(([label, value]) => [h('dt', {}, label), h('dd', {}, value)]));
}

// What the Details dialog shows about a host's insides: from a fresh reading
// (facts, health, ports) or, when the host cannot be reached, the last stored
// one (ports are never stored: they are null then).
function insideSections(f, health, ports) {
  const rows = [];
  if (f) {
    rows.push(['Host name', f.hostname || '—'], ['Operating system', f.os || '—'], ['Kernel', f.kernel || '—'],
      ['Architecture', f.arch || '—'], ['CPUs', f.cpus ? String(f.cpus) : '—']);
  }
  if (health) {
    const total = health.mem_total_kb;
    rows.push(
      ['Memory', total ? gigabytes((total - health.mem_avail_kb) * 1024) + ' used of ' + gigabytes(total * 1024) : '—'],
      ['Load', [health.load1, health.load5, health.load15].map((n) => n.toFixed(2)).join('   ') + '   (1, 5, 15 minutes)'],
      ['Uptime', health.uptime_s ? duration(health.uptime_s) : '—'],
      ['Reboot', health.reboot_required ? 'Needed: a newer kernel is installed, or the system asks for it' : 'Not needed'],
      ['Updates', health.updates >= 0 ? health.updates + ' waiting (from the host\'s own package list)' : 'Not known'],
      ['Failed services', health.failed.length ? health.failed.map((u) => h('div', { class: 'mono' }, u)) : 'None']);
  }
  if (f) rows.push(['Addresses', f.ips.length ? f.ips.map((ip) => h('div', { class: 'mono' }, ip.interface + '   ' + ip.cidr)) : '—']);

  return [
    factRows(rows),
    f && f.disks.length
      ? [h('h3', {}, 'Disks'),
        h('table', {},
          h('thead', {}, h('tr', {}, th('Mounted on'), th('Used'), th('Size'))),
          h('tbody', {}, f.disks.map((d) => h('tr', {}, h('td', { class: 'mono' }, d.mount), h('td', { class: 'num' }, gigabytes(d.used)), h('td', { class: 'num' }, gigabytes(d.size))))))]
      : null,
    ports
      ? [h('h3', {}, 'Listening ports'),
        ports.length
          ? h('table', {},
            h('thead', {}, h('tr', {}, th('Address'), th('Program'))),
            h('tbody', {}, ports.map((p) => h('tr', {}, h('td', { class: 'mono' }, p.local), h('td', {}, p.process || '—')))))
          : emptyText('None found, or the host has no ss.')]
      : null,
  ];
}

function detailsDialog(host) {
  const status = STATUS[host.status] || STATUS.unknown;
  const live = h('div', {}, h('div', { class: 'sub' }, 'Reading the host…'));
  openDialog({
    title: host.name,
    submitLabel: '',
    wide: true,
    body: [
      factRows([
        ['Address', host.address + ':' + host.port + ' as ' + host.user],
        ...(host.machine_id ? [['Machine', host.machine_name + ' (Proxmox / Terraform)']] : []),
        ['Status', [dot(status.dot), status.text, host.status_detail ? h('div', { class: 'sub' }, host.status_detail) : null]],
        ['Last seen', host.last_seen ? when(host.last_seen) + ' (' + ago(host.last_seen) + ')' : 'never'],
        ['Host key', h('span', { class: 'mono' }, host.host_key_fp || '—')],
        ['sudo', host.sudo_ok ? 'Works without a password'
          : 'Not available. The host can be looked at, but configuring it will not work. Edit the host to let the dashboard use sudo without a password, or give that user passwordless sudo.'],
      ]),
      live,
    ],
  });
  // Read from the host now, not from the database: this is the one place a
  // person wants the real state, and it costs one connection.
  api('GET', '/api/hosts/' + host.id + '/details').then((r) => {
    // h() flattens the nested lists and skips what is null; replaceChildren would not.
    if (r.ok) {
      live.replaceChildren(h('div', {}, insideSections(r.data.facts, r.data.health, r.data.ports)));
    } else {
      live.replaceChildren(
        notice('The host cannot be read now: ' + r.data.error + ' What follows is from the last check.'),
        h('div', {}, insideSections(host.facts, host.health, null)));
    }
  });
}

// ---------------------------------------------------------- quick actions

// The host's own list of services, to pick from. Failed ones come first: that
// is usually what a person is here for.
function servicePicker(host) {
  const select = h('select', { class: 'input' }, h('option', { value: '' }, 'Reading the host\'s services…'));
  const status = h('div');
  api('GET', '/api/hosts/' + host.id + '/services').then((r) => {
    if (!r.ok) {
      select.replaceChildren(h('option', { value: '' }, 'The services could not be listed'));
      status.replaceChildren(notice(r.data.error));
      return;
    }
    const services = r.data.services.slice().sort((a, b) =>
      (b.active === 'failed') - (a.active === 'failed') || a.unit.localeCompare(b.unit));
    select.replaceChildren(...services.map((s) =>
      h('option', { value: s.unit }, s.unit + ' — ' + s.active + (s.sub && s.sub !== s.active ? ' (' + s.sub + ')' : ''))));
  });
  return { select, status };
}

function restartDialog(host) {
  const picker = servicePicker(host);
  openDialog({
    title: 'Restart a service on ' + host.name,
    submitLabel: 'Restart',
    busyLabel: 'Restarting…',
    body: [field('Service', picker.select), picker.status],
    onSubmit: async () => {
      if (!picker.select.value) return 'Pick a service.';
      const r = await api('POST', '/api/hosts/' + host.id + '/restart', { unit: picker.select.value });
      if (!r.ok) return r.data.error;
      route();
      infoDialog(r.data.exit === 0 ? 'Restarted ' + r.data.unit : 'The restart failed',
        h('p', {}, r.data.unit + ' is now ' + r.data.state + '.'),
        r.data.output ? h('pre', { class: 'log log-short' }, r.data.output) : null);
      return null;
    },
  });
}

function logsDialog(host) {
  const picker = servicePicker(host);
  const logs = h('pre', { class: 'log' }, 'Pick a service and press Show logs. The last 200 lines are shown.');
  openDialog({
    title: 'Service logs of ' + host.name,
    submitLabel: 'Show logs',
    busyLabel: 'Reading…',
    wide: true,
    body: [field('Service', picker.select), picker.status, logs],
    onSubmit: async () => {
      if (!picker.select.value) return 'Pick a service.';
      const r = await api('GET', '/api/hosts/' + host.id + '/logs?unit=' + encodeURIComponent(picker.select.value));
      if (!r.ok) return r.data.error;
      logs.textContent = r.data.logs || '(the log is empty)';
      logs.scrollTop = logs.scrollHeight;
      return KEEP_OPEN;
    },
  });
}

function rebootDialog(host) {
  openDialog({
    title: 'Reboot ' + host.name + '?',
    submitLabel: 'Reboot',
    danger: true,
    busyLabel: 'Sending…',
    body: [h('p', {}, 'The host restarts now. Everything running on it stops, and it is unreachable for a minute or more. ' +
      'The dashboard waits for it, and shows it as Rebooting until it answers again.')],
    onSubmit: async () => {
      const r = await api('POST', '/api/hosts/' + host.id + '/reboot');
      if (!r.ok) return r.data.error;
      route();
      return null;
    },
  });
}

function runDialog(host) {
  const command = h('textarea', { class: 'input', rows: '3', spellcheck: 'false', autocapitalize: 'none', required: '', placeholder: 'uptime' });
  const root = h('input', { type: 'checkbox' });
  const timeout = h('select', { class: 'input input-small' },
    [10, 30, 60, 120].map((s) => h('option', { value: String(s), selected: s === 30 }, s + ' seconds')));
  const result = h('div');
  const canRoot = host.user !== 'root' && host.sudo_ok;

  openDialog({
    title: 'Run a command on ' + host.name,
    submitLabel: 'Run',
    busyLabel: 'Running…',
    wide: true,
    body: [
      h('p', { class: 'sub' }, 'It runs in the host\'s shell as ' + host.user + ', exactly as typed. ' +
        'The command is written to History in full, so do not put a password in it.'),
      field('Command', command),
      canRoot ? check(root, 'Run it as root (sudo)') : null,
      field('Stop it after', timeout),
      result,
    ],
    onSubmit: async () => {
      const r = await api('POST', '/api/hosts/' + host.id + '/run', {
        command: command.value, root: canRoot && root.checked, timeout: Number(timeout.value),
      });
      if (!r.ok) return r.data.error;
      const d = r.data;
      result.replaceChildren(
        d.timed_out ? notice('Stopped: it did not finish in ' + d.timeout + ' seconds.') : h('p', { class: 'sub' }, 'Exit code ' + d.exit),
        d.stdout ? [h('div', { class: 'cmd-label' }, 'Output'), h('pre', { class: 'log log-short' }, d.stdout)] : null,
        d.stderr ? [h('div', { class: 'cmd-label' }, 'Error output'), h('pre', { class: 'log log-short' }, d.stderr)] : null,
        d.truncated ? h('p', { class: 'sub' }, 'The output was cut short.') : null);
      return KEEP_OPEN;
    },
  });
}

// ------------------------------------------------------- groups and Ansible

// The sentence that says Ansible is missing, or nothing when it is there. The
// rest of the page works without it.
async function ansibleNotice() {
  const r = await api('GET', '/api/ansible');
  return r.ok && !r.data.installed ? notice(r.data.hint) : null;
}

async function groupsPage(container) {
  const [r, missing] = await Promise.all([api('GET', '/api/groups'), ansibleNotice()]);
  if (!r.ok) {
    container.replaceChildren(pageHead('Groups'), notice(r.data.error));
    return;
  }
  const groups = r.data.groups;
  const add = isAdmin() ? button('Create group', 'btn btn-primary', createGroupDialog) : null;

  container.replaceChildren(
    pageHead('Groups', 'Sets of hosts. A group is what a profile is given to and what an Ansible run is aimed at.', add),
    missing,
    groups.length === 0
      ? h('div', { class: 'empty' },
        h('div', { class: 'name' }, 'No groups yet'),
        h('div', {}, isAdmin() ? 'Create one, such as web, then put hosts in it.' : 'Groups that an admin creates show up here.'),
        add)
      : h('table', {},
        h('thead', {}, h('tr', {}, th('Group'), th('Hosts'), th('', 'col-act'))),
        h('tbody', {}, groups.map((g) => h('tr', {},
          h('td', { class: 'name' }, g.name),
          h('td', {}, g.hosts.length ? g.hosts.map((x) => h('span', { class: 'tag' }, x.name)) : h('span', { class: 'sub' }, 'no hosts')),
          h('td', { class: 'col-act' }, rowMenu([
            canOperate() && { label: isAdmin() ? 'Profile…' : 'See the profile…', run: () => profileDialog({ title: 'Profile of ' + g.name, url: '/api/groups/' + g.id + '/profile', intro: 'The roles every host of this group is configured with.' }) },
            canOperate() && { label: 'Preview…', run: () => previewDialog('group ' + g.name, { group_id: g.id }) },
            canOperate() && { label: 'Apply…', run: () => applyDialog('group ' + g.name, { group_id: g.id }) },
            canOperate() && { label: 'Update packages…', run: () => patchDialog('group ' + g.name, { group_id: g.id }) },
            canOperate() && { label: 'Ping with Ansible', run: () => pingDialog(g.name, { group_id: g.id }) },
            canOperate() && { label: isAdmin() ? 'Variables…' : 'See variables…', run: () => varsDialog({ title: 'Variables of ' + g.name, url: '/api/groups/' + g.id + '/vars' }) },
            isAdmin() && { label: 'Hosts in it…', run: () => membersDialog(g) },
            isAdmin() && { label: 'Rename…', run: () => renameGroupDialog(g) },
            isAdmin() && { label: 'Delete…', danger: true, run: () => deleteGroupDialog(g) },
          ])))))));
}

function createGroupDialog() {
  const name = input({ type: 'text', autocapitalize: 'none', spellcheck: 'false', required: '', placeholder: 'web' });
  openDialog({
    title: 'Create group',
    submitLabel: 'Create',
    body: [field('Name', name, 'Lowercase letters, digits and underscore, starting with a letter. A group and a host cannot have the same name.')],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/groups', { name: name.value });
      if (!message) route();
      return message;
    },
  });
}

function renameGroupDialog(g) {
  const name = input({ type: 'text', value: g.name, autocapitalize: 'none', spellcheck: 'false', required: '' });
  openDialog({
    title: 'Rename ' + g.name,
    submitLabel: 'Rename',
    body: [field('New name', name)],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/groups/' + g.id + '/rename', { name: name.value });
      if (!message) route();
      return message;
    },
  });
}

function deleteGroupDialog(g) {
  openDialog({
    title: 'Delete ' + g.name + '?',
    submitLabel: 'Delete',
    danger: true,
    body: [h('p', {}, 'The group and its variables are removed. The ' + g.hosts.length + ' hosts in it are not touched.')],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/groups/' + g.id + '/delete');
      if (!message) route();
      return message;
    },
  });
}

// Who is in a group: tick the hosts. Several at once, saved together.
function membersDialog(g) {
  const list = h('div', { class: 'choices' }, h('div', { class: 'sub' }, 'Loading the hosts…'));
  let boxes = null; // [{id, box}] once the hosts are loaded
  const members = new Set(g.hosts.map((x) => x.id));

  api('GET', '/api/hosts').then((r) => {
    if (!r.ok) { list.replaceChildren(notice(r.data.error)); return; }
    if (r.data.hosts.length === 0) { list.replaceChildren(emptyText('There are no hosts yet.')); return; }
    boxes = r.data.hosts.map((host) => ({ id: host.id, box: h('input', { type: 'checkbox', checked: members.has(host.id) }) }));
    list.replaceChildren(...r.data.hosts.map((host, i) =>
      check(boxes[i].box, [host.name, h('span', { class: 'sub' }, host.address)])));
  });

  openDialog({
    title: 'Hosts in ' + g.name,
    submitLabel: 'Save',
    body: [list],
    onSubmit: async () => {
      if (!boxes) return 'The hosts are still loading.';
      const add = boxes.filter((b) => b.box.checked && !members.has(b.id)).map((b) => b.id);
      const remove = boxes.filter((b) => !b.box.checked && members.has(b.id)).map((b) => b.id);
      const message = await submitting('POST', '/api/groups/' + g.id + '/hosts', { add, remove });
      if (!message) route();
      return message;
    },
  });
}

// The variables of a group or a host, as a form: a name and a value on each line.
// An operator can read them, an admin can change them.
async function varsDialog({ title, url }) {
  const rows = h('div');
  const editable = isAdmin();
  const addRow = (key, value) => {
    const row = h('div', { class: 'var-row' },
      input({ type: 'text', value: key, placeholder: 'name', autocapitalize: 'none', spellcheck: 'false', disabled: editable ? null : '' }),
      input({ type: 'text', value, placeholder: 'value', spellcheck: 'false', disabled: editable ? null : '' }),
      editable ? iconOnly('Remove this variable', ICON_CLOSE, () => row.remove()) : null);
    rows.append(row);
  };

  const r = await api('GET', url);
  if (!r.ok) {
    infoDialog(title, notice(r.data.error));
    return;
  }
  r.data.vars.forEach((v) => addRow(v.key, v.value));
  if (r.data.vars.length === 0 && !editable) rows.append(emptyText('No variables.'));

  openDialog({
    title,
    submitLabel: editable ? 'Save' : '',
    wide: true,
    body: [
      h('p', { class: 'sub' }, 'They go to Ansible as variables, in the generated group_vars and host_vars files. ' +
        'Whole numbers and true or false are written as such, everything else as text. A host\'s own variables win over its groups\'. ' +
        'To use a secret, write secret:name as the value (the name is on the Secrets page).'),
      rows,
      editable ? button('Add a variable', 'btn btn-small add-var', () => addRow('', '')) : null,
    ],
    onSubmit: async () => {
      const vars = [...rows.querySelectorAll('.var-row')]
        .map((row) => { const [k, v] = row.querySelectorAll('input'); return { key: k.value.trim(), value: v.value }; })
        .filter((v) => v.key !== '' || v.value !== '');
      const message = await submitting('POST', url, { vars });
      if (!message) route();
      return message;
    },
  });
}

// Ping with Ansible: the dashboard's own SSH check proves that it can log in;
// this proves that Ansible can, which is what configuring a host needs.
function pingDialog(label, target) {
  const result = h('div', {}, h('div', { class: 'sub' }, 'Running ansible…'));
  openDialog({ title: 'Ping with Ansible: ' + label, submitLabel: '', wide: true, body: [result] });
  api('POST', '/api/ansible/ping', target).then((r) => {
    if (!r.ok) {
      result.replaceChildren(problem(r.data), ranBlock(r.data.commands));
      return;
    }
    result.replaceChildren(
      r.data.results.length === 0
        ? emptyText('Nothing answered: the group has no hosts.')
        : h('table', {},
          h('thead', {}, h('tr', {}, th('Host'), th('Result'), th('Message'))),
          h('tbody', {}, r.data.results.map((x) => h('tr', {},
            h('td', { class: 'name' }, x.host),
            h('td', {}, h('span', { class: STATUS_CLASS[x.status] || '' }, x.status === 'ok' ? 'pong' : x.status)),
            h('td', { class: 'wrap' }, x.hint || x.message, x.hint ? h('details', { class: 'raw' }, h('summary', {}, 'What Ansible said'), h('pre', { class: 'log log-short' }, x.message)) : null))))),
      ranBlock(r.data.commands));
  });
}

const STATUS_CLASS = { ok: 'st-ok', changed: 'st-changed', failed: 'st-failed', unreachable: 'st-unreachable' };

// A problem from the server: the sentence, and the tool's own text folded under it.
function problem(data) {
  return h('div', { class: 'notice' },
    h('div', {}, data.error),
    data.detail ? h('details', { class: 'raw' }, h('summary', {}, 'What the tool said'), h('pre', { class: 'log log-short' }, data.detail)) : null);
}

// Facts: everything Ansible knows about a host, with a search box.
function factsDialog(host) {
  const body = h('div', {}, h('div', { class: 'sub' }, 'Asking ansible…'));
  openDialog({ title: 'Ansible facts of ' + host.name, submitLabel: '', wide: true, body: [body] });
  api('POST', '/api/ansible/facts', { host_id: host.id }).then((r) => {
    if (!r.ok) {
      body.replaceChildren(problem(r.data), ranBlock(r.data.commands));
      return;
    }
    const useful = Object.entries(r.data.useful);
    const search = input({ type: 'search', placeholder: 'Search the facts, such as ipv4 or kernel', spellcheck: 'false' });
    const table = h('tbody');
    const count = h('div', { class: 'sub' });
    const draw = () => {
      const q = search.value.trim().toLowerCase();
      const hits = r.data.facts.filter(([k, v]) => !q || k.toLowerCase().includes(q) || v.toLowerCase().includes(q));
      table.replaceChildren(...hits.slice(0, 200).map(([k, v]) => h('tr', {}, h('td', { class: 'mono' }, k), h('td', { class: 'mono wrap' }, v))));
      count.textContent = hits.length > 200 ? 'Showing 200 of ' + hits.length + '. Search to narrow it down.' : hits.length + ' facts';
    };
    search.addEventListener('input', draw);
    draw();
    body.replaceChildren(
      useful.length ? h('dl', { class: 'facts' }, useful.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])) : null,
      h('h3', {}, 'All facts'), search, count,
      h('table', {}, h('thead', {}, h('tr', {}, th('Fact'), th('Value'))), table),
      ranBlock(r.data.commands));
  });
}

// View code: the files Ansible reads, as they are. Read-only: they are written
// from the Groups and Hosts pages every time Ansible runs. The roles of the
// library are many files, so they are folded.
async function codePage(container) {
  const [r, missing] = await Promise.all([api('GET', '/api/code'), ansibleNotice()]);
  if (!r.ok) {
    container.replaceChildren(pageHead('Code'), notice(r.data.error));
    return;
  }
  const show = (f) => [h('h3', { class: 'mono' }, f.path), h('pre', { class: 'file' }, f.content)];
  const roles = r.data.files.filter((f) => f.path.startsWith('roles/'));
  const tfFiles = r.data.terraform || [];
  container.replaceChildren(...[
    pageHead('Code', 'The files Ansible and Terraform read, generated from your hosts, groups, profiles and machines. Read-only: change them on their pages.'),
    missing,
    sectionHead('Ansible', 'Inventory, configuration, variables and playbooks.'),
    ...r.data.files.filter((f) => !f.path.startsWith('roles/')).flatMap(show),
    h('details', { class: 'raw' },
      h('summary', {}, 'The roles of the library (' + roles.length + ' files). They come with the dashboard and are the same for everybody.'),
      roles.map(show)),
    ...(tfFiles.length
      ? [
        sectionHead('Terraform', 'Provider, containers and variables. The Proxmox API token secret is kept separately in secrets/proxmox.tfvars.json (0600) and is never shown here.'),
        ...tfFiles.flatMap((f) => show({ path: 'terraform/' + f.path, content: f.content })),
      ]
      : []),
  ].filter(Boolean));
}

// ----------------------------------------------------------------- profiles

// A profile is a list of roles with settings, given to a group or to a host. The
// form is drawn from the library's description of each role; the server checks
// every value again.

let libraryCache = null;

async function getLibrary() {
  if (!libraryCache) {
    const r = await api('GET', '/api/library');
    if (r.ok) libraryCache = r.data.roles;
  }
  return libraryCache || [];
}

// One setting as a form control, and how to read it back.
function paramControl(param, value, editable, secrets) {
  const disabled = editable ? null : '';
  let control;
  // A setting that holds a secret is never typed: it is chosen from the secrets on
  // the Secrets page, and what is kept is only the name (secret:name).
  if (param.secret) {
    const names = new Set(secrets || []);
    if (value && value.startsWith('secret:')) names.add(value.slice(7)); // one that was deleted since still shows
    control = h('select', { class: 'input', disabled },
      h('option', { value: '' }, 'None'),
      [...names].sort().map((n) => h('option', { value: 'secret:' + n, selected: value === 'secret:' + n }, n)));
    const hint = param.help || (names.size === 0 ? 'There are no secrets yet: add one on the Secrets page.' : 'Chosen from the Secrets page.');
    return { control, read: () => control.value, node: field(param.label, control, hint) };
  }
  switch (param.type) {
    case 'bool':
      control = h('input', { type: 'checkbox', checked: value === true, disabled });
      return { control, read: () => control.checked, node: check(control, param.label) };
    case 'choice':
      control = h('select', { class: 'input', disabled },
        param.choices.map((c) => h('option', { value: c, selected: c === value }, c)));
      return { control, read: () => control.value, node: field(param.label, control, param.help) };
    case 'list':
      control = h('textarea', { class: 'input', rows: '3', spellcheck: 'false', disabled });
      control.value = (value || []).join('\n');
      return { control, read: () => control.value.split('\n').map((s) => s.trim()).filter(Boolean), node: field(param.label, control, param.help) };
    default:
      control = input({ type: 'text', value: value == null ? '' : String(value), spellcheck: 'false', autocapitalize: 'none', disabled });
      return { control, read: () => control.value.trim(), node: field(param.label, control, param.help) };
  }
}

async function profileDialog({ title, url, intro }) {
  const [library, current, secretList] = await Promise.all([getLibrary(), api('GET', url), isAdmin() ? api('GET', '/api/secrets') : null]);
  if (!current.ok) {
    infoDialog(title, notice(current.data.error));
    return;
  }
  const editable = isAdmin();
  const secrets = secretList && secretList.ok ? secretList.data.secrets.map((s) => s.name) : [];
  const given = new Map(current.data.roles.map((r) => [r.role, r.params || {}]));

  const sections = library.map((role) => {
    const params = given.get(role.name) || {};
    const controls = role.params.map((p) => ({ param: p, ...paramControl(p, p.key in params ? params[p.key] : p.default, editable, secrets) }));
    const box = h('input', { type: 'checkbox', checked: given.has(role.name), disabled: editable ? null : '' });
    const body = h('div', { class: 'role-params', hidden: !given.has(role.name) }, controls.map((c) => c.node));
    box.addEventListener('change', () => { body.hidden = !box.checked; });
    const node = h('div', { class: 'role-box' },
      check(box, [h('strong', {}, role.title)]),
      h('div', { class: 'sub role-desc' }, role.description),
      body);
    return { role, box, controls, node };
  });

  const inherited = current.data.inherited || [];
  openDialog({
    title,
    submitLabel: editable ? 'Save profile' : '',
    wide: true,
    body: [
      intro ? h('p', { class: 'sub' }, intro) : null,
      inherited.length
        ? notice('It also gets the roles of its groups: ' + inherited.map((g) => g.group + ' (' + g.roles.join(', ') + ')').join('; ') +
          '. What is set here is added to them, and wins where both set the same thing.')
        : null,
      sections.map((s) => s.node),
    ],
    onSubmit: async () => {
      const roles = sections.filter((s) => s.box.checked).map((s) => {
        // Only what differs from the role's default is kept: a setting left alone follows the default.
        const params = {};
        for (const c of s.controls) {
          const value = c.read();
          if (JSON.stringify(value) !== JSON.stringify(c.param.default)) params[c.param.key] = value;
        }
        return { role: s.role.name, params };
      });
      const message = await submitting('POST', url, { roles });
      if (!message) route();
      return message;
    },
  });
}

const CONFIG_TEXT = {
  none: 'No profile',
  never_applied: 'Never applied',
  applied: 'Applied',
  drifted: 'Drifted',
  failed: 'Failed',
  changes_waiting: 'Changes waiting',
  invalid: 'Profile invalid',
};
const CONFIG_CLASS = { applied: 'st-ok', drifted: 'st-changed', failed: 'st-failed', invalid: 'st-failed', changes_waiting: 'st-changed', never_applied: 'sub', none: 'sub' };

// How a host's configuration is, for the Hosts table.
function configCell(host) {
  const c = host.config;
  if (!c || c.state === 'none') return h('span', { class: 'sub' }, '—');
  return h('div', { title: c.detail || null },
    h('span', { class: CONFIG_CLASS[c.state] || '' }, CONFIG_TEXT[c.state] || c.state),
    c.state === 'applied' && c.idempotent === true ? h('span', { class: 'st-ok', title: 'A second run changed nothing' }, ' ✓') : null,
    c.state === 'drifted' ? [' ', button(canOperate() ? 'Fix…' : 'Diff…', 'btn btn-small', () => profileDriftDialog(host.id, host.name, c.drift))] : null,
    h('div', { class: 'sub' }, c.roles.join(', ')));
}

function driftChangesBlock(changes) {
  const byRole = new Map();
  for (const c of (changes || [])) {
    const key = c.role || 'other';
    if (!byRole.has(key)) byRole.set(key, []);
    byRole.get(key).push(c);
  }
  return [...byRole.entries()].map(([role, list]) => h('div', { class: 'preview-role' },
    h('div', { class: 'cmd-label-plain' }, role),
    h('ul', {}, list.map((c) => h('li', {}, c.title,
      c.diff ? h('details', { class: 'raw' }, h('summary', {}, 'Show the file changes'), h('pre', { class: 'file' }, c.diff)) : null)))));
}

function profileDriftDialog(hostID, hostName, changes) {
  let dlg = null;
  const fixBtn = canOperate()
    ? button('Fix ' + hostName + '…', 'btn btn-primary', () => { dlg.close(); applyDialog(hostName, { host_id: hostID }); })
    : null;
  dlg = openDialog({
    title: 'Profile drift on ' + hostName,
    submitLabel: '',
    wide: true,
    body: [
      h('p', { class: 'sub' }, 'Files or settings on ' + hostName + ' were changed outside the dashboard. Applying its profile will put them back.'),
      driftChangesBlock(changes),
      fixBtn ? h('div', { class: 'toolbar' }, fixBtn) : null,
    ],
  });
}

async function runComplianceCheck() {
  const done = toast('Checking host compliance…');
  const r = await api('POST', '/api/compliance/check');
  done();
  if (!r.ok) {
    infoDialog('Compliance check failed', r.data.missing ? notice(r.data.error) : problem(r.data), ranBlock(r.data.commands));
    return;
  }
  const c = r.data.compliance;
  if (c.drifted.length === 0 && (!c.errors || c.errors.length === 0)) {
    infoDialog('Compliance check', h('p', {}, c.checked === 0
      ? 'No hosts with an applied profile to check.'
      : 'All ' + c.checked + ' checked host(s) match their profiles.'), ranBlock(r.data.commands));
  }
  route();
}

// Preview: what would change, host by host, in plain words. The same for the
// profiles, for updating packages, for access and for a custom playbook; opts says
// which: path (what to ask, /api/configure by default), request (more fields of
// the question) and onApply (what the "Apply these changes" button does).
function previewDialog(label, target, role, opts = {}) {
  const path = opts.path || '/api/configure';
  const result = h('div', {}, h('div', { class: 'sub' }, 'Asking Ansible for a dry run. This takes a moment: it logs in to each host and checks every task…'));
  const dlg = openDialog({ title: 'Preview: ' + label, submitLabel: '', wide: true, body: [result] });
  api('POST', path, { mode: 'preview', ...(role ? { role } : {}), ...target, ...(opts.request || {}) }).then((r) => {
    if (!r.ok) {
      result.replaceChildren(
        r.data.missing ? notice(r.data.error) : problem(r.data),
        leftOut(r.data.skipped, r.data.notes),
        ranBlock(r.data.commands));
      return;
    }
    const withChanges = r.data.hosts.filter((x) => x.changes.length > 0).length;
    const applyButton = withChanges > 0 && canOperate()
      ? button('Apply these changes…', 'btn btn-primary', () => { dlg.close(); (opts.onApply || (() => applyDialog(label, target, role)))(); })
      : null;
    result.replaceChildren(
      h('p', { class: 'sub' }, 'Nothing was changed. This is what applying would do right now.'),
      r.data.hosts.map(hostPreviewBlock),
      leftOut(r.data.skipped, r.data.notes),
      ranBlock(r.data.commands),
      applyButton ? h('div', { class: 'toolbar' }, applyButton) : null);
  });
}

// Hosts and roles that were left out, and why.
function leftOut(skipped, notes) {
  const items = [...(skipped || []).map((s) => s.host + ': ' + s.reason), ...(notes || []).map((n) => n.host + ': ' + n.reason)];
  return items.length ? h('div', { class: 'notice' }, h('div', {}, 'Left out:'), h('ul', {}, items.map((i) => h('li', {}, i)))) : null;
}

function hostPreviewBlock(host) {
  const byRole = new Map();
  for (const c of host.changes) {
    const key = c.role || 'other';
    if (!byRole.has(key)) byRole.set(key, []);
    byRole.get(key).push(c);
  }
  return h('div', { class: 'preview-host' },
    h('h3', {}, host.name, ' ', h('span', { class: 'sub' }, host.roles.join(', '))),
    host.down ? h('div', { class: 'notice' }, 'It could not be reached: ' + host.down) : null,
    host.errors.map((e) => h('div', { class: 'notice danger-box' },
      h('strong', {}, e.task), ': ', e.hint || e.message, e.hint && e.message ? h('details', { class: 'raw' }, h('summary', {}, 'What Ansible said'), h('pre', { class: 'log log-short' }, e.message)) : null)),
    host.changes.length === 0 && !host.down && host.errors.length === 0
      ? h('p', {}, h('span', { class: 'st-ok' }, '✓ '), 'Nothing to change: it is already as configured.')
      : [...byRole.entries()].map(([role, changes]) => h('div', { class: 'preview-role' },
        h('div', { class: 'cmd-label-plain' }, role),
        h('ul', {}, changes.map((c) => h('li', {}, c.title,
          c.diff ? h('details', { class: 'raw' }, h('summary', {}, 'Show the file changes'), h('pre', { class: 'file' }, c.diff)) : null))))));
}

// Rolling: how many hosts are done at a time. A run that is rolling stops at the
// first host that fails, and the hosts after it are left exactly as they were.
// allowAll: offer "All at once" (updating packages does not).
const ROLLING_CHOICES = [[0, 'All at once'], [1, 'One at a time'], [2, '2 at a time'], [3, '3 at a time'], [5, '5 at a time'], [10, '10 at a time']];

function rollingSelect(initial, allowAll) {
  const control = h('select', { class: 'input' },
    ROLLING_CHOICES.filter(([n]) => allowAll || n > 0).map(([n, text]) => h('option', { value: String(n), selected: n === initial }, text)));
  return {
    read: () => Number(control.value),
    node: field('Rolling', control, 'Hosts are done this many at a time. It stops at the first host that fails and leaves the rest untouched.'),
  };
}

// Apply: confirm, then a live log, then a recap. opts, as for previewDialog, and:
// title, blurb, submitLabel, runTitle (words for the dialogs), serial (the choice
// to start from) and allowAll (whether "All at once" is offered).
async function applyDialog(label, target, role, opts = {}) {
  const path = opts.path || '/api/configure';
  const base = { ...(role ? { role } : {}), ...target, ...(opts.request || {}) };
  const r = await api('POST', path, { mode: 'plan', ...base });
  if (!r.ok) {
    infoDialog('Apply: ' + label, notice(r.data.error));
    return;
  }
  const hosts = r.data.hosts;
  const rolling = rollingSelect(opts.serial || 0, opts.allowAll !== false);
  let dlg = null;
  dlg = openDialog({
    title: opts.title || 'Apply to ' + label + '?',
    submitLabel: hosts.length ? (opts.submitLabel || 'Apply') : '',
    wide: true,
    body: [
      hosts.length
        ? [h('p', {}, opts.blurb || 'This configures ' + hosts.length + (hosts.length === 1 ? ' host' : ' hosts') + ' now. Every task is safe to run again: a second run changes nothing.'),
          h('table', {}, h('thead', {}, h('tr', {}, th('Host'), th(opts.rolesHead || 'Roles'))),
            h('tbody', {}, hosts.map((x) => h('tr', {}, h('td', { class: 'name' }, x.name), h('td', {}, x.roles.join(', '))))))]
        : emptyText('There is nothing to configure.'),
      hosts.length && opts.rolling !== false && hosts.length > 1 ? rolling.node : null,
      leftOut(r.data.skipped, r.data.notes),
      r.data.commands ? h('div', { class: 'cmd' }, h('div', { class: 'cmd-label' }, 'Will run'), cmdBlock(r.data.commands[1])) : null,
      opts.extra ? opts.extra(() => dlg.close()) : null,
    ],
    onSubmit: async () => {
      logDialog(opts.runTitle || 'Applying to ' + label, { mode: 'apply', ...base, ...(opts.rolling === false ? {} : { serial: hosts.length > 1 ? rolling.read() : 0 }) }, { path });
      return null;
    },
  });
}

// Update packages: always rolling, one host at a time unless a bigger number is
// chosen. It refreshes the package list and installs the pending upgrades safely
// (nothing is removed). Afterwards the hosts that need a reboot are listed, with
// the button for rebooting them one by one.
function patchDialog(label, target) {
  applyDialog(label, target, '', {
    path: '/api/patch',
    serial: 1,
    allowAll: false,
    title: 'Update the packages of ' + label + '?',
    blurb: 'This refreshes the package list and installs the pending upgrades, one host at a time by default. ' +
      'If a host fails, the hosts after it are not touched.',
    rolesHead: 'What',
    submitLabel: 'Update packages',
    runTitle: 'Updating the packages of ' + label,
    // The dry run is one click away from the confirmation, as for the profiles.
    extra: (close) => h('div', { class: 'toolbar' },
      button('Preview first…', 'btn', () => { close(); previewDialog(label, target, '', { path: '/api/patch', onApply: () => patchDialog(label, target) }); })),
  });
}

// Reads a task's progress from a POST. The answer is Server-Sent Events, read by
// hand because EventSource can only GET, and a GET must never start a task.
// Events: plain lines of output, one "result" with the parsed outcome, then
// "done" or "error".
async function streamTask(path, body, onLine, onResult) {
  let resp;
  try {
    resp = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  } catch (err) {
    return { ok: false, error: 'Cannot reach the server.' };
  }
  if (!resp.ok || !resp.body) {
    let data = null;
    try { data = await resp.json(); } catch (err) { /* not JSON */ }
    if (resp.status === 401) sessionEnded();
    return { ok: false, error: (data && data.error) || 'Request failed (HTTP ' + resp.status + ').' };
  }
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let outcome = { ok: false, error: 'The connection closed before the task finished.' };
  for (;;) {
    let chunk;
    try { chunk = await reader.read(); } catch (err) { break; }
    if (chunk.done) break;
    buffer += decoder.decode(chunk.value, { stream: true });
    let end;
    while ((end = buffer.indexOf('\n\n')) >= 0) {
      const frame = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      let event = 'message';
      const data = [];
      for (const line of frame.split('\n')) {
        if (line.startsWith('event: ')) event = line.slice(7);
        else if (line.startsWith('data: ')) data.push(line.slice(6));
      }
      const text = data.join('\n');
      if (event === 'done') outcome = { ok: true };
      else if (event === 'error') outcome = { ok: false, error: text };
      else if (event === 'result') {
        try { onResult(JSON.parse(text)); } catch (err) { /* a broken result is not worth stopping for */ }
      } else onLine(text);
    }
  }
  return outcome;
}

// The window of a run: the live log, and under it the recap. Closing it does not
// stop the run on the server.
// opts: path (what to post to, /api/configure by default), recap (draws the
// result; runRecap by default) and failed (says whether the result has a failure).
function logDialog(title, request, opts = {}) {
  const path = opts.path || '/api/configure';
  const recap = opts.recap || runRecap;
  const hadFailures = opts.failed || ((a) => a.hosts.some((x) => !x.ok && !x.not_reached));
  const status = h('div', { class: 'log-status' }, h('span', { class: 'sub' }, 'Running…'));
  const log = h('pre', { class: 'log' });
  const result = h('div');
  openDialog({ title, submitLabel: '', wide: true, body: [status, log, result] });

  (async () => {
    let answer = null;
    const outcome = await streamTask(path, request,
      (line) => {
        const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
        log.append(line + '\n');
        if (atBottom) log.scrollTop = log.scrollHeight;
      },
      (data) => { answer = data; });

    if (answer) result.replaceChildren(recap(answer, request, path));
    const failed = answer && hadFailures(answer);
    if (!outcome.ok) status.replaceChildren(h('span', { class: 'st-failed' }, outcome.error));
    else status.replaceChildren(h('span', { class: failed ? 'st-failed' : 'st-ok' }, failed ? 'Finished, with failures.' : 'Finished.'));
    route();
  })();
}

// "Reboot one by one" for hosts that need it (the names come from the answer of an
// update): the hosts are found by name, and the order is the order of the list.
async function rebootOneByOneDialog(names) {
  const r = await api('GET', '/api/hosts');
  if (!r.ok) {
    infoDialog('Reboot one by one', notice(r.data.error));
    return;
  }
  const byName = new Map(r.data.hosts.map((x) => [x.name, x]));
  const hosts = names.map((n) => byName.get(n)).filter(Boolean);
  openDialog({
    title: 'Reboot ' + hosts.length + (hosts.length === 1 ? ' host' : ' hosts') + ' one by one?',
    submitLabel: hosts.length ? 'Reboot one by one' : '',
    danger: true,
    wide: true,
    body: [
      h('p', {}, 'They are rebooted in this order, and each one must answer again before the next is touched. ' +
        'If a host does not come back, it stops there and the others are left alone.'),
      h('ol', {}, hosts.map((x) => h('li', {}, x.name))),
    ],
    onSubmit: async () => {
      logDialog('Rebooting one by one', { host_ids: hosts.map((x) => x.id) }, { path: '/api/patch/reboot', recap: rebootRecap, failed: (a) => a.steps.some((s) => !s.ok) });
      return null;
    },
  });
}

function rebootRecap(answer) {
  const left = answer.not_rebooted || [];
  return [
    h('table', {}, h('thead', {}, h('tr', {}, th('Host'), th('Result'), th('What'))),
      h('tbody', {}, answer.steps.map((s) => h('tr', {},
        h('td', { class: 'name' }, s.name),
        h('td', {}, h('span', { class: s.ok ? 'st-ok' : 'st-failed' }, s.ok ? 'Back' : 'Failed')),
        h('td', { class: 'wrap' }, s.detail))))),
    left.length ? notice('Left alone, not rebooted: ' + left.join(', ')) : null,
  ];
}

// After an update: the hosts that now need a reboot, and the way to do it.
function rebootNeeded(answer) {
  const names = answer.reboot_needed || [];
  if (names.length === 0) return null;
  return h('div', { class: 'notice' },
    h('div', {}, names.length + (names.length === 1 ? ' host needs' : ' hosts need') + ' a reboot now: ' + names.join(', ') + '.'),
    canOperate() ? h('div', { class: 'toolbar' }, button('Reboot one by one…', 'btn btn-primary', () => rebootOneByOneDialog(names))) : null);
}

// The recap of a run, as a table, with the verdict of Check again, and the button for it.
function runRecap(answer, request, path) {
  const rows = answer.hosts.map((x) => h('tr', {},
    h('td', { class: 'name' }, x.name),
    h('td', {}, x.not_reached
      ? h('span', { class: 'sub' }, 'Not reached')
      : h('span', { class: x.ok ? 'st-ok' : 'st-failed' }, x.ok ? 'OK' : 'Failed')),
    h('td', {}, x.recap ? String(x.recap.changed) : '—'),
    h('td', { class: 'wrap' }, x.not_reached
      ? 'Left as it was: the run stopped at an earlier host.'
      : x.failure ? x.failure : (x.changed.length ? x.changed.join(', ') : 'Nothing changed'))));

  let verdict = null;
  if (answer.mode === 'check_again') {
    verdict = answer.idempotent
      ? h('div', { class: 'verdict pass' }, h('h3', {}, 'Idempotent ✓'), h('div', {}, 'A second run changed nothing.'))
      : h('div', { class: 'verdict fail' }, h('h3', {}, 'Not idempotent'),
        h('div', {}, 'These tasks changed something again:'), h('ul', {}, (answer.changed_again || []).map((t) => h('li', {}, t))));
  }
  // Check again is for the profiles: a second run of a role must change nothing.
  // Updating packages and access are not meant to be run twice for a verdict.
  const again = answer.mode === 'apply' && answer.hosts.every((x) => x.ok) && (!path || path === '/api/configure')
    ? h('div', { class: 'toolbar' }, button('Check again', 'btn', () => logDialog('Checking again', { ...request, mode: 'check_again' })),
      h('span', { class: 'sub' }, 'Runs it a second time: nothing should change.'))
    : null;
  return [
    h('table', {}, h('thead', {}, h('tr', {}, th('Host'), th('Result'), th('Changed'), th('What'))), h('tbody', {}, rows)),
    answer.not_reached > 0
      ? notice('The run stopped at a failure. ' + answer.not_reached + (answer.not_reached === 1 ? ' host was' : ' hosts were') + ' not touched.')
      : null,
    verdict, leftOut(answer.skipped, answer.notes), rebootNeeded(answer), again,
  ];
}

// ---------------------------------------------------------------- overview

function scheduleTable(sched) {
  const jobs = (sched && sched.jobs) || [];
  return h('table', {},
    h('thead', {}, h('tr', {}, th('Check'), th('Schedule'), th('Last run'), th('Next run'), th('Status', 'col-hide'), th('', 'col-act'))),
    h('tbody', {}, jobs.map((j) => {
      const act = j.id === 'drift' && canOperate() ? button('Check now', 'btn btn-small', runDriftCheck)
        : j.id === 'compliance' && canOperate() ? button('Check now', 'btn btn-small', runComplianceCheck) : null;
      const stCls = j.status === 'ok' ? 'st-ok' : (j.status === 'failed' ? 'st-failed' : 'sub');
      return h('tr', {},
        h('td', { class: 'name' }, j.label),
        h('td', {}, j.enabled ? j.cadence : h('span', { class: 'sub' }, 'Off')),
        h('td', { class: 'num', title: j.last_run ? when(j.last_run) : null }, j.running ? 'Running…' : (j.last_run ? ago(j.last_run) : 'Never')),
        h('td', { class: 'num', title: j.next_run ? when(j.next_run) : null }, j.enabled ? until(j.next_run) : '—'),
        h('td', { class: 'col-hide' }, h('span', { class: stCls }, j.detail || j.status || '—')),
        h('td', { class: 'col-act' }, act));
    })));
}

function nextStepCard(step) {
  let btn = null;
  if (step.action) {
    if (step.fix_host && canOperate()) {
      const name = step.action.replace(/^Fix /, '');
      btn = button(step.action + '…', 'btn btn-primary', () => applyDialog(name, { host_id: step.fix_host }));
    } else if (step.page) {
      btn = h('a', { class: 'btn btn-primary', href: '#/' + step.page }, step.action);
    }
  }
  return h('div', { class: 'next-step' + (step.good ? ' good' : '') },
    h('div', { class: 'next-label' }, step.good ? 'All clear' : 'Next step'),
    h('h2', {}, step.title),
    h('p', {}, step.body),
    step.details && step.details.length
      ? h('ul', { class: 'next-details' }, step.details.map((d) => h('li', {}, d)))
      : null,
    h('div', { class: 'next-actions' }, btn));
}

async function overviewPage(container) {
  const r = await api('GET', '/api/overview');
  if (!r.ok) {
    container.replaceChildren(pageHead('Overview'), notice(r.data.error));
    return;
  }
  const o = r.data;
  const actions = [
    canOperate() && o.hosts > 0 ? button('Check compliance', 'btn', runComplianceCheck) : null,
    canOperate() && o.proxmox_configured ? button('Check Proxmox drift', 'btn', runDriftCheck) : null,
  ];

  const driftRows = [
    ...(o.profile_drift || []).map((d) => h('tr', {},
      h('td', { class: 'name' }, h('a', { href: '#/hosts' }, d.host_name), ' ', h('span', { class: 'tag tag-warn' }, 'profile')),
      h('td', {}, driftChangesBlock(d.changes)),
      h('td', { class: 'col-act' }, canOperate()
        ? button('Fix…', 'btn btn-primary btn-small', () => applyDialog(d.host_name, { host_id: d.host_id }))
        : button('Diff…', 'btn btn-small', () => profileDriftDialog(d.host_id, d.host_name, d.changes))))),
    ...(o.machine_drift || []).map((d) => h('tr', {},
      h('td', { class: 'name' }, h('a', { href: '#/machines' }, d.machine), ' ', h('span', { class: 'tag tag-warn' }, 'proxmox')),
      h('td', {}, d.sentence),
      h('td', { class: 'col-act' }, isAdmin()
        ? button('Put it back…', 'btn btn-small', () => reviewTerraformDialog())
        : h('a', { class: 'btn btn-small', href: '#/machines' }, 'Machines')))),
  ];

  container.replaceChildren(...[
    pageHead('Overview', 'How your hosts and Proxmox machines are doing.', ...actions),
    h('div', { class: 'stats' },
      stat(o.hosts ? (o.online + ' / ' + o.hosts) : '0', 'hosts online', o.hosts === 0 ? '' : (o.online === o.hosts ? 'ok' : 'bad')),
      stat(String(o.config_failed), 'failing config', o.config_failed ? 'bad' : 'ok'),
      stat(String(o.config_drifted), 'drifted from profile', o.config_drifted ? 'warn' : 'ok'),
      stat(String(o.machines_drifted), 'drifted in Proxmox', o.machines_drifted ? 'warn' : 'ok'),
      stat(String(o.with_updates), 'updates waiting', o.with_updates ? 'warn' : 'ok'),
      stat(String(o.need_reboot), 'need a reboot', o.need_reboot ? 'warn' : 'ok')),
    nextStepCard(o.next_step),
    driftRows.length > 0 ? sectionHead('Drift', 'Changes made outside the dashboard on hosts or in Proxmox.') : null,
    driftRows.length > 0 ? h('table', {},
      h('thead', {}, h('tr', {}, th('Target'), th('What changed'), th('', 'col-act'))),
      h('tbody', {}, driftRows)) : null,
    o.attention.length > 0 ? sectionHead('Needs attention') : null,
    o.attention.length > 0 ? h('table', {},
      h('thead', {}, h('tr', {}, th('Host'), th('What'))),
      h('tbody', {}, o.attention.map((a) => h('tr', {},
        h('td', { class: 'name' }, h('a', { href: '#/hosts' }, a.name)),
        h('td', {}, a.issues.map((issue) => h('div', {}, issue))))))) : null,
    sectionHead('Scheduled checks', 'Background checks for host health, Proxmox drift and nightly compliance.',
      isAdmin() ? h('a', { class: 'btn btn-small', href: '#/settings' }, 'Configure in Settings') : null),
    scheduleTable(o.schedule),
    sectionHead('Last runs', 'Recent configuration, package, Terraform and compliance runs.',
      h('a', { class: 'btn btn-small', href: '#/history' }, 'Full history')),
    o.last_runs.length === 0
      ? emptyText('No runs recorded yet.')
      : h('table', {},
        h('thead', {}, h('tr', {}, th('When'), th('What'), th('Target'), th('Result'), th('Detail', 'col-hide'))),
        h('tbody', {}, o.last_runs.map((ev) => h('tr', {},
          h('td', { class: 'num sub', title: when(ev.at) }, ago(ev.at)),
          h('td', {}, ACTION_TEXT[ev.action] || ev.action),
          h('td', { class: 'name' }, ev.target || '—'),
          h('td', {}, h('span', { class: RESULT_CLASS[ev.result] || '' }, ev.result)),
          h('td', { class: 'col-hide sub wrap' }, ev.detail || '—'))))),
  ].filter(Boolean));
}

function trustKeyDialog(host) {
  openDialog({
    title: 'Trust the new key of ' + host.name + '?',
    submitLabel: 'Trust the new key',
    danger: true,
    body: [
      h('p', {}, 'The host shows a different SSH key than the one the dashboard saved. If you reinstalled the machine, that is expected. ' +
        'If you did not, somebody may be pretending to be it: do not trust it.'),
      h('dl', { class: 'facts' },
        h('dt', {}, 'Saved key'), h('dd', { class: 'mono' }, host.host_key_fp || '—'),
        h('dt', {}, 'Key it shows now'), h('dd', { class: 'mono' }, host.presented_fp)),
      h('p', { class: 'sub' }, 'A reinstalled machine has also lost the dashboard\'s login key. After trusting, use Edit and give its password to install the key again.'),
    ],
    onSubmit: async () => {
      const r = await api('POST', '/api/hosts/' + host.id + '/trust-key', { fingerprint: host.presented_fp });
      if (!r.ok) return r.data.error;
      route();
      return null;
    },
  });
}

function removeHostDialog(host) {
  const takeKey = h('input', { type: 'checkbox', checked: true });
  openDialog({
    title: 'Remove ' + host.name + '?',
    submitLabel: 'Remove',
    danger: true,
    busyLabel: 'Removing…',
    body: [
      h('p', {}, 'The dashboard forgets this host. The machine itself is not touched.'),
      check(takeKey, 'Also take the key off the host'),
      h('p', { class: 'hint' }, 'Removes the dashboard\'s key from its authorized_keys' +
        (host.sudo_ok ? ', and the sudo rule the dashboard wrote, if it wrote one' : '') +
        '. If the host cannot be reached, untick this to remove it from the dashboard only.'),
    ],
    onSubmit: async () => {
      const r = await api('POST', '/api/hosts/' + host.id + '/remove', { remove_key: takeKey.checked });
      if (!r.ok) return r.data.error;
      route();
      return null;
    },
  });
}

function renderDiscovery(d) {
  if (!d) return null;
  const nodes = (d.nodes || []).map((n) => n.name + (n.status ? ' (' + n.status + ')' : ''));
  const storages = (d.storages || []).map((s) => s.node + ': ' + s.name + (s.type ? ' (' + s.type + ')' : ''));
  const bridges = (d.bridges || []).map((b) => b.node + ': ' + b.name + (b.cidr ? ' — ' + b.cidr : ''));
  const templates = (d.templates || []).map((t) => t.node + ': ' + t.volid);
  return h('div', { class: 'me-gap' },
    factRows([
      ['Proxmox VE', d.version || '—'],
      ['Checked', when(d.checked_at)],
      ['Nodes', nodes.length ? nodes.join(', ') : 'None found'],
      ['Container storages', storages.length ? storages.join(', ') : 'None with rootdir content'],
      ['Network bridges', bridges.length ? bridges.join(', ') : 'None found'],
      ['Templates', templates.length ? templates.map((t) => h('div', { class: 'mono' }, t)) : 'None found (download a container template in Proxmox)'],
    ]));
}

async function settingsPage(container) {
  const [r, px, schedRes] = await Promise.all([api('GET', '/api/ssh-key'), api('GET', '/api/proxmox'), api('GET', '/api/schedule')]);
  const p = px.ok ? px.data : {};
  const sched = schedRes.ok ? schedRes.data : null;

  const endpoint = input({ type: 'text', value: p.endpoint || '', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', placeholder: 'https://192.168.1.10:8006' });
  const tokenID = input({ type: 'text', value: p.token_id || '', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', placeholder: 'terraform@pve!infra' });
  const tokenSecret = input({ type: 'password', autocomplete: 'new-password', placeholder: p.has_secret ? 'Saved — leave empty to keep it' : 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' });
  const insecure = h('input', { type: 'checkbox', checked: Boolean(p.insecure) });
  const pxStatus = h('div');
  const discBox = h('div', {}, renderDiscovery(p.discovery));

  const saveBtn = button('Save settings', 'btn btn-primary', async () => {
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving…';
    pxStatus.replaceChildren();
    const res = await api('POST', '/api/proxmox', {
      endpoint: endpoint.value, token_id: tokenID.value, token_secret: tokenSecret.value, insecure: insecure.checked,
    });
    tokenSecret.value = '';
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save settings';
    if (!res.ok) {
      pxStatus.replaceChildren(notice(res.data.error));
      return;
    }
    tokenSecret.placeholder = 'Saved — leave empty to keep it';
    pxStatus.replaceChildren(h('div', { class: 'notice ok-box' }, 'Proxmox settings saved.'));
    discBox.replaceChildren(renderDiscovery(res.data.discovery) || '');
  });

  const testBtn = button('Test connection', 'btn', async () => {
    testBtn.disabled = true;
    testBtn.textContent = 'Testing…';
    pxStatus.replaceChildren();
    const res = await api('POST', '/api/proxmox/test', {
      endpoint: endpoint.value, token_id: tokenID.value, token_secret: tokenSecret.value, insecure: insecure.checked,
    });
    testBtn.disabled = false;
    testBtn.textContent = 'Test connection';
    if (!res.ok) {
      pxStatus.replaceChildren(notice(res.data.error));
      return;
    }
    const d = res.data.discovery;
    pxStatus.replaceChildren(h('div', { class: 'notice ok-box' }, 'Connected to Proxmox VE ' + (d.version || '') + '. Discovered ' + (d.nodes || []).length + ' node(s) and ' + (d.templates || []).length + ' template(s).'));
    discBox.replaceChildren(renderDiscovery(d) || '');
  });

  const compEnabled = h('input', { type: 'checkbox', checked: sched ? Boolean(sched.compliance_enabled) : true });
  const compTime = input({ type: 'time', value: (sched && sched.compliance_time) || '03:00', required: '' });
  const schedStatus = h('div');
  const schedTableWrap = h('div', {}, sched ? scheduleTable(sched) : null);
  const saveSchedBtn = button('Save schedule', 'btn btn-primary', async () => {
    saveSchedBtn.disabled = true;
    saveSchedBtn.textContent = 'Saving…';
    schedStatus.replaceChildren();
    const res = await api('POST', '/api/schedule', {
      compliance_time: compTime.value, compliance_enabled: compEnabled.checked,
    });
    saveSchedBtn.disabled = false;
    saveSchedBtn.textContent = 'Save schedule';
    if (!res.ok) {
      schedStatus.replaceChildren(notice(res.data.error));
      return;
    }
    schedStatus.replaceChildren(h('div', { class: 'notice ok-box' }, 'Schedule saved.'));
    schedTableWrap.replaceChildren(scheduleTable(res.data));
  });

  const tfInfo = p.terraform;
  container.replaceChildren(...[
    pageHead('Settings'),
    sectionHead('SSH key', 'The key the dashboard logs in to your hosts with. Its private half never leaves this server.'),
    ...(r.ok
      ? [
        h('dl', { class: 'facts' }, h('dt', {}, 'Fingerprint'), h('dd', { class: 'mono' }, r.data.fingerprint)),
        h('p', { class: 'note' }, 'Public key:'),
        codeBlock(r.data.public_key),
        h('p', { class: 'note' }, 'To give a host this key by hand, run this on it, as the user the dashboard logs in as:'),
        codeBlock(authorizeCommand(r.data.public_key)),
      ]
      : [notice(r.data.error)]),
    sectionHead('Proxmox', 'Connect to your Proxmox VE API so Terraform can create, resize and destroy containers.'),
    ...(px.ok
      ? [
        tfInfo && !tfInfo.installed ? notice(tfInfo.hint) : null,
        tfInfo && tfInfo.installed ? h('p', { class: 'sub' }, tfInfo.version) : null,
        h('div', { class: 'settings-form' },
          field('Endpoint', endpoint, 'The URL of the Proxmox web/API server, usually port 8006.'),
          field('API token ID', tokenID, 'Format: user@realm!tokenname (with permissions to manage containers and storage).'),
          field('API token secret', tokenSecret, 'Write-only: stored in secrets/proxmox.tfvars.json (mode 0600) and never shown again.'),
          check(insecure, 'Allow self-signed TLS certificate'),
          h('div', { class: 'toolbar' }, saveBtn, testBtn)),
        pxStatus,
        discBox,
      ]
      : [notice(px.data.error)]),
    sectionHead('Scheduled checks', 'Health check runs every minute and Proxmox drift every 15 minutes. Set the nightly compliance check time here.'),
    h('div', { class: 'settings-form' },
      check(compEnabled, 'Run nightly compliance check'),
      field('Nightly compliance time (24-hour' + (sched && sched.timezone ? ', ' + sched.timezone : '') + ')', compTime,
        'Runs ansible-playbook --check --diff on every host with an applied profile.'),
      h('div', { class: 'toolbar' }, saveSchedBtn)),
    schedStatus,
    schedTableWrap,
  ].filter(Boolean));
}

// What History's "What" column says for each action the server writes.
const ACTION_TEXT = {
  'login': 'Login',
  'logout': 'Logout',
  'unauthenticated': 'Request without a login',
  'view': 'View',
  'users.manage': 'Manage users',
  'user.create': 'Create user',
  'user.role': 'Change role',
  'user.password.reset': 'Reset password',
  'user.disable': 'Disable user',
  'user.enable': 'Enable user',
  'password.change': 'Change own password',
  'sessions.revoke_others': 'Sign out other sessions',
  'hosts.manage': 'Manage hosts',
  'operate': 'Operate hosts',
  'settings.manage': 'Settings',
  'host.add': 'Add host',
  'host.edit': 'Edit host',
  'host.remove': 'Remove host',
  'host.trust_key': 'Trust new host key',
  'hosts.run': 'Run commands',
  'host.service.restart': 'Restart service',
  'host.service.logs': 'Read service logs',
  'host.reboot': 'Reboot',
  'host.reboot.done': 'Reboot finished',
  'host.run': 'Run a command',
  'groups.manage': 'Manage groups',
  'group.create': 'Create group',
  'group.rename': 'Rename group',
  'group.delete': 'Delete group',
  'group.hosts': 'Change the hosts of a group',
  'group.vars': 'Change the variables of a group',
  'host.vars': 'Change the variables of a host',
  'group.profile': 'Change the profile of a group',
  'host.profile': 'Change the profile of a host',
  'config.apply': 'Apply a profile',
  'config.check_again': 'Check again after an apply',
  'patch.apply': 'Update packages',
  'access.manage': 'Manage access',
  'access.key.add': 'Add an SSH key',
  'access.key.delete': 'Delete an SSH key',
  'access.grant': 'Change where a key may log in',
  'access.apply': 'Give and take away SSH access',
  'access.record': 'Write down which keys are on a host',
  'secrets.manage': 'Manage secrets',
  'secret.set': 'Set a secret',
  'secret.delete': 'Delete a secret',
  'playbooks.manage': 'Manage playbooks',
  'playbook.save': 'Save a playbook',
  'playbook.delete': 'Delete a playbook',
  'playbook.apply': 'Run a playbook',
  'proxmox.settings': 'Change Proxmox settings',
  'machines.manage': 'Manage machines',
  'machine.create': 'Create machine',
  'machine.resize': 'Resize machine',
  'machine.remove': 'Remove machine',
  'machine.cancel': 'Revert machine changes',
  'machine.start': 'Start machine',
  'machine.stop': 'Stop machine',
  'machine.accept_drift': 'Accept Proxmox drift',
  'machine.adopt': 'Adopt Proxmox container',
  'terraform.apply': 'Apply Terraform plan',
  'terraform.restore': 'Restore Terraform state backup',
  'compliance.check': 'Compliance check',
  'schedule.update': 'Change compliance schedule',
};
const RESULT_CLASS = { ok: 'st-ok', refused: 'st-changed', failed: 'st-failed' };

async function historyPage(container) {
  const body = h('tbody');
  const more = button('Load more', 'btn', () => load());
  more.hidden = true;
  const status = h('div');
  let before = 0;

  container.replaceChildren(
    pageHead('History', 'Who did what, and how it ended. Refused attempts are here too.'),
    status,
    h('table', {},
      h('thead', {}, h('tr', {}, th('When'), th('Who'), th('What'), th('Target'), th('Result'), th('Details'))),
      body),
    h('div', { class: 'toolbar' }, more));

  async function load() {
    more.disabled = true;
    const r = await api('GET', '/api/history?limit=50' + (before ? '&before=' + before : ''));
    more.disabled = false;
    if (!r.ok) {
      status.replaceChildren(notice(r.data.error));
      return;
    }
    status.replaceChildren();
    for (const e of r.data.events) {
      body.append(h('tr', {},
        h('td', { class: 'num' }, when(e.at)),
        h('td', { title: e.ip || null }, e.username || h('span', { class: 'sub' }, 'not logged in')),
        h('td', {}, ACTION_TEXT[e.action] || e.action),
        h('td', {}, e.target),
        h('td', {}, h('span', { class: RESULT_CLASS[e.result] || '' }, e.result)),
        h('td', { class: 'wrap sub' }, e.detail)));
      before = e.id;
    }
    more.hidden = !r.data.more;
    if (body.children.length === 0) status.replaceChildren(emptyText('Nothing has happened yet.'));
  }
  await load();
}

const ROLES = ['viewer', 'operator', 'admin'];
const ROLE_HELP = {
  viewer: 'Can look at everything, and change nothing.',
  operator: 'Can also run the everyday actions on hosts.',
  admin: 'Can do everything, including managing users.',
};

function roleSelect(current) {
  return h('select', { class: 'input' },
    ROLES.map((role) => h('option', { value: role, selected: role === current }, role + ' — ' + ROLE_HELP[role])));
}

// Runs a request from a dialog and turns a failure into the sentence to show.
async function submitting(method, path, body) {
  const r = await api(method, path, body);
  return r.ok ? null : r.data.error;
}

async function usersPage(container) {
  const r = await api('GET', '/api/users');
  if (!r.ok) {
    container.replaceChildren(pageHead('Users'), notice(r.data.error));
    return;
  }
  const users = r.data.users;

  const rows = users.map((u) => {
    const isMe = u.id === me.id;
    const base = '/api/users/' + u.id;
    return h('tr', {},
      h('td', { class: 'name' }, u.username, isMe ? h('span', { class: 'tag' }, 'you') : null),
      h('td', {}, u.role),
      h('td', {}, dot(u.disabled ? 'off' : 'ok'), u.disabled ? 'Disabled' : 'Active'),
      h('td', { class: 'sub' }, u.totp_enabled ? 'Enabled' : 'Not set up'),
      h('td', { class: 'num sub' }, when(u.created_at)),
      h('td', { class: 'col-act' }, isMe ? null : rowMenu([
        { label: 'Change role…', run: () => changeRoleDialog(u) },
        { label: 'Reset password…', run: () => resetPasswordDialog(u) },
        { label: 'Reset OTP…', run: () => resetOTPDialog(u) },
        u.disabled
          ? { label: 'Enable', run: async () => { await api('POST', base + '/enable'); route(); } }
          : { label: 'Disable…', danger: true, run: () => disableDialog(u) },
      ])));
  });

  container.replaceChildren(
    pageHead('Users', 'The people who can log in, and what each may do.',
      button('Create user', 'btn btn-primary', createUserDialog)),
    h('table', {},
      h('thead', {}, h('tr', {}, th('Name'), th('Role'), th('Status'), th('OTP'), th('Created'), th('', 'col-act'))),
      h('tbody', {}, rows)));
}

function createUserDialog() {
  const name = input({ type: 'text', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: '' });
  const password = input({ type: 'password', autocomplete: 'new-password', required: '' });
  const role = roleSelect('viewer');
  openDialog({
    title: 'Create user',
    submitLabel: 'Create',
    body: [
      field('User name', name, 'Lowercase letters, digits, dot, dash or underscore.'),
      field('Password', password, 'At least 10 characters. Tell them to change it on their Profile page.'),
      field('Role', role),
    ],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/users', { username: name.value, password: password.value, role: role.value });
      if (!message) route();
      return message;
    },
  });
}

function changeRoleDialog(u) {
  const role = roleSelect(u.role);
  openDialog({
    title: 'Change role of ' + u.username,
    submitLabel: 'Change role',
    body: [field('Role', role)],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/users/' + u.id + '/role', { role: role.value });
      if (!message) route();
      return message;
    },
  });
}

function resetPasswordDialog(u) {
  const password = input({ type: 'password', autocomplete: 'new-password', required: '' });
  openDialog({
    title: 'Reset the password of ' + u.username,
    submitLabel: 'Reset password',
    body: [
      h('p', {}, 'They are signed out everywhere at once, and log in with the new password.'),
      field('New password', password, 'At least 10 characters.'),
    ],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/users/' + u.id + '/password', { password: password.value });
      if (!message) route();
      return message;
    },
  });
}

function resetOTPDialog(u) {
  openDialog({
    title: 'Reset authenticator for ' + u.username + '?',
    submitLabel: 'Reset OTP',
    danger: true,
    body: [h('p', {}, 'They are signed out everywhere at once and must set up a new authenticator app on their next login.')],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/users/' + u.id + '/totp-reset');
      if (!message) route();
      return message;
    },
  });
}

function disableDialog(u) {
  openDialog({
    title: 'Disable ' + u.username + '?',
    submitLabel: 'Disable',
    danger: true,
    body: [h('p', {}, 'They are signed out at once and cannot log in until you enable them again. Their History stays.')],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/users/' + u.id + '/disable');
      if (!message) route();
      return message;
    },
  });
}

async function profilePage(container) {
  const r = await api('GET', '/api/me/sessions');
  const sessions = r.ok ? r.data.sessions : [];

  const others = sessions.filter((s) => !s.current).length;
  const signOutOthers = button('Sign out everywhere else', 'btn', async () => {
    signOutOthers.disabled = true;
    await api('POST', '/api/me/sessions/revoke-others');
    route();
  });
  signOutOthers.disabled = others === 0;

  container.replaceChildren(
    pageHead('Profile'),
    h('dl', { class: 'facts' },
      h('dt', {}, 'User name'), h('dd', {}, me.username),
      h('dt', {}, 'Role'), h('dd', {}, me.role, h('span', { class: 'sub' }, ' — ' + ROLE_HELP[me.role])),
      h('dt', {}, 'Password'), h('dd', {}, button('Change password…', 'btn btn-small', changePasswordDialog)),
      h('dt', {}, 'Two-factor authentication'), h('dd', {},
        me.totp_enabled ? 'Enabled (TOTP)' : 'Not set up',
        me.totp_enabled ? button('Reset authenticator…', 'btn btn-small', resetMyTOTPDialog) : null)),
    sectionHead('Sessions', 'Where you are logged in. A session ends after seven days.', signOutOthers),
    r.ok
      ? h('table', {},
        h('thead', {}, h('tr', {}, th('Signed in'), th('Last used'), th('From'), th('Browser'))),
        h('tbody', {}, sessions.map((s) => h('tr', {},
          h('td', { class: 'num' }, when(s.created_at), s.current ? h('span', { class: 'tag' }, 'this one') : null),
          h('td', { class: 'num' }, when(s.last_used_at)),
          h('td', {}, s.ip),
          h('td', { class: 'wrap sub', title: s.user_agent }, s.user_agent.slice(0, 60))))))
      : notice(r.data.error));
}

function changePasswordDialog() {
  const current = input({ type: 'password', autocomplete: 'current-password', required: '' });
  const next = input({ type: 'password', autocomplete: 'new-password', required: '' });
  const again = input({ type: 'password', autocomplete: 'new-password', required: '' });
  openDialog({
    title: 'Change your password',
    submitLabel: 'Change password',
    body: [
      field('Current password', current),
      field('New password', next, 'At least 10 characters.'),
      field('New password again', again),
    ],
    onSubmit: async () => {
      if (next.value !== again.value) return 'The two new passwords are not the same.';
      const r = await api('POST', '/api/me/password', { current: current.value, new: next.value });
      if (!r.ok) return r.data.error;
      route();
      return null;
    },
  });
}

function resetMyTOTPDialog() {
  const password = input({ type: 'password', autocomplete: 'current-password', required: '' });
  const code = input({ type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '8', placeholder: '123456', required: '' });
  openDialog({
    title: 'Reset your authenticator',
    submitLabel: 'Reset authenticator',
    danger: true,
    body: [
      h('p', {}, 'This signs you out everywhere and clears your current authenticator key. You will set up a new authenticator on your next login.'),
      field('Current password', password),
      field('Current one-time code', code, 'Enter the 6-digit code from your current authenticator app.'),
    ],
    onSubmit: async () => {
      const r = await api('POST', '/api/me/totp/reset', { password: password.value, code: code.value });
      if (!r.ok) return r.data.error;
      showLogin('Your authenticator was reset. Log in to set up a new one.');
      return null;
    },
  });
}

// ------------------------------------------------------------------ access

// People's SSH public keys, and the groups and hosts each may log in to. Giving
// access is two steps on purpose: what a key may reach is written down first, and
// Apply puts the keys on the hosts (after a Preview). Revoke takes one key off
// every host it was put on, in one go. A public key is not a secret.

// The start and the end of a key, enough to tell two apart.
function shortKey(key) {
  const [type, body] = key.split(' ');
  return type + ' ' + (body && body.length > 24 ? body.slice(0, 14) + '…' + body.slice(-8) : body || '');
}

function applyAccessDialog() {
  applyDialog('access', {}, '', {
    path: '/api/access/apply',
    rolling: false,
    title: 'Give and take away SSH access?',
    blurb: 'This puts the keys that were given on these hosts and takes off the ones that were taken away. Nobody else\'s keys are touched.',
    rolesHead: 'What',
    submitLabel: 'Apply',
    runTitle: 'Giving and taking away SSH access',
  });
}

function previewAccess() {
  previewDialog('access', {}, '', { path: '/api/access/apply', onApply: applyAccessDialog });
}

async function accessPage(container) {
  const [r, groups, hosts, missing] = await Promise.all([api('GET', '/api/access'), api('GET', '/api/groups'), api('GET', '/api/hosts'), ansibleNotice()]);
  if (!r.ok) {
    container.replaceChildren(pageHead('Access'), notice(r.data.error));
    return;
  }
  const groupList = groups.ok ? groups.data.groups : [];
  const hostList = hosts.ok ? hosts.data.hosts : [];
  const groupName = new Map(groupList.map((g) => [g.id, g.name]));
  const hostName = new Map(hostList.map((x) => [x.id, x.name]));
  const { keys, pending } = r.data;

  const pendingBox = pending.length === 0 ? null : h('div', { class: 'notice' },
    h('div', {}, 'Waiting to be applied (nothing has been done on these hosts yet):'),
    h('ul', {}, pending.map((p) => h('li', {}, h('strong', {}, p.host), ': ',
      [p.add.length ? 'give ' + p.add.join(', ') : null, p.remove.length ? 'take away ' + p.remove.join(', ') : null].filter(Boolean).join('; ')))),
    h('div', { class: 'toolbar' }, button('Preview…', 'btn', previewAccess), button('Apply…', 'btn btn-primary', applyAccessDialog)));

  const add = button('Add a key', 'btn btn-primary', addKeyDialog);
  container.replaceChildren(
    pageHead('Access', 'Who may log in to which hosts over SSH. Add a person\'s public key, say where it may log in, then apply.', add),
    missing,
    pendingBox,
    keys.length === 0
      ? h('div', { class: 'empty' },
        h('div', { class: 'name' }, 'No keys yet'),
        h('div', {}, 'Add a teammate\'s public key (the line from their id_ed25519.pub), then give it a group.'),
        add)
      : h('table', {},
        h('thead', {}, h('tr', {}, th('Name'), th('Account', 'col-hide'), th('Key', 'col-hide'), th('May log in to'), th('Is on'), th('', 'col-act'))),
        h('tbody', {}, keys.map((k) => h('tr', {},
          h('td', { class: 'name' }, k.name),
          h('td', { class: 'col-hide' }, k.user || h('span', { class: 'sub', title: 'The user the dashboard logs in as on each host' }, 'login user')),
          h('td', { class: 'col-hide mono sub', title: k.public_key }, shortKey(k.public_key)),
          h('td', {}, k.group_ids.length + k.host_ids.length === 0
            ? h('span', { class: 'sub' }, 'nowhere')
            : [...k.group_ids.map((id) => h('span', { class: 'tag' }, 'group ' + (groupName.get(id) || id))),
              ...k.host_ids.map((id) => h('span', { class: 'tag' }, hostName.get(id) || id))]),
          h('td', {}, k.installed.length ? k.installed.map((n) => h('span', { class: 'tag' }, n)) : h('span', { class: 'sub' }, 'no host')),
          h('td', { class: 'col-act' }, rowMenu([
            { label: 'Where it may log in…', run: () => grantsDialog(k, groupList, hostList) },
            { label: 'Revoke everywhere…', danger: true, run: () => revokeKeyDialog(k) },
            { label: 'Delete…', danger: true, run: () => deleteKeyDialog(k) },
          ])))))));
}

function addKeyDialog() {
  const name = input({ type: 'text', autocomplete: 'off', spellcheck: 'false', required: '', placeholder: 'Dewi' });
  const key = h('textarea', { class: 'input', rows: '3', spellcheck: 'false', required: '', placeholder: 'ssh-ed25519 AAAA… dewi@laptop' });
  const user = input({ type: 'text', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', placeholder: 'the login user of each host' });
  openDialog({
    title: 'Add a key',
    submitLabel: 'Add',
    wide: true,
    body: [
      field('Whose key', name, 'Shown in this list and in the log of a run.'),
      field('Public key', key, 'One line, as in authorized_keys. Only a public key: never paste a private one.'),
      field('Account on the hosts (optional)', user, 'Which user the person logs in as. Empty: the user the dashboard logs in as on each host.'),
    ],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/access/keys', { name: name.value, public_key: key.value, user: user.value });
      if (!message) route();
      return message;
    },
  });
}

function grantsDialog(k, groups, hosts) {
  const gBoxes = groups.map((g) => ({ id: g.id, box: h('input', { type: 'checkbox', checked: k.group_ids.includes(g.id) }), g }));
  const hBoxes = hosts.map((x) => ({ id: x.id, box: h('input', { type: 'checkbox', checked: k.host_ids.includes(x.id) }), x }));
  openDialog({
    title: 'Where ' + k.name + ' may log in',
    submitLabel: 'Save',
    body: [
      h('p', { class: 'sub' }, 'Saving writes this down and changes no host. Use Apply on the Access page to put the key there.'),
      h('div', { class: 'cmd-label-plain' }, 'Groups'),
      h('div', { class: 'choices' }, gBoxes.length
        ? gBoxes.map((b) => check(b.box, [b.g.name, h('span', { class: 'sub' }, b.g.hosts.length + ' hosts')]))
        : emptyText('There are no groups.')),
      h('div', { class: 'cmd-label-plain' }, 'Single hosts'),
      h('div', { class: 'choices' }, hBoxes.length
        ? hBoxes.map((b) => check(b.box, [b.x.name, h('span', { class: 'sub' }, b.x.address)]))
        : emptyText('There are no hosts.')),
    ],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/access/keys/' + k.id + '/grants', {
        group_ids: gBoxes.filter((b) => b.box.checked).map((b) => b.id),
        host_ids: hBoxes.filter((b) => b.box.checked).map((b) => b.id),
      });
      if (!message) route();
      return message;
    },
  });
}

function revokeKeyDialog(k) {
  openDialog({
    title: 'Revoke ' + k.name + ' everywhere?',
    submitLabel: 'Revoke everywhere',
    danger: true,
    body: [
      h('p', {}, 'The key of ' + k.name + ' is taken off ' + (k.installed.length ? k.installed.join(', ') : 'every host it was put on') + ' now, and everything it was given is removed. ' +
        'It stays on the list without any access, so it can be given again.'),
    ],
    onSubmit: async () => {
      logDialog('Revoking ' + k.name, {}, { path: '/api/access/keys/' + k.id + '/revoke' });
      return null;
    },
  });
}

function deleteKeyDialog(k) {
  openDialog({
    title: 'Delete the key of ' + k.name + '?',
    submitLabel: 'Delete',
    danger: true,
    body: [h('p', {}, 'The key is forgotten. If it is still on hosts, the next Apply takes it off them; Revoke everywhere does that at once.')],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/access/keys/' + k.id + '/delete');
      if (!message) route();
      return message;
    },
  });
}

// ----------------------------------------------------------------- secrets

// Passwords and tokens that a role or a variable can use. Write-only: the value
// is typed once, kept encrypted (ansible-vault), and cannot be shown again, by
// this page or by anything else. Setting it again replaces it.

async function secretsPage(container) {
  const r = await api('GET', '/api/secrets');
  if (!r.ok) {
    container.replaceChildren(pageHead('Secrets'), notice(r.data.error));
    return;
  }
  const secrets = r.data.secrets;
  const add = button('Add a secret', 'btn btn-primary', () => secretDialog(null));
  container.replaceChildren(
    pageHead('Secrets', 'Passwords and tokens for roles and variables. A value is typed once and kept encrypted: it can never be shown again, only replaced.', add),
    secrets.length === 0
      ? h('div', { class: 'empty' },
        h('div', { class: 'name' }, 'No secrets yet'),
        h('div', {}, 'Add one, then choose it in a role\'s settings, or write secret:name as the value of a variable.'),
        add)
      : h('table', {},
        h('thead', {}, h('tr', {}, th('Name'), th('Set'), th('Used by'), th('', 'col-act'))),
        h('tbody', {}, secrets.map((s) => h('tr', {},
          h('td', { class: 'name mono' }, s.name),
          h('td', { class: 'num sub' }, when(s.updated_at)),
          h('td', {}, s.used_by.length ? s.used_by.map((u) => h('div', {}, u)) : h('span', { class: 'sub' }, 'nothing')),
          h('td', { class: 'col-act' }, rowMenu([
            { label: 'Set a new value…', run: () => secretDialog(s) },
            { label: 'Delete…', danger: true, run: () => deleteSecretDialog(s) },
          ])))))));
}

function secretDialog(existing) {
  const name = input({ type: 'text', value: existing ? existing.name : '', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: '', placeholder: 'db_password', readonly: existing ? '' : null });
  const value = input({ type: 'password', autocomplete: 'new-password', required: '' });
  openDialog({
    title: existing ? 'New value for ' + existing.name : 'Add a secret',
    submitLabel: 'Save',
    body: [
      field('Name', name, 'Lowercase letters, digits and underscore. Roles and variables refer to it by this name.'),
      field('Value', value, 'One line. It is encrypted at once and cannot be read back. ' +
        (existing ? 'The roles that use it will show "Changes waiting" until they are applied again.' : '')),
    ],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/secrets', { name: name.value.trim(), value: value.value });
      value.value = '';
      if (!message) route();
      return message;
    },
  });
}

function deleteSecretDialog(s) {
  openDialog({
    title: 'Delete ' + s.name + '?',
    submitLabel: 'Delete',
    danger: true,
    body: [h('p', {}, s.used_by.length
      ? 'It is still used by ' + s.used_by.join('; ') + '. Change those first: it cannot be deleted while something uses it.'
      : 'The secret is deleted. Nothing uses it.')],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/secrets/' + encodeURIComponent(s.name) + '/delete');
      if (!message) route();
      return message;
    },
  });
}

// --------------------------------------------------------------- playbooks

// Ansible written by hand, for what the library does not cover. A playbook is
// checked with ansible-playbook --syntax-check before it is saved, and run like
// anything else: Preview first, then Run. It runs as root on the hosts, so it is
// an admin's.

async function playbooksPage(container) {
  const [r, missing] = await Promise.all([api('GET', '/api/playbooks'), ansibleNotice()]);
  if (!r.ok) {
    container.replaceChildren(pageHead('Playbooks'), notice(r.data.error));
    return;
  }
  const list = r.data.playbooks;
  const add = button('New playbook', 'btn btn-primary', () => playbookDialog(''));
  container.replaceChildren(
    pageHead('Playbooks', 'Your own Ansible playbooks. They are checked when saved and run against a group or a host, with a Preview first.', add),
    missing,
    list.length === 0
      ? h('div', { class: 'empty' },
        h('div', { class: 'name' }, 'No playbooks yet'),
        h('div', {}, 'Write one for what the roles do not cover.'),
        add)
      : h('table', {},
        h('thead', {}, h('tr', {}, th('Name'), th('Saved'), th('', 'col-act'))),
        h('tbody', {}, list.map((p) => h('tr', {},
          h('td', { class: 'name mono' }, p.name),
          h('td', { class: 'num sub' }, when(p.updated_at)),
          h('td', { class: 'col-act' }, rowMenu([
            { label: 'Run on…', run: () => runPlaybookDialog(p.name) },
            { label: 'Edit…', run: () => playbookDialog(p.name) },
            { label: 'Delete…', danger: true, run: () => deletePlaybookDialog(p.name) },
          ])))))));
}

const PLAYBOOK_START = '- name: What this playbook does\n  hosts: all\n  become: true\n  tasks:\n    - name: A first task\n      ansible.builtin.debug:\n        msg: hello\n';

async function playbookDialog(name) {
  let text = PLAYBOOK_START;
  if (name) {
    const r = await api('GET', '/api/playbooks/' + encodeURIComponent(name));
    if (!r.ok) {
      infoDialog('Edit ' + name, notice(r.data.error));
      return;
    }
    text = r.data.content;
  }
  const nameBox = input({ type: 'text', value: name, autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: '', placeholder: 'tune-kernel', readonly: name ? '' : null });
  const editor = h('textarea', { class: 'input editor', rows: '20', spellcheck: 'false', autocapitalize: 'none', wrap: 'off' });
  editor.value = text;
  const detail = h('pre', { class: 'log log-short', hidden: true });
  openDialog({
    title: name ? 'Edit ' + name : 'New playbook',
    submitLabel: 'Check and save',
    busyLabel: 'Checking…',
    wide: true,
    body: [
      field('Name', nameBox, 'Lowercase letters, digits, dash and underscore.'),
      field('Playbook (YAML)', editor, 'It is saved only if ansible-playbook --syntax-check accepts it. Use no_log: true on a task that handles a secret.'),
      detail,
    ],
    onSubmit: async () => {
      detail.hidden = true;
      const r = await api('POST', '/api/playbooks', { name: nameBox.value.trim(), content: editor.value });
      if (r.ok) {
        route();
        return null;
      }
      if (r.data.detail) {
        detail.textContent = r.data.detail;
        detail.hidden = false;
      }
      return r.data.error;
    },
  });
}

function deletePlaybookDialog(name) {
  openDialog({
    title: 'Delete ' + name + '?',
    submitLabel: 'Delete',
    danger: true,
    body: [h('p', {}, 'The playbook is deleted. Hosts are not touched.')],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/playbooks/' + encodeURIComponent(name) + '/delete');
      if (!message) route();
      return message;
    },
  });
}

// Pick a group or a host; then a Preview, from which it can be run.
async function runPlaybookDialog(name) {
  const [groups, hosts] = await Promise.all([api('GET', '/api/groups'), api('GET', '/api/hosts')]);
  if (!groups.ok || !hosts.ok) {
    infoDialog('Run ' + name, notice((groups.ok ? hosts : groups).data.error));
    return;
  }
  const where = h('select', { class: 'input' },
    h('optgroup', { label: 'Groups' }, groups.data.groups.map((g) => h('option', { value: 'g' + g.id }, g.name + ' (' + g.hosts.length + ' hosts)'))),
    h('optgroup', { label: 'Hosts' }, hosts.data.hosts.map((x) => h('option', { value: 'h' + x.id }, x.name))));
  openDialog({
    title: 'Run ' + name,
    submitLabel: 'Preview',
    busyLabel: 'Opening…',
    body: [
      field('On', where),
      h('p', { class: 'sub' }, 'The Preview is a dry run: it shows what would change and changes nothing. You can run it from there.'),
    ],
    onSubmit: async () => {
      const kind = where.value[0];
      const id = Number(where.value.slice(1));
      const target = kind === 'g' ? { group_id: id } : { host_id: id };
      const label = name + ' on ' + (kind === 'g' ? 'group ' : 'host ') + where.selectedOptions[0].textContent.replace(/ \(\d+ hosts\)$/, '');
      const path = '/api/playbooks/' + encodeURIComponent(name) + '/run';
      previewDialog(label, target, '', {
        path,
        onApply: () => applyDialog(label, target, '', {
          path, rolling: false, rolesHead: 'What', title: 'Run ' + name + '?', submitLabel: 'Run', runTitle: 'Running ' + name,
          blurb: 'This runs the playbook ' + name + ' now. A playbook is not checked for being safe to run twice.',
        }),
      });
      return null;
    },
  });
}

// --------------------------------------------------------------- machines

// Proxmox containers managed by Terraform (IM7). Desired state lives in the
// database; Review changes runs `terraform plan -out` and Apply applies that
// exact saved plan once, within 15 minutes.

const MACHINE_STATUS = {
  running: { dot: 'ok', text: 'Running' },
  stopped: { dot: 'off', text: 'Stopped' },
  will_be_created: { dot: 'warn', text: 'Will be created' },
  will_change: { dot: 'warn', text: 'Will change' },
  will_be_removed: { dot: 'bad', text: 'Will be removed' },
  unknown: { dot: 'off', text: 'Unknown' },
};

const MACHINE_PRESETS = [
  { id: 'small', label: 'Small — 1 CPU, 512 MB RAM, 8 GB disk', cores: 1, memory_mb: 512, disk_gb: 8 },
  { id: 'medium', label: 'Medium — 2 CPU, 2 GB RAM, 16 GB disk', cores: 2, memory_mb: 2048, disk_gb: 16 },
  { id: 'large', label: 'Large — 4 CPU, 4 GB RAM, 32 GB disk', cores: 4, memory_mb: 4096, disk_gb: 32 },
];

function sizeSummary(s) {
  const mem = s.memory_mb >= 1024 && s.memory_mb % 1024 === 0 ? (s.memory_mb / 1024) + ' GB' : s.memory_mb + ' MB';
  return s.cores + ' CPU · ' + mem + ' · ' + s.disk_gb + ' GB';
}

async function machinesPage(container) {
  const r = await api('GET', '/api/machines');
  if (!r.ok) {
    container.replaceChildren(pageHead('Machines'), notice(r.data.error));
    return;
  }
  const { machines, configured, has_pending, proxmox_error, terraform, drift } = r.data;
  const hasApplied = machines.some((m) => m.applied_at > 0);
  const createBtn = isAdmin() && configured ? button('Create machine', has_pending ? 'btn' : 'btn btn-primary', createMachineDialog) : null;
  const reviewBtn = isAdmin() && configured && !has_pending && machines.length > 0
    ? button('Review changes…', 'btn', () => reviewTerraformDialog()) : null;
  const driftBtn = canOperate() && configured && hasApplied
    ? button('Check drift', 'btn', runDriftCheck) : null;
  const moreMenu = isAdmin() && configured
    ? rowMenu([
      { label: 'Adopt container…', run: adoptMachineDialog },
      { label: 'State backups…', run: stateBackupsDialog },
    ], 'More machine actions') : null;

  const banner = isAdmin() && configured && has_pending
    ? h('div', { class: 'banner waiting' },
      h('div', {}, h('strong', {}, 'Unapplied changes. '), 'Review the Terraform plan before anything changes in Proxmox.'),
      button('Review changes…', 'btn btn-primary', () => reviewTerraformDialog()))
    : null;

  const byName = new Map(machines.map((m) => [m.name, m]));
  const driftBox = drift && drift.items && drift.items.length > 0
    ? h('div', { class: 'notice' },
      h('div', {}, h('strong', {}, 'Drift detected in Proxmox'), ' ', h('span', { class: 'sub' }, '(checked ' + ago(drift.checked_at) + ')')),
      h('ul', {}, drift.items.map((item) => {
        const m = byName.get(item.machine);
        return h('li', {}, item.sentence, ' ',
          isAdmin() ? button('Put it back…', 'btn btn-small', () => reviewTerraformDialog()) : null, ' ',
          isAdmin() && m && item.action !== 'destroy' ? button('Accept', 'btn btn-small', () => acceptMachineDrift(m)) : null);
      })))
    : null;

  let body;
  if (!configured && machines.length === 0) {
    body = h('div', { class: 'empty' },
      h('div', { class: 'name' }, 'Proxmox is not connected yet'),
      h('div', {}, isAdmin() ? 'Add your Proxmox endpoint and API token in Settings to create containers.' : 'An admin has to configure Proxmox in Settings first.'),
      isAdmin() ? h('a', { class: 'btn btn-primary', href: '#/settings' }, 'Go to Settings') : null);
  } else if (machines.length === 0) {
    body = h('div', { class: 'empty' },
      h('div', { class: 'name' }, 'No machines yet'),
      h('div', {}, isAdmin() ? 'Create a Proxmox container, or adopt an existing one from the ⋯ menu.' : 'Proxmox containers created by an admin show up here.'),
      createBtn);
  } else {
    body = h('table', {},
      h('thead', {}, h('tr', {}, th('Name'), th('Node', 'col-hide'), th('Size'), th('Address'), th('Groups', 'col-hide'), th('Status'), th('Host', 'col-hide'), th('', 'col-act'))),
      h('tbody', {}, machines.map(machineRow)));
  }

  container.replaceChildren(...[
    pageHead('Machines', 'Proxmox containers managed by Terraform. Created machines appear on Hosts automatically.', driftBtn, reviewBtn, createBtn, moreMenu),
    terraform && !terraform.installed ? notice(terraform.hint) : null,
    proxmox_error ? notice('Could not read live status from Proxmox: ' + proxmox_error) : null,
    driftBox,
    banner,
    body,
  ].filter(Boolean));
}

async function runDriftCheck() {
  const done = toast('Checking Proxmox for drift…');
  const r = await api('POST', '/api/terraform/drift');
  done();
  if (!r.ok) {
    infoDialog('Drift check failed', notice(r.data.error));
    return;
  }
  const n = (r.data.drift && r.data.drift.items || []).length;
  if (n === 0) infoDialog('Drift check', h('p', {}, 'No drift found: Proxmox matches the dashboard.'), ranBlock(r.data.commands));
  route();
}

async function acceptMachineDrift(m) {
  const done = toast('Accepting drift for ' + m.name + '…');
  const r = await api('POST', '/api/machines/' + m.id + '/accept-drift');
  done();
  if (!r.ok) infoDialog('Accept drift', notice(r.data.error));
  route();
}

function machineRow(m) {
  const st = MACHINE_STATUS[m.status] || MACHINE_STATUS.unknown;
  const realNote = (m.status === 'will_change' || m.status === 'will_be_removed') && (m.real_status === 'running' || m.real_status === 'stopped')
    ? h('div', { class: 'sub' }, 'currently ' + m.real_status) : null;
  const addrPrimary = m.ip_resolved || (m.ip_mode === 'static' ? m.ip_cidr.split('/')[0] : 'DHCP');
  const hostStatus = m.host_status ? (STATUS[m.host_status] || STATUS.unknown) : null;

  return h('tr', {},
    h('td', { class: 'name' }, m.name, m.vm_id ? h('div', { class: 'sub num' }, 'VM ' + m.vm_id) : null),
    h('td', { class: 'col-hide' }, m.node),
    h('td', { class: 'num' }, sizeSummary(m)),
    h('td', { class: 'num' }, addrPrimary, m.ip_mode === 'dhcp' && m.ip_resolved ? h('div', { class: 'sub' }, 'DHCP') : null),
    h('td', { class: 'col-hide' }, m.groups.length ? m.groups.map((g) => h('span', { class: 'tag' }, g)) : h('span', { class: 'sub' }, '—')),
    h('td', {}, dot(st.dot), st.text, realNote),
    h('td', { class: 'col-hide' }, m.host_id
      ? h('a', { href: '#/hosts' }, hostStatus ? dot(hostStatus.dot) : null, m.host_name || m.name)
      : h('span', { class: 'sub' }, '—')),
    h('td', { class: 'col-act' }, rowMenu([
      canOperate() && m.applied_at > 0 && m.vm_id > 0 && m.real_status === 'stopped' && { label: 'Start', run: () => powerMachine(m, 'start') },
      canOperate() && m.applied_at > 0 && m.vm_id > 0 && m.real_status === 'running' && { label: 'Stop', danger: true, run: () => powerMachine(m, 'stop') },
      isAdmin() && !m.pending_delete && { label: 'Resize…', run: () => resizeMachineDialog(m) },
      isAdmin() && m.applied_at > 0 && !m.pending_delete && { label: 'Rebuild…', danger: true, run: () => rebuildMachineDialog(m) },
      isAdmin() && (m.status === 'will_change' || m.pending_delete) && { label: m.pending_delete ? 'Cancel removal' : 'Revert changes', run: () => cancelMachineChange(m) },
      isAdmin() && !m.pending_delete && { label: m.applied_at === 0 ? 'Discard…' : 'Remove…', danger: true, run: () => removeMachineDialog(m) },
    ])));
}

async function powerMachine(m, action) {
  const done = toast((action === 'start' ? 'Starting ' : 'Stopping ') + m.name + '…');
  const r = await api('POST', '/api/machines/' + m.id + '/' + action);
  done();
  if (!r.ok) infoDialog((action === 'start' ? 'Start ' : 'Stop ') + m.name, notice(r.data.error));
  route();
}

async function cancelMachineChange(m) {
  const r = await api('POST', '/api/machines/' + m.id + '/cancel');
  if (!r.ok) infoDialog('Revert ' + m.name, notice(r.data.error));
  route();
}

function sizeControls(initial) {
  const match = MACHINE_PRESETS.find((p) => p.cores === initial.cores && p.memory_mb === initial.memory_mb && p.disk_gb === initial.disk_gb);
  const preset = h('select', { class: 'input' },
    MACHINE_PRESETS.map((p) => h('option', { value: p.id, selected: match && match.id === p.id }, p.label)),
    h('option', { value: 'custom', selected: !match }, 'Custom'));
  const cores = input({ type: 'number', value: String(initial.cores), min: '1', max: '64', required: '' });
  const memory = input({ type: 'number', value: String(initial.memory_mb), min: '128', max: '262144', step: '128', required: '' });
  const disk = input({ type: 'number', value: String(initial.disk_gb), min: '2', max: '4096', required: '' });

  preset.addEventListener('change', () => {
    const p = MACHINE_PRESETS.find((x) => x.id === preset.value);
    if (!p) return;
    cores.value = String(p.cores);
    memory.value = String(p.memory_mb);
    disk.value = String(p.disk_gb);
  });
  for (const box of [cores, memory, disk]) {
    box.addEventListener('input', () => {
      const m = MACHINE_PRESETS.find((p) => p.cores === Number(cores.value) && p.memory_mb === Number(memory.value) && p.disk_gb === Number(disk.value));
      preset.value = m ? m.id : 'custom';
    });
  }
  return {
    read: () => ({ cores: Number(cores.value), memory_mb: Number(memory.value), disk_gb: Number(disk.value) }),
    nodes: [
      field('Size', preset),
      h('div', { class: 'row three' }, field('CPU cores', cores), field('Memory (MB)', memory), field('Disk (GB)', disk)),
    ],
  };
}

function selectOrInput(options, placeholder) {
  return options.length > 0
    ? h('select', { class: 'input' }, options.map((o) => h('option', { value: o.value }, o.label)))
    : input({ type: 'text', placeholder, autocapitalize: 'none', spellcheck: 'false', required: '' });
}

async function createMachineDialog() {
  const [px, groupsRes] = await Promise.all([api('GET', '/api/proxmox'), api('GET', '/api/groups')]);
  if (!px.ok) {
    infoDialog('Create machine', notice(px.data.error));
    return;
  }
  const disc = px.data.discovery || {};
  const nodes = (disc.nodes || []).map((n) => ({ value: n.name, label: n.name + (n.status ? ' (' + n.status + ')' : '') }));
  const groups = groupsRes.ok ? groupsRes.data.groups : [];

  const name = input({ type: 'text', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: '', placeholder: 'web-1' });
  const size = sizeControls(MACHINE_PRESETS[0]);
  const nodeCtrl = selectOrInput(nodes, 'pve');
  const storageWrap = h('div'), bridgeWrap = h('div'), templateWrap = h('div');
  let storageCtrl, bridgeCtrl, templateCtrl;

  function fillNodeLists() {
    const n = nodeCtrl.value;
    storageCtrl = selectOrInput((disc.storages || []).filter((s) => !n || s.node === n).map((s) => ({ value: s.name, label: s.name + (s.type ? ' (' + s.type + ')' : '') })), 'local-lvm');
    bridgeCtrl = selectOrInput((disc.bridges || []).filter((b) => !n || b.node === n).map((b) => ({ value: b.name, label: b.name + (b.cidr ? ' — ' + b.cidr : '') })), 'vmbr0');
    templateCtrl = selectOrInput((disc.templates || []).filter((t) => !n || t.node === n).map((t) => ({ value: t.volid, label: t.volid })), 'local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst');
    storageWrap.replaceChildren(field('Storage', storageCtrl));
    bridgeWrap.replaceChildren(field('Network bridge', bridgeCtrl));
    templateWrap.replaceChildren(field('Template', templateCtrl, 'Debian or Ubuntu LXC template on the chosen node.'));
  }
  fillNodeLists();
  if (nodeCtrl.tagName === 'SELECT') nodeCtrl.addEventListener('change', fillNodeLists);

  const ipMode = h('select', { class: 'input' }, h('option', { value: 'static' }, 'Static IPv4'), h('option', { value: 'dhcp' }, 'DHCP'));
  const ipCIDR = input({ type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: '192.168.1.50/24', required: '' });
  const gateway = input({ type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: '192.168.1.1' });
  const staticFields = h('div', { class: 'row' }, field('IP address / prefix', ipCIDR), field('Gateway (optional)', gateway));
  ipMode.addEventListener('change', () => {
    staticFields.hidden = ipMode.value !== 'static';
    ipCIDR.required = ipMode.value === 'static';
  });

  const groupBoxes = groups.map((g) => ({ id: g.id, box: h('input', { type: 'checkbox' }), g }));
  const autoCfg = h('input', { type: 'checkbox', checked: true });

  openDialog({
    title: 'Create machine',
    submitLabel: 'Save and review changes',
    busyLabel: 'Saving…',
    wide: true,
    body: [
      !disc.checked_at ? notice('Run "Test connection" in Settings → Proxmox to fill the node, storage, bridge and template lists.') : null,
      field('Name', name, 'Lowercase letters, digits and hyphens (for example web-1). Also used as the host name.'),
      size.nodes,
      h('div', { class: 'row' }, field('Node', nodeCtrl), storageWrap),
      h('div', { class: 'row' }, bridgeWrap, field('IP address', ipMode)),
      staticFields,
      templateWrap,
      groups.length
        ? [h('div', { class: 'cmd-label-plain' }, 'Groups'), h('div', { class: 'choices' }, groupBoxes.map((b) => check(b.box, [b.g.name, h('span', { class: 'sub' }, b.g.hosts.length + ' hosts')])))]
        : h('p', { class: 'sub' }, 'No groups yet. You can assign groups later.'),
      check(autoCfg, 'Configure it after creation'),
      h('p', { class: 'hint' }, 'Applies its groups\' profile once the container is created and online.'),
    ],
    onSubmit: async () => {
      const r = await api('POST', '/api/machines', {
        name: name.value.trim(), node: nodeCtrl.value.trim(), ...size.read(),
        storage: storageCtrl.value.trim(), bridge: bridgeCtrl.value.trim(), template: templateCtrl.value.trim(),
        ip_mode: ipMode.value, ip_cidr: ipMode.value === 'static' ? ipCIDR.value.trim() : '',
        gateway: ipMode.value === 'static' ? gateway.value.trim() : '',
        auto_configure: autoCfg.checked, group_ids: groupBoxes.filter((b) => b.box.checked).map((b) => b.id),
      });
      if (!r.ok) return r.data.error;
      route();
      reviewTerraformDialog();
      return null;
    },
  });
}

function resizeMachineDialog(m) {
  const size = sizeControls(m);
  openDialog({
    title: 'Resize ' + m.name,
    submitLabel: 'Save and review changes',
    busyLabel: 'Saving…',
    body: [
      h('p', { class: 'sub' }, 'After saving, Terraform previews whether this change happens in place or destroys and recreates the container.'),
      size.nodes,
    ],
    onSubmit: async () => {
      const message = await submitting('POST', '/api/machines/' + m.id + '/resize', size.read());
      if (message) return message;
      route();
      reviewTerraformDialog();
      return null;
    },
  });
}

function removeMachineDialog(m) {
  const neverCreated = m.applied_at === 0;
  openDialog({
    title: (neverCreated ? 'Discard ' : 'Remove ') + m.name + '?',
    submitLabel: neverCreated ? 'Discard' : 'Mark for removal and review',
    danger: true,
    body: [h('p', {}, neverCreated
      ? 'This machine has not been created on Proxmox yet. Discarding removes it immediately.'
      : 'This marks ' + m.name + ' for removal. Next, Terraform will show a plan destroying only ' + m.name + ' and removing its host.')],
    onSubmit: async () => {
      const r = await api('POST', '/api/machines/' + m.id + '/remove');
      if (!r.ok) return r.data.error;
      route();
      if (!r.data.deleted) reviewTerraformDialog();
      return null;
    },
  });
}

function rebuildMachineDialog(m) {
  openDialog({
    title: 'Rebuild ' + m.name + '?',
    submitLabel: 'Review rebuild',
    danger: true,
    body: [h('p', {}, 'Terraform will destroy ' + m.name + ' and create a fresh container with the same name and IP. ' +
      'Its new SSH host key will be trusted automatically (audited) and its profile applied again. Any unsaved data inside the container is lost.')],
    onSubmit: async () => {
      reviewTerraformDialog({ replace: m.name });
      return null;
    },
  });
}

function tfRecap(answer) {
  const items = [
    ['Created', answer.created], ['Changed in place', answer.updated], ['Recreated', answer.replaced],
    ['Destroyed', answer.destroyed], ['Added as hosts', answer.hosts_added], ['Configured', answer.configured],
  ].filter(([, list]) => list && list.length).map(([label, list]) => [label, list.join(', ')]);
  return h('div', {}, items.length ? factRows(items) : null, (answer.warnings || []).map((w) => notice(w)));
}

function planChangesTable(changes) {
  return h('table', { class: 'me-gap' },
    h('thead', {}, h('tr', {}, th('Machine'), th('Change'), th('Details'))),
    h('tbody', {}, changes.map((c) => h('tr', {},
      h('td', { class: 'name' }, c.machine),
      h('td', {}, h('span', { class: 'act act-' + c.action }, c.plain_action), c.reason ? h('div', { class: 'sub' }, c.reason) : null),
      h('td', {}, c.attributes.length
        ? h('details', { class: 'attrs' },
          h('summary', {}, c.attributes.length + (c.attributes.length === 1 ? ' attribute' : ' attributes')),
          h('table', { class: 'attrs-table' }, h('tbody', {}, c.attributes.map((a) => h('tr', {},
            h('td', {}, a.path),
            h('td', { class: a.sensitive && a.before === '(sensitive)' ? 'attr-hidden' : (a.before ? 'attr-before' : 'sub') }, a.before || '—'),
            h('td', { class: 'sub' }, '→'),
            h('td', { class: a.sensitive || a.unknown ? 'attr-hidden' : (a.after ? 'attr-after' : 'sub') }, a.after || '—'))))))
        : h('span', { class: 'sub' }, '—'))))));
}

function reviewTerraformDialog(reqBody) {
  const body = h('div', {}, h('div', { class: 'sub' }, 'Running terraform plan (and initializing providers if needed). This may take a moment…'));
  const dlg = openDialog({ title: reqBody && reqBody.replace ? 'Review rebuild: ' + reqBody.replace : 'Review changes', submitLabel: '', wide: true, body: [body] });
  api('POST', '/api/terraform/plan', reqBody).then((r) => {
    if (!r.ok) {
      body.replaceChildren(...[r.data.missing ? notice(r.data.error) : problem(r.data), ranBlock(r.data.commands)].filter(Boolean));
      return;
    }
    const { plan, plain_summary, changes, applicable, commands } = r.data;
    const destructive = (plan.summary.replace || 0) > 0 || (plan.summary.destroy || 0) > 0;
    const applyBtn = applicable && isAdmin()
      ? button(destructive ? 'Apply (destroys containers)' : 'Apply this plan', destructive ? 'btn btn-danger' : 'btn btn-primary', () => {
        dlg.close();
        logDialog('Applying Terraform plan', { plan_id: plan.id }, { path: '/api/terraform/apply', recap: tfRecap, failed: (a) => Boolean(a.error) });
      }) : null;

    body.replaceChildren(h('div', {},
      h('div', { class: 'review-head' }, h('p', { class: 'plan-summary' }, plain_summary), applyBtn),
      destructive ? h('div', { class: 'notice danger-box' }, 'Warning: this plan will destroy or recreate containers. Data inside a destroyed container is lost.') : null,
      changes.length > 0 ? planChangesTable(changes) : h('p', { class: 'sub' }, 'Everything in Proxmox already matches the desired machines.'),
      applicable ? h('p', { class: 'sub' }, 'Only this exact saved plan is applied, once, within 15 minutes.') : null,
      ranBlock(commands)));
  });
}

async function adoptMachineDialog() {
  const [px, groupsRes] = await Promise.all([api('GET', '/api/proxmox'), api('GET', '/api/groups')]);
  if (!px.ok) {
    infoDialog('Adopt container', notice(px.data.error));
    return;
  }
  const disc = px.data.discovery || {};
  const nodes = (disc.nodes || []).map((n) => ({ value: n.name, label: n.name + (n.status ? ' (' + n.status + ')' : '') }));
  const groups = groupsRes.ok ? groupsRes.data.groups : [];

  const nodeCtrl = selectOrInput(nodes, 'pve');
  const vmid = input({ type: 'number', min: '100', required: '', placeholder: '105' });
  const name = input({ type: 'text', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: '', placeholder: 'praktikum' });
  const size = sizeControls(MACHINE_PRESETS[0]);
  const storageWrap = h('div'), bridgeWrap = h('div'), templateWrap = h('div');
  let storageCtrl, bridgeCtrl, templateCtrl;

  function fillNodeLists() {
    const n = nodeCtrl.value;
    storageCtrl = selectOrInput((disc.storages || []).filter((s) => !n || s.node === n).map((s) => ({ value: s.name, label: s.name + (s.type ? ' (' + s.type + ')' : '') })), 'local-lvm');
    bridgeCtrl = selectOrInput((disc.bridges || []).filter((b) => !n || b.node === n).map((b) => ({ value: b.name, label: b.name + (b.cidr ? ' — ' + b.cidr : '') })), 'vmbr0');
    templateCtrl = selectOrInput((disc.templates || []).filter((t) => !n || t.node === n).map((t) => ({ value: t.volid, label: t.volid })), 'local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst');
    storageWrap.replaceChildren(field('Storage', storageCtrl));
    bridgeWrap.replaceChildren(field('Network bridge', bridgeCtrl));
    templateWrap.replaceChildren(field('Template (for OS type)', templateCtrl));
  }
  fillNodeLists();
  if (nodeCtrl.tagName === 'SELECT') nodeCtrl.addEventListener('change', fillNodeLists);

  const ipMode = h('select', { class: 'input' }, h('option', { value: 'static' }, 'Static IPv4'), h('option', { value: 'dhcp' }, 'DHCP'));
  const ipCIDR = input({ type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: '192.168.1.50/24', required: '' });
  const gateway = input({ type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: '192.168.1.1' });
  const staticRow = h('div', { class: 'row' }, field('IP address / prefix', ipCIDR), field('Gateway (optional)', gateway));
  ipMode.addEventListener('change', () => {
    staticRow.hidden = ipMode.value !== 'static';
    ipCIDR.required = ipMode.value === 'static';
  });
  const groupBoxes = groups.map((g) => ({ id: g.id, box: h('input', { type: 'checkbox' }), g }));
  const preview = h('div');

  let dlg = null;
  dlg = openDialog({
    title: 'Adopt a Proxmox container',
    submitLabel: 'Check for adoption',
    busyLabel: 'Checking…',
    wide: true,
    body: [
      h('p', { class: 'sub' }, 'Imports a hand-made container into Terraform state. Enter its Proxmox node, VM ID and current settings; the review must show no changes before Adopt is allowed.'),
      h('div', { class: 'row three' }, field('Node', nodeCtrl), field('VM ID', vmid), field('Name', name)),
      size.nodes,
      h('div', { class: 'row' }, storageWrap, bridgeWrap),
      h('div', { class: 'row' }, field('IP address', ipMode), templateWrap),
      staticRow,
      groups.length ? [h('div', { class: 'cmd-label-plain' }, 'Groups'), h('div', { class: 'choices' }, groupBoxes.map((b) => check(b.box, b.g.name)))] : null,
      preview,
    ],
    onSubmit: async () => {
      preview.replaceChildren();
      const r = await api('POST', '/api/machines/adopt/preview', {
        node: nodeCtrl.value.trim(), vmid: Number(vmid.value), name: name.value.trim(), ...size.read(),
        storage: storageCtrl.value.trim(), bridge: bridgeCtrl.value.trim(), template: templateCtrl.value.trim(),
        ip_mode: ipMode.value, ip_cidr: ipMode.value === 'static' ? ipCIDR.value.trim() : '',
        gateway: ipMode.value === 'static' ? gateway.value.trim() : '',
        group_ids: groupBoxes.filter((b) => b.box.checked).map((b) => b.id),
      });
      if (!r.ok) {
        if (r.data.detail || r.data.commands) {
          preview.replaceChildren(...[problem(r.data), ranBlock(r.data.commands)].filter(Boolean));
          return KEEP_OPEN;
        }
        return r.data.error;
      }
      if (!r.data.ready) {
        preview.replaceChildren(h('div', {},
          notice(r.data.plain_summary),
          planChangesTable(r.data.changes || []),
          ranBlock(r.data.commands)));
        return KEEP_OPEN;
      }
      const adoptBtn = button('Adopt ' + name.value.trim(), 'btn btn-primary', () => {
        dlg.close();
        logDialog('Adopting ' + name.value.trim(), { plan_id: r.data.plan_id }, { path: '/api/terraform/apply', recap: tfRecap, failed: (a) => Boolean(a.error) });
      });
      preview.replaceChildren(h('div', {},
        h('div', { class: 'notice ok-box' }, r.data.plain_summary),
        h('div', { class: 'toolbar' }, adoptBtn),
        ranBlock(r.data.commands)));
      return KEEP_OPEN;
    },
  });
}

async function stateBackupsDialog() {
  const r = await api('GET', '/api/terraform/backups');
  if (!r.ok) {
    infoDialog('State backups', notice(r.data.error));
    return;
  }
  const backups = r.data.backups;
  const preview = h('div');
  let dlg = null;

  async function previewBackup(b) {
    preview.replaceChildren(h('div', { class: 'sub' }, 'Running terraform plan against backup ' + b.id + '…'));
    const pr = await api('POST', '/api/terraform/backups/' + encodeURIComponent(b.id) + '/preview');
    if (!pr.ok) {
      preview.replaceChildren(problem(pr.data));
      return;
    }
    const restoreBtn = button('Restore ' + b.id, 'btn btn-danger', async () => {
      restoreBtn.disabled = true;
      restoreBtn.textContent = 'Restoring…';
      const rr = await api('POST', '/api/terraform/backups/' + encodeURIComponent(b.id) + '/restore');
      if (!rr.ok) {
        preview.replaceChildren(notice(rr.data.error));
        return;
      }
      dlg.close();
      infoDialog('State restored', h('p', {}, 'Restored ' + b.id + '. The previous state was backed up first.'));
      route();
    });
    preview.replaceChildren(h('div', {},
      h('div', { class: 'dialog-group' },
        h('div', { class: 'review-head' }, h('p', { class: 'plan-summary' }, 'Restoring ' + b.id + ' would lead to: ' + pr.data.plain_summary), restoreBtn),
        pr.data.changes && pr.data.changes.length ? planChangesTable(pr.data.changes) : h('p', { class: 'sub' }, 'No differences from current desired machines.'),
        ranBlock(pr.data.commands))));
  }

  dlg = openDialog({
    title: 'Terraform state backups',
    submitLabel: '',
    wide: true,
    body: [
      h('p', { class: 'sub' }, 'Taken automatically before every apply (kept 30 deep). Previewing a backup shows the plan it would lead to without changing the live state.'),
      backups.length === 0
        ? emptyText('No state backups yet. The first backup is created before your second apply.')
        : h('table', {},
          h('thead', {}, h('tr', {}, th('Backup'), th('Taken'), th('Size'), th('', 'col-act'))),
          h('tbody', {}, backups.map((b) => h('tr', {},
            h('td', { class: 'mono' }, b.id),
            h('td', { class: 'num' }, when(b.created_at)),
            h('td', { class: 'num sub' }, b.size + ' B'),
            h('td', { class: 'col-act' }, button('Preview restore…', 'btn btn-small', () => previewBackup(b))))))),
      preview,
    ],
  });
}

// ------------------------------------------------------------------- shell

const ICON_MACHINES = 'M8 2l5.5 3v6L8 14l-5.5-3V5zM8 8l5.5-3M8 8v6M8 8L2.5 5';
const ICON_ACCESS = 'M5.5 10.5a3 3 0 1 0 0-.01M7.7 8.3L14 2M12 4l1.5 1.5M10 6l1.5 1.5';
const ICON_SECRETS = 'M4 7.5h8v6H4zM5.5 7.5V5.5a2.5 2.5 0 0 1 5 0v2';
const ICON_PLAYBOOKS = 'M4 2.5h8v11H4zM6 5.5h4M6 8h4M6 10.5h2.5';
const ICON_OVERVIEW = 'M2.5 2.5h4.5v4.5H2.5zM9 2.5h4.5v4.5H9zM2.5 9h4.5v4.5H2.5zM9 9h4.5v4.5H9z';
const ICON_GROUPS = 'M2.5 4.5h11v8h-11zM2.5 4.5l1.5-2h3l1 2';
const ICON_CODE = 'M5.5 4.5l-3 3.5 3 3.5M10.5 4.5l3 3.5-3 3.5M9 3.5l-2 9';

// refresh: the page draws itself again every 15 seconds while nothing is being
// done on it, because what it shows changes by itself (the check every minute,
// a reboot finishing).
const pages = [
  { id: 'overview', title: 'Overview', icon: ICON_OVERVIEW, render: overviewPage, refresh: true },
  { id: 'hosts', title: 'Hosts', icon: ICON_HOSTS, render: hostsPage, refresh: true },
  { id: 'machines', title: 'Machines', icon: ICON_MACHINES, render: machinesPage, refresh: true },
  { id: 'groups', title: 'Groups', icon: ICON_GROUPS, render: groupsPage },
  { id: 'access', title: 'Access', icon: ICON_ACCESS, render: accessPage, adminOnly: true },
  { id: 'secrets', title: 'Secrets', icon: ICON_SECRETS, render: secretsPage, adminOnly: true },
  { id: 'playbooks', title: 'Playbooks', icon: ICON_PLAYBOOKS, render: playbooksPage, adminOnly: true },
  { id: 'code', title: 'Code', icon: ICON_CODE, render: codePage, operatorOnly: true },
  { id: 'history', title: 'History', icon: ICON_HISTORY, render: historyPage },
  { id: 'users', title: 'Users', icon: ICON_USERS, render: usersPage, adminOnly: true },
  { id: 'settings', title: 'Settings', icon: ICON_SETTINGS, render: settingsPage, adminOnly: true },
  { id: 'profile', title: 'Profile', icon: ICON_PROFILE, render: profilePage },
];

function visiblePages() {
  return pages.filter((p) => (!p.adminOnly || isAdmin()) && (!p.operatorOnly || canOperate()));
}

function currentPage() {
  const id = location.hash.replace(/^#\/?/, '');
  return visiblePages().find((p) => p.id === id) || pages[0];
}

let drawing = 0; // a page that finishes loading after another was opened must not draw

// Pages draw into a spare element first and are swapped in when they are
// complete, so a reload (after a dialog) does not flash an empty page.
async function route() {
  clearTimeout(refreshTimer);
  if (!me) return;
  closeMenu();
  const page = currentPage();
  nav.querySelectorAll('a').forEach((a) => a.classList.toggle('active', a.dataset.page === page.id));
  const ticket = ++drawing;
  const container = h('div');
  await page.render(container);
  if (ticket === drawing && me) {
    view.replaceChildren(...container.childNodes);
    if (page.refresh) scheduleRefresh();
  }
}

let refreshTimer = null;

// Draws the page again in 15 seconds, unless a menu or a dialog is open (it
// would close under the person's hands), in which case it asks again later.
function scheduleRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    if (openMenu || document.querySelector('dialog[open]')) scheduleRefresh();
    else route();
  }, 15000);
}

function showApp() {
  document.body.classList.remove('logged-out');
  nav.replaceChildren(...visiblePages().map((p) =>
    h('a', { href: '#/' + p.id, 'data-page': p.id }, icon(p.icon), p.title)));

  const signOut = button('Sign out', 'btn btn-small', async () => {
    await api('POST', '/api/logout');
    showLogin();
  });
  applyCommandsSwitch();
  document.getElementById('sidebar-foot').replaceChildren(
    commandsSwitch(),
    h('div', { class: 'me-line me-gap' }, me.username),
    h('div', { class: 'sub' }, me.role),
    h('div', { class: 'me-out' }, signOut));
  route();
}

window.addEventListener('hashchange', route);

(async function start() {
  const r = await api('GET', '/api/me');
  if (r.ok) {
    me = r.data;
    showApp();
  } else {
    showLogin();
  }
})();
