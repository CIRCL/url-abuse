// Home page: checks a URL with the API v2 (doc/api/v2.md).
// POST /api/v2/analyse starts the analysis, then GET /api/v2/analyse/<uuid> is
// polled: the server sends the whole state each time, and the page updates the
// rows that changed (keyed by URL, IP and provider). Everything that comes from
// the checked site or a provider is inserted as text.
(function () {
  'use strict';

  var POLL_EVERY_MS = 1000;
  var GIVE_UP_AFTER_MS = 5 * 60 * 1000;
  var API = 'api/v2/';

  var $ = function (id) { return document.getElementById(id); };

  var els = {
    body: document.body,
    form: $('lookup'),
    input: $('url'),
    hint: $('form-hint'),
    report: $('report'),
    caption: $('subject-caption'),
    subject: $('subject-url'),
    track: $('progress-track'),
    progressText: $('progress-text'),
    verdict: $('verdict'),
    actions: $('actions'),
    send: $('send-report'),
    lookyloo: $('lookyloo'),
    lookylooWait: $('lookyloo-wait'),
    again: $('new-check'),
    chain: $('chain'),
    tplHop: $('tpl-hop'),
    tplHost: $('tpl-host'),
    submit: document.querySelector('#lookup button[type=submit]'),
    working: $('working'),
    workingTitle: $('working-title'),
    workingDetail: $('working-detail'),
    workingTime: $('working-time')
  };

  // One run per submitted URL. Answers for an older run are dropped.
  var run = null;

  /* ---------- Small DOM helpers ---------- */

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'text') node.textContent = attrs[k];
        else if (k === 'class') node.className = attrs[k];
        else node.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      if (c == null) return;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function safeLink(href, label) {
    if (typeof href !== 'string' || !/^https?:\/\//i.test(href)) return null;
    return el('a', { href: href, target: '_blank', rel: 'noopener', text: label });
  }

  function list(items) {
    return el('ul', null, items.map(function (t) { return el('li', { text: String(t) }); }));
  }

  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

  function wait(ms) { return new Promise(function (res) { setTimeout(res, ms); }); }

  function api(method, path, body) {
    return fetch(API + path, {
      method: method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) {
          var err = new Error(data.message || ('HTTP ' + r.status));
          err.status = r.status;
          throw err;
        }
        return data;
      });
    });
  }

  /* ---------- Reading each provider's answer ---------- */

  // A reader turns the data of an "ok" answer into { state, text, extra }.
  // state: ok | bad | warn | info | none. One reader per provider name; a
  // provider without a reader is shown as "Data found" / "Nothing returned".
  var readers = {
    dns: function (d) {
      var all = (d.ipv4 || []).length + (d.ipv6 || []).length;
      if (!all) return { state: 'none', text: "The host doesn't resolve" };
      return { state: 'info', text: plural(all, 'address', 'addresses') + ' below' };
    },

    bgpranking: function (d, links) {
      if (!d || !d.asn) return { state: 'none', text: 'No routing data' };
      var lines = ['AS' + d.asn + ', prefix ' + d.prefix];
      var state = 'info';
      if (d.position) {
        lines.push('Position ' + d.position + ' of ' + d.total_known_asns + ' in BGP Ranking');
        if (d.position < 100) state = 'bad';
        else if (d.position < 1000) state = 'warn';
      }
      var extra = list(lines);
      var link = safeLink(links[0], 'BGP Ranking');
      if (link) extra.appendChild(el('li', null, [link]));
      return { state: state, text: d.asn_description || ('AS' + d.asn), extra: extra };
    }
  };

  function read(name, result) {
    if (result.status === 'pending') return { state: 'pending', text: 'Waiting for an answer' };
    if (result.status === 'error') return { state: 'none', text: 'This check failed on the server' };
    if (readers[name]) return readers[name](result.data, result.links || []);
    if (result.data == null) return { state: 'none', text: 'Nothing returned' };
    return { state: 'info', text: 'Data found' };
  }

  /* ---------- Rendering an analysis ---------- */

  function hopLabel(i, n, searching) {
    if (n === 1) return searching ? 'Looking for redirects…' : 'No redirects';
    if (i === 0) return 'Where the link starts';
    if (i === n - 1) return 'Where it ends up';
    return 'Redirect';
  }

  // Rows and progress segments are created once and updated in place.
  function rowFor(view, key, rows, label) {
    if (!view.rows[key]) {
      var dt = el('dt', { text: label });
      var val = el('span', { class: 'val' });
      var dd = el('dd', { 'data-state': 'pending' }, [el('span', { class: 'status-dot' }), val]);
      rows.appendChild(dt);
      rows.appendChild(dd);
      view.rows[key] = { dd: dd, val: val, shown: null };
    }
    return view.rows[key];
  }

  function groupFor(view, key) {
    if (!view.groups[key]) {
      var node = el('div', { class: 'seg-group' });
      els.track.appendChild(node);
      view.groups[key] = { node: node, segs: {} };
    }
    return view.groups[key];
  }

  function segFor(group, name) {
    if (!group.segs[name]) {
      group.segs[name] = el('span', { class: 'seg', 'data-state': 'pending' });
      group.node.appendChild(group.segs[name]);
      group.node.style.setProperty('--n', Object.keys(group.segs).length);
    }
    return group.segs[name];
  }

  function show(row, seg, result) {
    var shown = JSON.stringify(result);
    if (row.shown === shown) return;       // unchanged since the last poll
    row.shown = shown;
    row.dd.dataset.state = result.state;
    seg.dataset.state = result.state;
    row.val.textContent = result.text;
    if (result.extra) {
      if (result.extra.tagName === 'A') row.val.appendChild(document.createTextNode(' '));
      row.val.appendChild(result.extra);
    }
  }

  // Results of one target (a URL or an IP): one row and one segment per provider.
  function renderResults(view, target, results, rows, group, labels, skipped) {
    Object.keys(results).forEach(function (name) {
      var result = results[name];
      if (result.status === 'not_applicable') return;
      if (result.status === 'not_configured') { skipped.push(labels[name] || name); return; }
      var shown = read(name, result);
      show(rowFor(view, target + '|' + name, rows, labels[name] || name), segFor(group, name), shown);
      if (result.status === 'ok' || result.status === 'error') view.states.push(shown.state);
    });
  }

  function renderHop(view, hop, i, n, labels, searching) {
    var node = view.hops[hop.url];
    if (!node) {
      node = els.tplHop.content.firstElementChild.cloneNode(true);
      node.querySelector('.hop-url').textContent = hop.url;
      els.chain.appendChild(node);
      view.hops[hop.url] = node;
    }
    node.querySelector('.hop-index').textContent = i + 1;
    var head = node.querySelector('.hop-url');
    var small = head.querySelector('small') || head.appendChild(el('small'));
    small.textContent = hopLabel(i, n, searching);

    var skipped = [];
    renderResults(view, hop.url, hop.results, node.querySelector('.hop-rows'),
                  groupFor(view, hop.url), labels, skipped);

    var hosts = node.querySelector('.hosts');
    hop.hosts.forEach(function (host) {
      var key = hop.url + '|' + host.ip;
      var hostNode = view.hosts[key];
      if (!hostNode) {
        hostNode = els.tplHost.content.firstElementChild.cloneNode(true);
        var ipHead = hostNode.querySelector('.host-ip');
        ipHead.textContent = host.ip;
        ipHead.appendChild(el('small', { text: host.family }));
        hosts.appendChild(hostNode);
        view.hosts[key] = hostNode;
      }
      renderResults(view, host.ip + '@' + hop.url, host.results, hostNode.querySelector('.rows'),
                    groupFor(view, key), labels, skipped);
    });

    var line = node.querySelector('.skipped');
    var names = skipped.filter(function (s, k) { return skipped.indexOf(s) === k; });
    line.hidden = !names.length;
    line.textContent = names.length ? 'Not set up on this server: ' + names.join(', ') + '.' : '';
  }

  function renderLookyloo(capture) {
    if (!capture || capture.status === 'pending') return;
    var link = capture.links && capture.links[0];
    if (capture.status === 'ok' && safeLink(link, '')) {
      els.lookyloo.href = link;
      els.lookyloo.hidden = false;
      els.lookylooWait.hidden = true;
    } else if (capture.status !== 'not_configured') {
      els.lookylooWait.textContent = "Lookyloo couldn't capture this page.";
    } else {
      els.lookylooWait.hidden = true;
    }
  }

  function render(view, a) {
    if (a.url !== view.url) {
      view.url = a.url;
      renderSubject(a.url);
    }
    var labels = {};
    Object.keys(a.providers || {}).forEach(function (name) { labels[name] = a.providers[name].label; });
    view.states = [];
    var searching = a.status === 'queued' || (a.lookyloo && a.lookyloo.status === 'pending');
    a.chain.forEach(function (hop, i) { renderHop(view, hop, i, a.chain.length, labels, searching); });
    renderLookyloo(a.lookyloo);

    els.track.setAttribute('aria-valuemax', a.progress.total);
    els.track.setAttribute('aria-valuenow', a.progress.done);
    if (a.status === 'queued') {
      els.progressText.textContent = 'Waiting for a free worker';
    } else if (a.status === 'running') {
      var capturing = a.lookyloo && a.lookyloo.status === 'pending';
      els.progressText.textContent = a.progress.done + ' of ' + a.progress.total + ' checks finished' +
        (capturing ? ' · following redirects in Lookyloo' : '');
    } else {
      var secs = Math.max(1, Math.round((a.finished || Date.now() / 1000) - a.created));
      els.progressText.textContent = plural(a.progress.total, 'check', 'checks') + ' finished in ' +
        plural(secs, 'second', 'seconds');
    }
  }

  /* ---------- "Working" panel: what is happening, and for how long ---------- */

  var working = { timer: null, started: 0 };

  function workingStart() {
    working.started = Date.now();
    els.working.hidden = false;
    els.workingTime.textContent = '0 s';
    els.submit.setAttribute('aria-busy', 'true');
    els.submit.textContent = 'Checking…';
    clearInterval(working.timer);
    working.timer = setInterval(function () {
      els.workingTime.textContent = Math.round((Date.now() - working.started) / 1000) + ' s';
    }, 1000);
  }

  function workingStop() {
    clearInterval(working.timer);
    els.working.hidden = true;
    els.submit.removeAttribute('aria-busy');
    els.submit.textContent = 'Check URL';
  }

  function workingPhase(title, detail) {
    if (els.workingTitle.textContent !== title) els.workingTitle.textContent = title;
    if (els.workingDetail.textContent !== detail) els.workingDetail.textContent = detail;
  }

  function workingFrom(a) {
    if (a.status === 'queued') {
      workingPhase('Waiting for a free slot…', 'Other links are being checked; yours starts in a moment.');
    } else if (a.lookyloo && a.lookyloo.status === 'pending') {
      workingPhase('Opening the page in a real browser…',
        'Lookyloo follows every redirect, like a visitor would. This usually takes 20 to 60 seconds; the other checks run meanwhile.');
    } else {
      workingPhase('Asking the sources…', a.progress.done + ' of ' + a.progress.total + ' answers received.');
    }
  }

  /* ---------- Verdict ---------- */

  function joinNames(names) {
    if (names.length === 1) return names[0];
    return names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1];
  }

  function showVerdict(a, view) {
    var labels = function (names) {
      return names.map(function (n) { return (a.providers[n] && a.providers[n].label) || n; });
    };
    var v = a.verdict;
    var tone, title, lead, detail;
    if (v.verdict === 'malicious') {
      tone = 'bad';
      title = 'Dangerous link';
      lead = 'Flagged by ' + joinNames(labels(v.flagged_by)) + '.';
      detail = "Don't open it, and don't type a password or card number on it. " +
               'If you already did, change that password now and call your bank. ' +
               'Send the report so CIRCL analysts can act on it.';
    } else if (v.verdict === 'suspicious' || view.states.indexOf('bad') !== -1 || view.states.indexOf('warn') !== -1) {
      tone = 'warn';
      title = 'Be careful with this link';
      lead = v.flagged_by.length
        ? joinNames(labels(v.flagged_by)) + (v.flagged_by.length === 1 ? ' has' : ' have') + ' doubts about it.'
        : 'Some of the data below is worrying.';
      detail = 'Read the details below before you open it. If it came by email or text message, send the report to CIRCL.';
    } else if (!v.checked_by.length) {
      tone = 'neutral';
      title = "We can't tell if this link is dangerous";
      lead = 'No reputation source checked it.';
      detail = 'This server has no reputation source set up (PhishTank, VirusTotal, Google Safe Browsing…). ' +
               'Treat the link as unknown: if it came by email or text message, report it to CIRCL. ' +
               'The capture, routing and network data are below.';
    } else {
      tone = 'ok';
      title = 'No source flags this link';
      lead = 'Checked by ' + joinNames(labels(v.checked_by)) + '.';
      detail = "That isn't proof it's safe: new phishing pages often go unlisted for hours. If it looks suspicious, report it anyway.";
    }

    els.report.dataset.tone = tone;
    if (tone === 'bad') els.caption.textContent = 'Flagged as dangerous';
    els.verdict.dataset.tone = tone;
    els.verdict.textContent = '';
    if (tone === 'bad' || tone === 'warn') {
      els.verdict.setAttribute('role', 'alert');
      els.verdict.appendChild(warningIcon());
    } else {
      els.verdict.removeAttribute('role');
      els.verdict.appendChild(tone === 'ok' ? checkIcon() : unknownIcon());
    }
    var text = el('div', { class: 'verdict-text' }, [el('strong', { text: title })]);
    if (lead) text.appendChild(el('p', { class: 'verdict-lead', text: lead }));
    text.appendChild(el('p', { text: detail }));
    els.verdict.appendChild(text);
    els.verdict.hidden = false;
  }

  function checkIcon() {
    var NS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 48 48');
    svg.setAttribute('class', 'verdict-icon');
    svg.setAttribute('aria-hidden', 'true');
    var disc = document.createElementNS(NS, 'circle');
    disc.setAttribute('cx', '24'); disc.setAttribute('cy', '24'); disc.setAttribute('r', '21');
    disc.setAttribute('class', 'icon-body');
    var tick = document.createElementNS(NS, 'path');
    tick.setAttribute('d', 'M14.5 24.5l6.5 6.5 12.5-13');
    tick.setAttribute('class', 'icon-mark');
    svg.appendChild(disc); svg.appendChild(tick);
    return svg;
  }

  function unknownIcon() {
    var NS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 48 48');
    svg.setAttribute('class', 'verdict-icon');
    svg.setAttribute('aria-hidden', 'true');
    var disc = document.createElementNS(NS, 'circle');
    disc.setAttribute('cx', '24'); disc.setAttribute('cy', '24'); disc.setAttribute('r', '21');
    disc.setAttribute('class', 'icon-body');
    var hook = document.createElementNS(NS, 'path');
    hook.setAttribute('d', 'M18 18.5a6 6 0 1 1 8.5 5.5c-1.6.8-2.5 2-2.5 3.8v1.2');
    hook.setAttribute('class', 'icon-mark');
    var dot = document.createElementNS(NS, 'circle');
    dot.setAttribute('cx', '24'); dot.setAttribute('cy', '35'); dot.setAttribute('r', '2.25');
    dot.setAttribute('class', 'icon-dot');
    svg.appendChild(disc); svg.appendChild(hook); svg.appendChild(dot);
    return svg;
  }

  function warningIcon() {
    var NS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 48 48');
    svg.setAttribute('class', 'verdict-icon');
    svg.setAttribute('aria-hidden', 'true');
    var tri = document.createElementNS(NS, 'path');
    tri.setAttribute('d', 'M24 4.5 45.5 42h-43z');
    tri.setAttribute('class', 'icon-body');
    var bar = document.createElementNS(NS, 'path');
    bar.setAttribute('d', 'M24 17v12');
    bar.setAttribute('class', 'icon-mark');
    var dot = document.createElementNS(NS, 'circle');
    dot.setAttribute('cx', '24'); dot.setAttribute('cy', '35'); dot.setAttribute('r', '2.25');
    dot.setAttribute('class', 'icon-dot');
    svg.appendChild(tri); svg.appendChild(bar); svg.appendChild(dot);
    return svg;
  }

  /* ---------- Page states ---------- */

  function renderSubject(raw) {
    els.subject.textContent = '';
    var u;
    try { u = new URL(raw); } catch (e) { els.subject.textContent = raw; return; }
    var rest = raw.slice(raw.indexOf(u.host) + u.host.length);
    els.subject.appendChild(el('span', { class: 'u-scheme', text: u.protocol + '//' }));
    els.subject.appendChild(el('span', { class: 'u-host', text: u.host }));
    if (rest && rest !== '/') els.subject.appendChild(el('span', { class: 'u-path', text: rest }));
  }

  function showError(title, detail) {
    els.verdict.hidden = true;
    var old = els.report.querySelector('.report-error');
    if (old) old.remove();
    els.chain.before(el('div', { class: 'report-error', role: 'alert' }, [
      el('strong', { text: title }),
      el('p', { text: detail })
    ]));
  }

  function reset() {
    els.track.textContent = '';
    els.chain.textContent = '';
    els.verdict.hidden = true;
    delete els.report.dataset.tone;
    els.actions.hidden = true;
    els.lookyloo.hidden = true;
    els.lookylooWait.hidden = false;
    els.lookylooWait.textContent = 'Capturing the page in Lookyloo…';
    // Only when the instance sends reports (data-enabled, from config/generic.json)
    els.send.hidden = els.send.dataset.enabled !== 'true';
    els.send.disabled = false;
    els.send.textContent = 'Send report to CIRCL';
    var sent = els.actions.querySelector('.sent');
    if (sent) sent.remove();
    var err = els.report.querySelector('.report-error');
    if (err) err.remove();
  }

  function start(input) {
    var token = {};
    run = token;
    var view = { url: null, hops: {}, hosts: {}, rows: {}, groups: {}, states: [] };

    reset();
    els.body.classList.add('has-report');
    els.report.hidden = false;
    els.caption.textContent = 'Checking';
    renderSubject(input);
    els.progressText.textContent = 'Checking the address';
    workingPhase('Checking the link…', 'Sending it to the server.');
    workingStart();

    var started = Date.now();
    function poll(uuid) {
      return api('GET', 'analyse/' + encodeURIComponent(uuid)).then(function (a) {
        if (run !== token) return;
        render(view, a);
        workingFrom(a);
        if (a.status === 'done') {
          workingStop();
          els.caption.textContent = 'Checked';
          showVerdict(a, view);
          els.actions.hidden = false;
          return;
        }
        if (a.status === 'failed') throw new Error('failed');
        if (Date.now() - started > GIVE_UP_AFTER_MS) throw new Error('timeout');
        return wait(POLL_EVERY_MS).then(function () { return poll(uuid); });
      });
    }

    api('POST', 'analyse', { url: input }).then(function (created) {
      if (run !== token) return;
      token.url = created.url;
      try { history.replaceState(null, '', '?url=' + encodeURIComponent(created.url)); } catch (e) { /* ignore */ }
      return poll(created.uuid);
    }).catch(function (err) {
      if (run !== token) return;
      workingStop();
      els.progressText.textContent = 'Stopped';
      if (err.status === 400) {
        els.caption.textContent = "Can't check";
        showError("This address can't be checked.", err.message + ' Check for typos and try again.');
        return;
      }
      els.actions.hidden = false;
      showError('The check stopped before it finished.',
        err.message === 'timeout' ? 'The checks took more than five minutes. Try again later.'
                                  : 'The server returned an error. Try again in a moment.');
    });
  }

  /* ---------- Events ---------- */

  els.form.addEventListener('submit', function (e) {
    e.preventDefault();
    var value = els.input.value.trim();
    if (!value) {
      els.hint.hidden = false;
      els.hint.textContent = 'Paste the URL you want to check.';
      els.input.focus();
      return;
    }
    els.hint.hidden = true;
    start(value);
  });

  els.send.addEventListener('click', function () {
    if (!run || !run.url) return;
    var token = run;
    els.send.disabled = true;
    els.send.textContent = 'Sending report…';
    api('POST', 'report', { url: token.url }).then(function (answer) {
      if (run !== token) return;
      els.send.hidden = true;
      els.send.after(el('span', { class: 'sent', role: 'status',
        text: answer.sent ? 'Report sent to CIRCL' : 'Already reported to CIRCL today' }));
    }).catch(function () {
      if (run !== token) return;
      els.send.disabled = false;
      els.send.textContent = 'Send report to CIRCL';
      showError("The report wasn't sent.", "This server couldn't deliver the email. Try again later, or write to info@circl.lu with the URL.");
    });
  });

  els.again.addEventListener('click', function () {
    run = null;
    workingStop();
    els.report.hidden = true;
    els.body.classList.remove('has-report');
    els.input.value = '';
    try { history.replaceState(null, '', window.location.pathname); } catch (e) { /* ignore */ }
    window.scrollTo({ top: 0 });
    els.input.focus();
  });

  var params = new URLSearchParams(window.location.search);
  if (params.get('url')) {
    els.input.value = params.get('url');
    els.form.requestSubmit();
  }
}());

// URL field: example links "typed" in the placeholder, letter by letter.
// Only the placeholder changes (never the value). Stops for good as soon as the
// field is focused or filled; off with prefers-reduced-motion.
(function () {
  'use strict';

  var input = document.getElementById('url');
  if (!input || input.value || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return;
  }
  var examples = [
    'https://paypal-account-verify.example.net/login',
    'https://bit.ly/3xAmpl3',
    'http://your-bank.example.com/secure/update',
    'https://docs-share.example.org/invoice.pdf',
    'https://www.circl.lu/'
  ];
  var original = input.placeholder;
  var stopped = false;
  var timer = null;
  var stop = function () {
    stopped = true;
    clearTimeout(timer);
    input.placeholder = original;
  };
  input.addEventListener('focus', stop, { once: true });
  input.addEventListener('input', stop, { once: true });

  var example = 0;
  var length = 0;
  var deleting = false;
  var step = function () {
    if (stopped) {
      return;
    }
    var text = examples[example];
    length += deleting ? -1 : 1;
    input.placeholder = text.slice(0, length) + (deleting ? '' : '▍');
    var delay = deleting ? 25 : 55 + Math.random() * 60;
    if (!deleting && length === text.length) {
      deleting = true;
      delay = 1800;              // pause on the full URL
    } else if (deleting && length === 0) {
      deleting = false;
      example = (example + 1) % examples.length;
      delay = 400;
    }
    timer = setTimeout(step, delay);
  };
  timer = setTimeout(step, 800);
}());
