(function () {
  'use strict';

  var POLL_EVERY_MS = 1000;
  var GIVE_UP_AFTER_MS = 60000;

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
    tplHost: $('tpl-host')
  };

  // One run per submitted URL. Results from an older run are dropped.
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

  /* ---------- Backend jobs ---------- */

  function postJob(path, body) {
    return fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    }).then(function (id) { return id.trim(); });
  }

  function wait(ms) { return new Promise(function (res) { setTimeout(res, ms); }); }

  // Resolves with the job's JSON result, or rejects with 'timeout'.
  function poll(jobId, token) {
    var started = Date.now();
    function tick() {
      if (run !== token) return Promise.reject('stale');
      return fetch('_result/' + encodeURIComponent(jobId)).then(function (r) {
        if (r.status === 200) return r.json();
        if (Date.now() - started > GIVE_UP_AFTER_MS) throw 'timeout';
        return wait(POLL_EVERY_MS).then(tick);
      });
    }
    return tick();
  }

  // An empty job id means the source has no API key on this server.
  function job(path, body, token) {
    return postJob(path, body).then(function (id) {
      if (!id) return { skipped: true };
      return poll(id, token).then(function (data) { return { data: data }; });
    });
  }

  /* ---------- Progress bar: one segment per check ---------- */

  function Progress() {
    this.groups = [];
    this.startedAt = Date.now();
  }

  Progress.prototype.group = function () {
    var g = { node: el('div', { class: 'seg-group' }), n: 0 };
    this.groups.push(g);
    els.track.appendChild(g.node);
    return g;
  };

  Progress.prototype.segment = function (group) {
    var seg = el('span', { class: 'seg', 'data-state': 'pending' });
    group.node.appendChild(seg);
    group.n += 1;
    group.node.style.setProperty('--n', group.n);
    this.render();
    return seg;
  };

  Progress.prototype.drop = function (group, seg) {
    seg.remove();
    group.n -= 1;
    if (group.n === 0) group.node.remove();
    else group.node.style.setProperty('--n', group.n);
    this.render();
  };

  Progress.prototype.counts = function () {
    var segs = els.track.querySelectorAll('.seg');
    var done = 0;
    segs.forEach(function (s) { if (s.dataset.state !== 'pending') done += 1; });
    return { total: segs.length, done: done };
  };

  Progress.prototype.render = function (label) {
    var c = this.counts();
    els.track.setAttribute('aria-valuemax', c.total);
    els.track.setAttribute('aria-valuenow', c.done);
    if (label) els.progressText.textContent = label;
    else els.progressText.textContent = c.done + ' of ' + c.total + ' checks finished';
  };

  /* ---------- Reading each source's answer ---------- */

  // Each reader returns { state, text, extra } where extra is an optional node.
  var readers = {
    phishtank: function (d) {
      if (d) return { state: 'bad', text: 'Listed as a phishing site', extra: safeLink(d, 'View on PhishTank') };
      return { state: 'ok', text: 'Not listed' };
    },

    virustotal: function (d) {
      if (!d || !d[1]) return { state: 'none', text: (d && d[0]) || 'No report' };
      var link = safeLink(d[1], 'Full report');
      var pos = d[2], total = d[3];
      if (pos === null || pos === undefined) {
        return { state: 'info', text: 'Scan queued. The report will be ready in a few minutes.', extra: link };
      }
      var text = pos + ' of ' + total + ' engines flag it';
      if (pos === 0) return { state: 'ok', text: text, extra: link };
      if (pos < total / 3) return { state: 'warn', text: text, extra: link };
      return { state: 'bad', text: text, extra: link };
    },

    gsb: function (d, query) {
      if (d) {
        return {
          state: 'bad',
          text: 'Listed for ' + d,
          extra: safeLink('https://transparencyreport.google.com/safe-browsing/search?url=' + encodeURIComponent(query), 'Details')
        };
      }
      return { state: 'ok', text: 'Not listed' };
    },

    eupi: function (d) {
      if (!d || d === 'inconnu') return { state: 'none', text: 'Not in their database' };
      if (d === 'clean') return { state: 'ok', text: 'Marked clean' };
      return { state: 'bad', text: 'Marked as ' + d };
    },

    whois: function (d) {
      if (d && d.length) return { state: 'info', text: plural(d.length, 'contact', 'contacts'), extra: list(d) };
      return { state: 'none', text: 'No abuse contact found' };
    },

    bgp: function (d) {
      if (!d || !d[0]) return { state: 'none', text: 'No routing data' };
      var asn = d[0], prefix = d[1], name = d[2], position = d[4], total = d[5];
      var lines = ['AS' + asn + ', prefix ' + prefix];
      var state = 'info';
      if (position) {
        lines.push('Position ' + position + ' of ' + total + ' in BGP Ranking');
        if (position < 100) state = 'bad';
        else if (position < 1000) state = 'warn';
      }
      return { state: state, text: name || ('AS' + asn), extra: list(lines) };
    },

    pdns: function (d) {
      if (!d || !d[0]) return { state: 'none', text: 'No records' };
      return { state: 'info', text: plural(d[0], 'record', 'records') + ', most recent:', extra: list(d[1] || []) };
    },

    pssl: function (d) {
      var keys = d ? Object.keys(d) : [];
      if (!keys.length) return { state: 'none', text: 'No certificates seen' };
      return {
        state: 'info',
        text: plural(keys.length, 'certificate', 'certificates') + ' seen on this address',
        extra: list(keys.map(function (sha1) { return sha1 + '  ' + ((d[sha1] || [])[0] || ''); }))
      };
    }
  };

  var URL_CHECKS = [
    { name: 'PhishTank', path: 'phishtank', read: readers.phishtank },
    { name: 'VirusTotal', path: 'virustotal_report', read: readers.virustotal },
    { name: 'Google Safe Browsing', path: 'googlesafebrowsing', read: readers.gsb },
    { name: 'EU phishing initiative', path: 'eupi', read: readers.eupi },
    { name: 'Abuse contacts', path: 'whois', read: readers.whois }
  ];

  var IP_CHECKS = [
    { name: 'Network', source: 'BGP Ranking', path: 'bgpranking', read: readers.bgp },
    { name: 'PhishTank', path: 'phishtank', read: readers.phishtank },
    { name: 'Passive DNS', path: 'pdnscircl', read: readers.pdns },
    { name: 'TLS certificates', path: 'psslcircl', read: readers.pssl, v4only: true },
    { name: 'Abuse contacts', path: 'whois', read: readers.whois }
  ];

  var REPUTATION = ['phishtank', 'virustotal_report', 'googlesafebrowsing', 'eupi'];

  /* ---------- Running checks ---------- */

  function row(rows, name) {
    var dt = el('dt', { text: name });
    var val = el('span', { class: 'val', text: 'Waiting for an answer' });
    var dd = el('dd', { 'data-state': 'pending' }, [el('span', { class: 'status-dot' }), val]);
    rows.appendChild(dt);
    rows.appendChild(dd);
    return { dt: dt, dd: dd, val: val };
  }

  function settle(r, seg, result) {
    r.dd.dataset.state = result.state;
    seg.dataset.state = result.state;
    r.val.textContent = result.text;
    if (result.extra) {
      if (result.extra.tagName === 'A') r.val.appendChild(document.createTextNode(' '));
      r.val.appendChild(result.extra);
    }
  }

  function runCheck(token, check, query, rows, group, skipped) {
    var r = row(rows, check.name);
    var seg = run.progress.segment(group);
    return job(check.path, { query: query }, token).then(function (res) {
      if (run !== token) return;
      if (res.skipped) {
        r.dt.remove(); r.dd.remove();
        run.progress.drop(group, seg);
        skipped(check.name);
        return;
      }
      if (REPUTATION.indexOf(check.path) !== -1) run.reputationRan = true;
      var result = check.read(res.data, query);
      run.results.push({ state: result.state, source: check.source || check.name });
      settle(r, seg, result);
      run.progress.render();
    }).catch(function (err) {
      if (run !== token || err === 'stale') return;
      settle(r, seg, {
        state: 'none',
        text: err === 'timeout' ? 'No answer after 60 seconds' : 'This check failed on the server'
      });
      run.progress.render();
    });
  }

  function skippedLine(node) {
    var names = [];
    return function (name) {
      if (names.indexOf(name) === -1) names.push(name);
      node.hidden = false;
      node.textContent = 'Not set up on this server: ' + names.join(', ') + '.';
    };
  }

  function runHost(token, ip, family, container, skip) {
    var node = els.tplHost.content.firstElementChild.cloneNode(true);
    var head = node.querySelector('.host-ip');
    head.textContent = ip;
    head.appendChild(el('small', { text: family }));
    container.appendChild(node);
    var rows = node.querySelector('.rows');
    var group = run.progress.group();
    return Promise.all(IP_CHECKS.filter(function (c) {
      return !(c.v4only && family === 'IPv6');
    }).map(function (c) {
      return runCheck(token, c, ip, rows, group, skip);
    }));
  }

  function hopLabel(i, n) {
    if (n === 1) return 'No redirects';
    if (i === 0) return 'Where the link starts';
    if (i === n - 1) return 'Where it ends up';
    return 'Redirect';
  }

  function runHop(token, url, i, n) {
    var node = els.tplHop.content.firstElementChild.cloneNode(true);
    node.querySelector('.hop-index').textContent = i + 1;
    var head = node.querySelector('.hop-url');
    head.textContent = url;
    head.appendChild(el('small', { text: hopLabel(i, n) }));
    els.chain.appendChild(node);

    var rows = node.querySelector('.hop-rows');
    var hosts = node.querySelector('.hosts');
    var skip = skippedLine(node.querySelector('.skipped'));
    var group = run.progress.group();

    var urlChecks = URL_CHECKS.map(function (c) {
      return runCheck(token, c, url, rows, group, skip);
    });

    // Resolving is a check of its own; its answer spawns one block per address.
    var r = row(rows, 'Addresses');
    var seg = run.progress.segment(group);
    var resolved = job('resolve', { url: url }, token).then(function (res) {
      if (run !== token) return;
      var v4 = (res.data && res.data[0]) || [];
      var v6 = (res.data && res.data[1]) || [];
      var all = v4.length + v6.length;
      settle(r, seg, all
        ? { state: 'info', text: plural(all, 'address', 'addresses') + ' below' }
        : { state: 'none', text: "The host doesn't resolve" });
      run.progress.render();
      return Promise.all(
        v4.map(function (ip) { return runHost(token, ip, 'IPv4', hosts, skip); })
          .concat(v6.map(function (ip) { return runHost(token, ip, 'IPv6', hosts, skip); }))
      );
    }).catch(function (err) {
      if (run !== token || err === 'stale') return;
      settle(r, seg, { state: 'none', text: "Couldn't resolve the host" });
      run.progress.render();
    });

    return Promise.all(urlChecks.concat([resolved]));
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
    var box = el('div', { class: 'report-error', role: 'alert' }, [
      el('strong', { text: title }),
      el('p', { text: detail })
    ]);
    els.chain.before(box);
  }

  function showVerdict() {
    // Count distinct sources, not checks: PhishTank on three hosts is still one source.
    function sources(state) {
      var names = [];
      run.results.forEach(function (r) {
        if (r.state === state && names.indexOf(r.source) === -1) names.push(r.source);
      });
      return names;
    }
    var badSources = sources('bad');
    var warnSources = sources('warn');
    var tone, title, lead, detail;

    if (badSources.length) {
      tone = 'bad';
      title = 'Dangerous link';
      lead = 'Flagged by ' + joinNames(badSources) + '.';
      detail = "Don't open it, and don't type a password or card number on it. " +
               'If you already did, change that password now and call your bank. ' +
               'Send the report so CIRCL analysts can act on it.';
    } else if (warnSources.length) {
      tone = 'warn';
      title = 'Be careful with this link';
      lead = joinNames(warnSources) + (warnSources.length === 1 ? ' has' : ' have') + ' doubts about it.';
      detail = 'Read the details below before you open it. If it came by email or text message, send the report to CIRCL.';
    } else if (!run.reputationRan) {
      tone = 'neutral';
      title = 'No reputation source could check this link.';
      detail = 'This server has no API keys for PhishTank, VirusTotal, Google Safe Browsing or the EU phishing initiative. Routing and contact data are below.';
    } else {
      tone = 'ok';
      title = 'No source flags this link.';
      detail = "That isn't proof it's safe: new phishing pages often go unlisted for hours. If it looks suspicious, send the report anyway.";
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
    }
    var text = el('div', { class: 'verdict-text' }, [el('strong', { text: title })]);
    if (lead) text.appendChild(el('p', { class: 'verdict-lead', text: lead }));
    text.appendChild(el('p', { text: detail }));
    els.verdict.appendChild(text);
    els.verdict.hidden = false;
  }

  function joinNames(names) {
    if (names.length === 1) return names[0];
    return names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1];
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

  function reset() {
    els.track.textContent = '';
    els.chain.textContent = '';
    els.verdict.hidden = true;
    delete els.report.dataset.tone;
    els.actions.hidden = true;
    els.lookyloo.hidden = true;
    els.lookylooWait.hidden = false;
    els.lookylooWait.textContent = 'Capturing the page in Lookyloo…';
    els.send.hidden = false;
    els.send.disabled = false;
    els.send.textContent = 'Send report to CIRCL';
    var sent = els.actions.querySelector('.sent');
    if (sent) sent.remove();
    var err = els.report.querySelector('.report-error');
    if (err) err.remove();
  }

  function start(input) {
    var token = { url: input };
    run = token;
    run.progress = new Progress();
    run.results = [];
    run.reputationRan = false;

    reset();
    els.body.classList.add('has-report');
    els.report.hidden = false;
    els.caption.textContent = 'Checking';
    renderSubject(input);

    var prep = run.progress.group();
    var segValid = run.progress.segment(prep);
    var segChain = run.progress.segment(prep);
    run.progress.render('Checking the address');

    // Lookyloo captures the page in a headless browser. It is slow and runs on its own.
    job('lookyloo', { url: input }, token).then(function (res) {
      if (run !== token) return;
      var link = res.data && safeLink(res.data, '');
      if (link) {
        els.lookyloo.href = res.data;
        els.lookyloo.hidden = false;
        els.lookylooWait.hidden = true;
      } else {
        els.lookylooWait.textContent = "Lookyloo couldn't capture this page.";
      }
    }).catch(function () {
      if (run !== token) return;
      els.lookylooWait.textContent = "Lookyloo couldn't capture this page.";
    });

    job('start', { url: input }, token).then(function (res) {
      if (run !== token) return;
      var d = res.data || [false, input, 'no answer from the server'];
      if (!d[0]) {
        segValid.dataset.state = 'bad';
        segChain.dataset.state = 'none';
        run.progress.render('Stopped');
        els.caption.textContent = "Can't check";
        showError("This address can't be checked.", 'Reason: ' + (d[2] || 'unknown') + '. Check for typos and try again.');
        return;
      }
      segValid.dataset.state = 'ok';
      run.url = d[1];
      renderSubject(d[1]);
      run.progress.render('Following redirects');

      return job('urls', { url: d[1] }, token).then(function (res) {
        if (run !== token) return;
        var urls = (res.data && res.data.length) ? res.data : [d[1]];
        segChain.dataset.state = urls.length > 1 ? 'info' : 'ok';
        run.progress.render();
        return Promise.all(urls.map(function (u, i) { return runHop(token, u, i, urls.length); }));
      }).then(function () {
        if (run !== token) return;
        var secs = Math.max(1, Math.round((Date.now() - run.progress.startedAt) / 1000));
        var c = run.progress.counts();
        run.progress.render(c.total + ' checks finished in ' + plural(secs, 'second', 'seconds'));
        els.caption.textContent = 'Checked';
        showVerdict();
        els.actions.hidden = false;
      });
    }).catch(function (err) {
      if (run !== token || err === 'stale') return;
      run.progress.render('Stopped');
      showError('The check stopped before it finished.',
        err === 'timeout' ? 'The server took more than a minute to answer. Try again in a moment.'
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
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = 'http://' + value;
    els.hint.hidden = true;
    els.input.value = value;
    start(value);
  });

  els.send.addEventListener('click', function () {
    if (!run || !run.url) return;
    var token = run;
    els.send.disabled = true;
    els.send.textContent = 'Sending report…';
    fetch('submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: token.url })
    }).then(function (r) {
      if (run !== token) return;
      if (!r.ok) throw new Error('HTTP ' + r.status);
      els.send.hidden = true;
      els.send.after(el('span', { class: 'sent', role: 'status', text: 'Report sent to CIRCL' }));
    }).catch(function () {
      if (run !== token) return;
      els.send.disabled = false;
      els.send.textContent = 'Send report to CIRCL';
      if (!els.report.querySelector('.report-error')) {
        showError("The report wasn't sent.", "This server couldn't deliver the email. Try again later, or write to info@circl.lu with the URL.");
        showVerdict();
      }
    });
  });

  els.again.addEventListener('click', function () {
    run = null;
    els.report.hidden = true;
    els.body.classList.remove('has-report');
    els.input.value = '';
    window.scrollTo({ top: 0 });
    els.input.focus();
  });

  var params = new URLSearchParams(window.location.search);
  if (params.get('url')) {
    els.input.value = params.get('url');
    els.form.requestSubmit();
  }
}());
