/* ══════════════════════════════════════════════
   WebShield — script.js
   Raza Ali · Roll No. 23550005
   Works across index.html, results.html, history.html
   ══════════════════════════════════════════════ */

/* ── SHARED DATA (stored in sessionStorage so all pages share it) ── */
var SAMPLE_RESULTS = [
  { type: 'SQL Injection',            severity: 'High',   description: 'User input is passed directly to SQL queries without parameterisation. Allows attackers to read, modify, or delete database records.' },
  { type: 'Cross-Site Scripting (XSS)',severity: 'High',  description: "Reflected XSS detected in search parameter. Malicious scripts can be injected and executed in victim's browser." },
  { type: 'Insecure HTTP Headers',    severity: 'Medium', description: 'Missing X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy headers increase exposure to MIME-type and clickjacking attacks.' },
  { type: 'Open Redirect',            severity: 'Medium', description: 'Redirect URL parameter is not validated, allowing attackers to redirect users to malicious external websites.' },
  { type: 'Directory Listing Enabled',severity: 'Low',    description: 'Web server returns directory indexes for /uploads and /assets. File structure exposed to unauthenticated users.' },
  { type: 'Outdated jQuery (1.11.3)', severity: 'Low',    description: 'Detected jQuery version has known XSS vulnerabilities (CVE-2020-11022). Upgrade to 3.7.x recommended.' },
  { type: 'SSL/TLS Info',             severity: 'Info',   description: 'TLS 1.2 in use. TLS 1.3 is recommended for stronger security and better performance.' }
];

/* Load history from sessionStorage */
function loadHistory() {
  var raw = sessionStorage.getItem('scanHistory');
  if (raw) {
    try { return JSON.parse(raw); } catch(e) {}
  }
  /* Default sample history */
  return [
    { id: '#0041', url: 'https://testphp.vulnweb.com',    time: '2025-04-17 14:32', high: 3, medium: 2, low: 1, clean: false },
    { id: '#0040', url: 'https://juice-shop.example.com', time: '2025-04-16 09:15', high: 0, medium: 0, low: 2, clean: false },
    { id: '#0039', url: 'https://secure.myapp.io',        time: '2025-04-14 18:05', high: 0, medium: 0, low: 0, clean: true  }
  ];
}

function saveHistory(arr) {
  sessionStorage.setItem('scanHistory', JSON.stringify(arr));
}

/* ── TOAST ── */
function showToast(msg) {
  var t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(function(){ t.classList.remove('show'); }, 2800);
}

/* ══════════════════════════════════════════════
   INDEX PAGE  (index.html)
   ══════════════════════════════════════════════ */
function initIndexPage() {
  if (!document.getElementById('scanBtn')) return;

  var isDisclaimed = false;

  /* disclaimer toggle */
  var box = document.getElementById('disclaimerBox');
  if (box) {
    box.addEventListener('click', function() {
      isDisclaimed = !isDisclaimed;
      document.getElementById('disclaimer').checked = isDisclaimed;
      box.classList.toggle('checked', isDisclaimed);
      validateForm();
    });
  }

  /* url input */
  var urlInput = document.getElementById('urlInput');
  if (urlInput) {
    urlInput.addEventListener('input', validateForm);
  }

  function validateForm() {
    var url = urlInput ? urlInput.value.trim() : '';
    document.getElementById('scanBtn').disabled = !(url && isDisclaimed);
  }

  /* scan button */
  document.getElementById('scanBtn').addEventListener('click', function() {
    var raw = urlInput.value.trim();
    if (!raw) return;

    var url = raw.startsWith('http') ? raw : 'https://' + raw;
    sessionStorage.setItem('currentUrl', url);

    /* disable button */
    var btn = document.getElementById('scanBtn');
    btn.disabled = true;
    btn.textContent = '⏳ Scanning… Please wait';

    /* show progress */
    var progress = document.getElementById('scanProgress');
    progress.classList.add('show');

    var steps = ['step1','step2','step3','step4'];
    var pcts  = [25, 50, 80, 100];
    var i = 0;

    var iv = setInterval(function() {
      if (i > 0) {
        var prev = document.getElementById(steps[i-1]);
        prev.classList.remove('running');
        prev.classList.add('done');
      }
      if (i < steps.length) {
        document.getElementById(steps[i]).classList.add('running');
        document.getElementById('progressBar').style.width = pcts[i] + '%';
        i++;
      } else {
        clearInterval(iv);
        setTimeout(function() { finishScan(url); }, 500);
      }
    }, 700);
  });

  function finishScan(url) {
    var now = new Date();
    var results = SAMPLE_RESULTS;

    /* build history entry */
    var high   = results.filter(function(r){ return r.severity === 'High'; }).length;
    var medium = results.filter(function(r){ return r.severity === 'Medium'; }).length;
    var low    = results.filter(function(r){ return r.severity === 'Low' || r.severity === 'Info'; }).length;

    var entry = {
      id:     '#' + String(Math.floor(Math.random() * 9000) + 1000),
      url:    url,
      time:   now.toISOString().slice(0,16).replace('T',' '),
      high:   high,
      medium: medium,
      low:    low,
      clean:  high === 0 && medium === 0
    };

    /* save to session */
    var hist = loadHistory();
    hist.unshift(entry);
    saveHistory(hist);
    sessionStorage.setItem('lastScanEntry', JSON.stringify(entry));
    sessionStorage.setItem('lastScanResults', JSON.stringify(results));

    /* go to results page */
    window.location.href = 'results.html';
  }
}

/* ══════════════════════════════════════════════
   RESULTS PAGE  (results.html)
   ══════════════════════════════════════════════ */
function initResultsPage() {
  if (!document.getElementById('resultsTable')) return;

  var currentResults = [];

  /* load data saved by index page */
  var entryRaw   = sessionStorage.getItem('lastScanEntry');
  var resultsRaw = sessionStorage.getItem('lastScanResults');

  var entry = entryRaw   ? JSON.parse(entryRaw)   : null;
  var savedResults = resultsRaw ? JSON.parse(resultsRaw) : SAMPLE_RESULTS;

  /* fallback: show sample data if arriving directly */
  if (!entry) {
    entry = {
      id: '#0041', url: 'https://testphp.vulnweb.com',
      time: '17 Apr 2025, 14:32', high: 2, medium: 2, low: 3
    };
    savedResults = SAMPLE_RESULTS;
  }

  currentResults = savedResults;

  /* populate banner */
  document.getElementById('resultUrl').textContent  = entry.url;
  document.getElementById('resultTime').textContent = entry.time;
  document.getElementById('resultId').textContent   = entry.id.replace('#','');
  document.getElementById('statHigh').textContent   = entry.high;
  document.getElementById('statMedium').textContent = entry.medium;
  document.getElementById('statLow').textContent    = entry.low;

  renderResultsTable(currentResults);

  /* filter chips */
  document.querySelectorAll('.chip').forEach(function(chip) {
    chip.addEventListener('click', function() {
      document.querySelectorAll('.chip').forEach(function(c){ c.classList.remove('active'); });
      chip.classList.add('active');
      var sev = chip.dataset.filter;
      var filtered = sev === 'all' ? currentResults : currentResults.filter(function(r){ return r.severity === sev; });
      renderResultsTable(filtered);
    });
  });

  /* export CSV */
  var exportBtn = document.getElementById('exportBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', function() {
      var rows = [['#','Vulnerability','Severity','Description']];
      currentResults.forEach(function(r, i) {
        rows.push([i+1, r.type, r.severity, r.description]);
      });
      var csv = rows.map(function(r){ return r.map(function(c){ return '"'+c+'"'; }).join(','); }).join('\n');
      var a = document.createElement('a');
      a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
      a.download = 'scan_results.csv';
      a.click();
      showToast('📄 CSV exported!');
    });
  }
}

function renderResultsTable(data) {
  var wrap = document.getElementById('resultsTable');
  if (!wrap) return;

  if (!data.length) {
    wrap.innerHTML = '<div class="no-issues"><div class="icon">✅</div><h3>No Vulnerabilities Found</h3><p>This site passed all security checks. Good job!</p></div>';
    return;
  }

  var rows = data.map(function(r, i) {
    return '<tr data-severity="'+r.severity+'">' +
      '<td class="td-num">' + String(i+1).padStart(2,'0') + '</td>' +
      '<td><div class="vuln-type">'+r.type+'</div></td>' +
      '<td><span class="badge badge-'+r.severity.toLowerCase()+'">'+r.severity+'</span></td>' +
      '<td><div class="vuln-desc">'+r.description+'</div></td>' +
      '</tr>';
  }).join('');

  wrap.innerHTML =
    '<table>' +
      '<thead><tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
    '</table>';
}

/* ══════════════════════════════════════════════
   HISTORY PAGE  (history.html)
   ══════════════════════════════════════════════ */
function initHistoryPage() {
  if (!document.getElementById('historyList')) return;

  var scanHistory = loadHistory();

  renderHistory(scanHistory);
  updateBadge(scanHistory.length);

  /* search */
  var searchBox = document.getElementById('historySearch');
  if (searchBox) {
    searchBox.addEventListener('input', function() {
      var q = searchBox.value.toLowerCase();
      var filtered = scanHistory.filter(function(s) {
        return s.url.toLowerCase().includes(q) || s.time.includes(q);
      });
      renderHistory(filtered);
    });
  }

  /* clear history */
  var clearBtn = document.getElementById('clearBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', function() {
      if (!scanHistory.length) return;
      if (!confirm('Clear all scan history?')) return;
      scanHistory = [];
      saveHistory(scanHistory);
      renderHistory(scanHistory);
      updateBadge(0);
      showToast('🗑 History cleared');
    });
  }

  function renderHistory(data) {
    var list = document.getElementById('historyList');
    if (!data.length) {
      list.innerHTML = '<div class="empty-state"><div class="icon">📂</div><h3>No scans yet</h3><p>Run your first scan to see history here.</p></div>';
      return;
    }

    list.innerHTML = data.map(function(s) {
      var iconClass = s.clean ? 'safe' : s.high > 0 ? 'danger' : 'warning';
      var emoji     = s.clean ? '✅'   : s.high > 0 ? '🔴'     : '🟠';
      return '<div class="history-item" onclick="viewHistoryScan(\'' + s.id + '\')">' +
        '<div class="history-icon ' + iconClass + '">' + emoji + '</div>' +
        '<div class="history-info">' +
          '<div class="history-url">' + s.url + '</div>' +
          '<div class="history-time">🕐 ' + s.time + ' · Scan ' + s.id + '</div>' +
        '</div>' +
        '<div class="history-badges">' +
          (s.high   ? '<div class="count-chip h">H:' + s.high   + '</div>' : '') +
          (s.medium ? '<div class="count-chip m">M:' + s.medium + '</div>' : '') +
          (s.low    ? '<div class="count-chip l">L:' + s.low    + '</div>' : '') +
          (s.clean  ? '<div class="count-chip c">Clean ✓</div>' : '') +
        '</div>' +
      '</div>';
    }).join('');
  }

  /* expose to onclick */
  window.viewHistoryScan = function(id) {
    var found = scanHistory.find(function(s){ return s.id === id; });
    if (!found) return;
    var results = SAMPLE_RESULTS.slice(0, found.high + found.medium + found.low);
    sessionStorage.setItem('lastScanEntry',   JSON.stringify(found));
    sessionStorage.setItem('lastScanResults', JSON.stringify(results));
    window.location.href = 'results.html';
  };

  function updateBadge(n) {
    var b = document.getElementById('histBadge');
    if (b) b.textContent = n;
  }
}

/* ── NAV BADGE (all pages: show history count) ── */
function initNavBadge() {
  var b = document.getElementById('histBadge');
  if (b) {
    b.textContent = loadHistory().length;
  }
}

/* ── BOOT ── */
document.addEventListener('DOMContentLoaded', function() {
  initNavBadge();
  initIndexPage();
  initResultsPage();
  initHistoryPage();
});
