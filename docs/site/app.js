/* pycoraza docs site · interactivity
   - Theme toggle (auto / light / dark), persisted in localStorage.
   - Copy-to-clipboard buttons on every <pre class="code"> block.
   - Simple tab groups for the quickstart snippets. */
(function () {
  'use strict';

  // ---------------- THEME ----------------
  var root = document.documentElement;
  var STORAGE_KEY = 'pycoraza-theme';

  function applyTheme(theme) {
    if (theme === 'auto') {
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', theme);
    }
  }

  var saved = null;
  try { saved = localStorage.getItem(STORAGE_KEY); } catch (e) { /* private mode */ }
  if (saved === 'light' || saved === 'dark' || saved === 'auto') {
    applyTheme(saved);
  }

  var toggle = document.getElementById('themeToggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var current = root.getAttribute('data-theme');
      var next;
      if (current === 'dark') next = 'light';
      else if (current === 'light') next = 'auto';
      else next = 'dark';
      applyTheme(next);
      try { localStorage.setItem(STORAGE_KEY, next); } catch (e) { /* ignore */ }
    });
  }

  // ---------------- COPY CODE ----------------
  document.querySelectorAll('pre.code').forEach(function (pre) {
    if (pre.parentElement && pre.parentElement.classList.contains('code-wrap')) return;
    var wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.textContent = 'copy';
    btn.setAttribute('aria-label', 'Copy code to clipboard');
    btn.addEventListener('click', function () {
      var text = pre.innerText;
      var done = function () {
        btn.textContent = 'copied';
        btn.classList.add('is-copied');
        setTimeout(function () {
          btn.textContent = 'copy';
          btn.classList.remove('is-copied');
        }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () {
          btn.textContent = 'error';
        });
      } else {
        // fallback for very old browsers
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'absolute';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); done(); } catch (e) { btn.textContent = 'error'; }
        document.body.removeChild(ta);
      }
    });
    wrap.appendChild(btn);
  });

  // ---------------- TABS ----------------
  var tabGroups = {};
  document.querySelectorAll('.tabs').forEach(function (tabs) {
    var group = tabs.getAttribute('data-tabgroup') || 'default';
    if (!tabGroups[group]) tabGroups[group] = [];
    tabGroups[group].push(tabs);

    tabs.querySelectorAll('.tab').forEach(function (tab) {
      tab.addEventListener('click', function () {
        selectTab(group, tab.getAttribute('data-tab'));
      });
    });
  });

  function selectTab(group, value) {
    (tabGroups[group] || []).forEach(function (tabs) {
      tabs.querySelectorAll('.tab').forEach(function (t) {
        var active = t.getAttribute('data-tab') === value;
        t.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      tabs.querySelectorAll('.tab-panel').forEach(function (panel) {
        var active = panel.getAttribute('data-tab') === value;
        if (active) panel.removeAttribute('hidden');
        else panel.setAttribute('hidden', '');
      });
    });
  }
})();
