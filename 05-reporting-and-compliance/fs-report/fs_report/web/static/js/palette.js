/**
 * palette.js — ⌘K Command Palette + Keyboard Navigation
 *
 * Owns: #pal palette, #cheat cheatsheet, global keydown handler, #ov click-to-close.
 * Contract: fast-run.js (loads after this file) exposes window.__openFR and
 * window.__setScope. All cross-module calls are guarded.
 *
 * Data injected inline before this script:
 *   window.__CC.recipes  = [{label, nav_category}, ...]
 *   window.__CC.projects = ['Project A', 'Project B', ...]
 *   window.__CC.folders  = [{id, name}, ...]  (optional; refreshed live by
 *                          command-center.js fetchFolders → __refreshPaletteFolders)
 *   window.__CC.pinned   = 'Recipe Name'  (optional, string)
 *
 * ES5-style IIFE — no build step required.
 */
(function () {
  /* ── Data ──────────────────────────────────────────────────── */
  var CC = (window.__CC = window.__CC || {});
  var recipes = CC.recipes || [];
  var projects = CC.projects || [];
  var folders = CC.folders || [];

  /* Icon map: recipe label → lucide icon name */
  var ICON_MAP = {
    'Executive Dashboard':     'gauge',
    'Triage Prioritization':   'target',
    'CVE Impact':              'search',
    'Remediation Package':     'wrench',
    'Component Vuln Analysis': 'shield-alert',
    'Component List':          'package',
    'License Report':          'scale',
    'CRA Compliance':          'landmark',
    'Security Progress':       'trending-up',
    'Version Comparison':      'git-compare',
    'Customer Brief':          'file-text',
    'False Positive Analysis': 'flask-conical',
  };

  /* Build palette items */
  var ITEMS = [];

  /* Recipe items */
  recipes.forEach(function (r) {
    var icon = ICON_MAP[r.label] || 'play';
    ITEMS.push({
      type: 'Recipe',
      label: r.label,
      icon: icon,
      sub: 'run',
      run: function () {
        window.__openFR && window.__openFR(r.label);
      },
      _recipe: r,
    });
  });

  /* Project items.  Selecting a project sets the scope to that project (no
     folder) — same set-scope behavior as the run bar; a later run targets it. */
  function _makeProjectItem(p) {
    return {
      type: 'Project',
      label: p,
      icon: 'box',
      sub: 'set scope',
      run: function () {
        /* Project scope: project only, clearing any folder filter (project
           wins — fast-run.js drops folder_filter when a project is set). */
        window.__setScope && window.__setScope(p, '', '');
        /* #14: visible feedback — a scope-set used to silently do nothing. */
        window.__showToast && window.__showToast('Scope → ' + p);
      },
    };
  }
  projects.forEach(function (p) {
    ITEMS.push(_makeProjectItem(p));
  });

  /* Folder items — folder is a first-class selectable target (folder-targeting
     design §5). Folder values are IDs; labels are folder names.  Selecting a
     folder sets the scope to that folder (folder ID) with NO project, so a
     subsequent run targets the folder recursively (incl. subfolders).
     Distinguished from projects by a dedicated "Folder" group + folder icon. */
  function _folderId(f) {
    return f && (f.id !== undefined && f.id !== null) ? String(f.id) : '';
  }
  function _folderName(f) {
    return (f && (f.name || f.label)) || _folderId(f);
  }
  /* Build an INDENTED folder tree mirroring _scope_dropdowns.html's
     buildFolderTree (Finding 9): key children on parentFolderId (API field;
     fall back to parent_id), sort siblings by name, and prefix descendants with
     two spaces per depth so the palette folder list matches the run-bar /
     builder cascade tree instead of being a flat alphabetical list. Returns
     [{ id, label, raw }]; IDs stay the scope values, indented names the labels.
     A flat list (no resolvable parents) degrades to a plain alphabetical list,
     same as the cascade helper. */
  function _buildFolderTree(list) {
    var byParent = {};
    list.forEach(function (f) {
      var pid = f.parentFolderId || f.parent_id || '__root__';
      if (!byParent[pid]) byParent[pid] = [];
      byParent[pid].push(f);
    });
    var result = [];
    function walk(parentId, depth) {
      var children = byParent[parentId] || [];
      children.sort(function (a, b) { return _folderName(a).localeCompare(_folderName(b)); });
      children.forEach(function (f) {
        /* Indent with NBSP ( ) rather than plain spaces: the palette renders
           labels into a <div> (not an <option>), and HTML collapses leading/
           runs of normal whitespace — so a plain-space prefix would be invisible.
           Two NBSP per depth keeps the visible indentation the cascade shows. */
        var prefix = '';
        for (var i = 0; i < depth; i++) prefix += '  ';
        result.push({ id: _folderId(f), label: prefix + _folderName(f), raw: f });
        walk(f.id, depth + 1);
      });
    }
    walk('__root__', 0);
    if (result.length === 0) {
      list.slice().sort(function (a, b) {
        return _folderName(a).localeCompare(_folderName(b));
      }).forEach(function (f) {
        result.push({ id: _folderId(f), label: _folderName(f), raw: f });
      });
    }
    return result;
  }
  /* Build a Folder palette item from a tree node ({ id, label }).  `label`
     carries the indentation prefix; `id` is the scope value. */
  function _makeFolderItem(node) {
    var id = node.id;
    return {
      type: 'Folder',
      label: node.label,
      icon: 'folder',
      sub: 'set folder scope',
      run: function () {
        /* Folder scope: folder ID only, no project (folder-only → recursive
           folder-tree target). Mirrors run-bar folder-only selection. */
        window.__setScope && window.__setScope('', '', id);
        /* #14: feedback uses the folder NAME (node.raw), not the indented
           label or the bare ID. */
        window.__showToast && window.__showToast('Folder scope → ' + _folderName(node.raw));
      },
    };
  }
  /* Append Folder items for the given flat folder list, rendered as an indented
     tree (skip any node without an ID). Shared by init + __refreshPaletteFolders
     so both surfaces produce the same tree. */
  function _addFolderItems(list) {
    _buildFolderTree(list || []).forEach(function (node) {
      if (node.id) ITEMS.push(_makeFolderItem(node));
    });
  }
  _addFolderItems(folders);

  /* Create items — new Workflow / Compound / Comparison docs (PR1.5). */
  var CREATE = [
    ['New Workflow',   'workflow',    'workflow'],
    ['New Compound',   'layers',      'compound'],
    ['New Comparison', 'git-compare', 'comparison'],
  ];
  CREATE.forEach(function (c) {
    var label = c[0], icon = c[1], kind = c[2];
    ITEMS.push({
      type: 'Create',
      label: label,
      icon: icon,
      sub: 'open builder',
      run: function () {
        location.href = '/workflows/builder?kind=' + encodeURIComponent(kind) + '&new=1';
      },
    });
  });

  /* View items (hardcoded) */
  var VIEWS = [
    ['Scan Queue',     'radar',    '/queue',   null],
    ['Report History', 'folder-open', '/reports', null],
    ['Settings',       'sliders-horizontal', '/settings', null],
  ];
  VIEWS.forEach(function (v) {
    var label = v[0], icon = v[1], href = v[2], anchor = v[3];
    ITEMS.push({
      type: 'View',
      label: label,
      icon: icon,
      sub: 'navigate',
      run: function () {
        if (anchor) {
          var el = document.querySelector(anchor);
          if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
        } else {
          location.href = href;
        }
      },
    });
  });

  /* ── DOM refs ──────────────────────────────────────────────── */
  var ov    = document.getElementById('ov');
  var pal   = document.getElementById('pal');
  var q     = document.getElementById('pal-q');
  var list  = document.getElementById('pal-list');
  var cheat = document.getElementById('cheat');

  /* ── Palette state ─────────────────────────────────────────── */
  var sel = 0, results = [], flat = [];

  /* ── Fuzzy filter ──────────────────────────────────────────── */
  function score(it, toks) {
    var l = it.label.toLowerCase();
    for (var i = 0; i < toks.length; i++) {
      if (l.indexOf(toks[i]) < 0) return -1;
    }
    return 1;
  }

  function filter() {
    var v = q.value.trim().toLowerCase();
    var toks = v ? v.split(/\s+/) : [];
    results = ITEMS.filter(function (it) {
      return toks.length ? score(it, toks) >= 0 : true;
    });
    sel = 0;
    renderList();
  }

  /* ── Render grouped list ───────────────────────────────────── */
  function renderList() {
    var groups = {}, order = [];
    results.forEach(function (it) {
      if (!groups[it.type]) { groups[it.type] = []; order.push(it.type); }
      groups[it.type].push(it);
    });

    var html = '', idx = 0;
    flat = [];

    order.forEach(function (t) {
      html += '<div class="pal-grp">' + t + '</div>';
      groups[t].forEach(function (it) {
        var i = idx++;
        flat.push(it);
        var isSel = (i === sel);
        html += '<div class="pal-row' + (isSel ? ' sel' : '') + '" data-i="' + i + '">' +
          '<i data-lucide="' + it.icon + '"></i> ' + _esc(it.label) +
          (isSel
            ? '<span class="enter">↵ run</span>'
            : '<span class="sub">' + _esc(it.sub) + '</span>') +
          '</div>';
      });
    });

    if (!flat.length) html = '<div class="pal-grp">No matches</div>';
    list.innerHTML = html;
    if (window.lucide) lucide.createIcons();
    var s = list.querySelector('.pal-row.sel');
    if (s) s.scrollIntoView({ block: 'nearest' });
  }

  /* ── HTML escape helper ────────────────────────────────────── */
  function _esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /**
   * Refresh the project items in the palette with a new list of names.
   * Called by command-center.js after a best-effort fetch from the proxy.
   * Safe to call at any time; re-renders the palette list if it is open.
   */
  window.__refreshPaletteProjects = function (projectNames) {
    /* Remove existing Project-type items */
    ITEMS = ITEMS.filter(function (it) { return it.type !== 'Project'; });
    /* Add fresh project items */
    (projectNames || []).forEach(function (p) {
      ITEMS.push(_makeProjectItem(p));
    });
    /* Also update CC.projects so subsequent opens are aware */
    CC.projects = projectNames || [];
    /* If palette is open, re-render immediately */
    if (_palOpen()) filter();
  };

  /**
   * Refresh the folder items in the palette with a new list of folders.
   * Called by command-center.js after a best-effort fetch from the proxy.
   * Each folder is `{id, name}` (folder ID is the scope value; name is the
   * label). Safe to call at any time; re-renders the palette list if open.
   */
  window.__refreshPaletteFolders = function (folderList) {
    /* Remove existing Folder-type items */
    ITEMS = ITEMS.filter(function (it) { return it.type !== 'Folder'; });
    /* Add fresh folder items as an indented tree (Finding 9), matching the
       run-bar / builder cascade — skips any node without an ID. */
    _addFolderItems(folderList || []);
    /* Also update CC.folders so subsequent opens are aware */
    CC.folders = folderList || [];
    /* If palette is open, re-render immediately */
    if (_palOpen()) filter();
  };

  /* ── Active-scope indicator (#14) ──────────────────────────────
     Show what the palette / next run is currently scoped to, so a scope set is
     visible and recipes show the scope they'll target. Reads the LIVE scope via
     fast-run's __getScope and mirrors compute_effective_scope's precedence
     (project > folder > portfolio). Folder IDs are resolved to names via the
     palette's folder list (CC.folders) for a readable label. */
  function _folderNameById(id) {
    var fid = String(id || '');
    var fl = (CC && CC.folders) || [];
    for (var i = 0; i < fl.length; i++) {
      if (fl[i] && String(fl[i].id) === fid) return fl[i].name || fl[i].label || fid;
    }
    return fid;
  }
  function _scopeLabel() {
    var sc = (window.__getScope && window.__getScope()) ||
             { project: '', folder: '', version: '' };
    var project = String(sc.project || '').trim();
    var folder  = String(sc.folder  || '').trim();
    var version = String(sc.version || '').trim();
    if (project) return project + (version ? ' @ ' + version : '');
    if (folder)  return 'Folder: ' + _folderNameById(folder);
    return 'Portfolio';
  }
  function _renderScopeIndicator() {
    var el = document.getElementById('pal-scope');
    if (el) el.textContent = 'Scope: ' + _scopeLabel();
  }

  /* ── Open / close / activate ───────────────────────────────── */
  function openPal() {
    ov.classList.add('open');
    pal.classList.add('open');
    q.value = '';
    filter();
    _renderScopeIndicator();
    setTimeout(function () { q.focus(); }, 30);
  }

  function closePal() {
    pal.classList.remove('open');
    /* Only remove #ov.open if no other overlay is open */
    if (!document.getElementById('fr').classList.contains('open') &&
        !cheat.classList.contains('open')) {
      ov.classList.remove('open');
    }
  }

  function openCheat() {
    cheat.classList.add('open');
    ov.classList.add('open');
  }

  function closeAll() {
    pal.classList.remove('open');
    cheat.classList.remove('open');
    /* fast-run.js may not be loaded yet — guard */
    window.__closeFR && window.__closeFR();
    /* configure modal — command-center.js exposes __closeCfgModal */
    window.__closeCfgModal && window.__closeCfgModal();
    ov.classList.remove('open');
  }

  function activate(altEnter) {
    var it = flat[sel];
    if (!it) return;
    closePal();
    if (altEnter && it.type === 'Recipe') {
      /* Alt+Enter → configure: open prerun modal (no redirect) */
      if (window.__openConfigure) {
        window.__openConfigure(it.label);
      } else {
        /* Fallback: legacy redirect only if __openConfigure is absent */
        location.href = '/?configure=' + encodeURIComponent(it.label);
      }
    } else {
      it.run();
    }
  }

  /* ── Input + list interaction ──────────────────────────────── */
  if (q) q.addEventListener('input', filter);

  if (list) {
    list.addEventListener('click', function (e) {
      var r = e.target.closest('.pal-row');
      if (r) { sel = +r.dataset.i; activate(false); }
    });
  }

  /* ── Overlay click-to-close ────────────────────────────────── */
  if (ov) ov.addEventListener('click', closeAll);

  /* ── #kbar pill click ──────────────────────────────────────── */
  var kbar = document.getElementById('kbar');
  if (kbar) kbar.onclick = openPal;

  /* ── Overlay open check helpers ────────────────────────────── */
  function _palOpen()   { return pal   && pal.classList.contains('open');   }
  function _frOpen()    { var fr = document.getElementById('fr'); return fr && fr.classList.contains('open'); }
  function _cheatOpen() { return cheat && cheat.classList.contains('open'); }
  function _cfgOpen()   {
    var cfgModal = document.getElementById('cfg-modal');
    var cfgOv    = document.getElementById('cfg-ov');
    return (cfgModal && cfgModal.classList.contains('open')) ||
           (cfgOv    && cfgOv.classList.contains('open'));
  }
  function _anyOverlay() { return _palOpen() || _frOpen() || _cheatOpen() || _cfgOpen(); }

  /* ── go-key chord state ────────────────────────────────────── */
  var _goPending = 0; /* 0 = idle, 1 = waiting for second key */
  var _goTimer = null;

  function _clearGo() { _goPending = 0; _goTimer = null; }

  /* ── Global keydown handler ────────────────────────────────── */
  document.addEventListener('keydown', function (e) {
    /* ⌘K / Ctrl+K — always active, toggle palette */
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      _palOpen() ? closePal() : openPal();
      return;
    }

    /* Palette-specific navigation */
    if (_palOpen()) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        sel = Math.min(flat.length - 1, sel + 1);
        renderList();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        sel = Math.max(0, sel - 1);
        renderList();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        activate(e.altKey); /* Alt+Enter = configure */
      } else if (e.key === 'Escape') {
        closePal();
      }
      return;
    }

    /* Escape with no overlay open is a no-op; with overlay open, closeAll */
    if (e.key === 'Escape') { closeAll(); return; }

    /* Focus guard: typing in a form field OR any overlay open → suppress single-key shortcuts */
    var tag = (e.target.tagName || '').toUpperCase();
    var typing = (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' ||
                  e.target.isContentEditable);
    if (typing || _anyOverlay()) return;

    /* Single-key shortcuts */
    if (e.key === '/') { e.preventDefault(); openPal(); return; }
    if (e.key === '?') { openCheat(); return; }

    /* r — run pinned report */
    if (e.key.toLowerCase() === 'r' && !_goPending) {
      var pinned = (CC.pinned && CC.pinned.report) || CC.pinned_report || '';
      if (pinned) { window.__openFR && window.__openFR(pinned); }
      return;
    }

    /* g → chord: start 1.2s window */
    if (e.key.toLowerCase() === 'g') {
      _goPending = 1;
      if (_goTimer) clearTimeout(_goTimer);
      _goTimer = setTimeout(_clearGo, 1200);
      return;
    }

    /* Go-to chord second key */
    if (_goPending) {
      clearTimeout(_goTimer);
      _clearGo();
      var k = e.key.toLowerCase();
      if (k === 'q') {
        location.href = '/queue';
      } else if (k === 'r') {
        location.href = '/reports';
      } else if (k === 's') {
        location.href = '/settings';
      } else if (k === 'b') {
        location.href = '/workflows/builder';
      }
    }
  });

  /* ── #run= deep-link ───────────────────────────────────────── */
  if (location.hash.indexOf('#run=') === 0) {
    var _rr = decodeURIComponent(location.hash.slice(5)).replace(/\+/g, ' ');
    setTimeout(function () {
      window.__openFR && window.__openFR(_rr);
    }, 400);
  }

})();
