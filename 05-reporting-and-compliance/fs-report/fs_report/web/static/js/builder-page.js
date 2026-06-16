/* ===================================================================
 * Workflow Builder page (Pass 3 · Task 6) — AUTHORING.
 *
 * ONE Alpine component (`builder()`) owns the workflow model. SortableJS
 * provides drag-to-add (library -> canvas) and drag-to-reorder. The MODEL is
 * the single source of truth: indices, connector edges, step count, and cards
 * ALWAYS re-render from `model.steps` (Alpine x-for) — we never read step order
 * back out of the DOM. SortableJS's DOM mutations are immediately translated
 * into model mutations and the transient DOM node it created is removed so
 * Alpine can reconcile cleanly.
 *
 * Model shape (engine-key shape, matching workflow_store.py §4.1):
 *   {
 *     name: "",
 *     global: { project_filter, folder_filter, version_filter, period, start,
 *               end, ai, ai_depth, cache_ttl },
 *     steps: [ { id, kind, ref, overrides:{}, params:{} } ]
 *   }
 *
 * Task 7 wires the four interactions onto the same model:
 *   - Inspector (§5.4): selectStep opens a subtree-scoped, root-scoped per-step
 *     inspector; recipe fields write into step.overrides (engine keys), MCP
 *     params into step.params; the per-step Project/Version cascade re-inits
 *     per selection (unique ids so it can't collide with the global cascade).
 *   - Run animation (§6.3): runWorkflow POSTs {model}, opens the EXISTING SSE
 *     stream, maps each `step` event onto its card (queued/running/done/error/
 *     skipped) + connector lighting; Stop → cancel, Edit → back to authoring.
 *   - Export modal (§7): four tabs POST to /api/workflows/export and show the
 *     returned text; Copy (clipboard) + Download (Blob anchor, server filename).
 *   - Client preflight (§10): every runnable recipe step is validated against
 *     its EFFECTIVE config (global ← overrides) using the recipe requirement
 *     metadata from window.__CC — the same predicates the server backstops.
 * =================================================================== */

(function () {
  "use strict";

  /* Category color map — mirrors the --nav-* tokens so a step card's icon tile
     is tinted by its recipe category (MCP tools use the blue tool accent). */
  var NAV_COLORS = {
    Executive: "var(--nav-executive)",
    Investigation: "var(--nav-investigation)",
    Remediation: "var(--nav-remediation)",
    Compliance: "var(--nav-compliance)",
  };

  /* Per-step incrementing client id counter (no Math.random / Date.now).
     Prefixed "c" so a preserved persisted id (also "c<n>") slots into the same
     namespace; seedIdCounter() bumps _idc past any preserved numeric suffix so
     a freshly-added step can't collide with a loaded one (fix G). */
  var _idc = 0;
  function freshId() {
    _idc += 1;
    return "c" + _idc;
  }
  /* Bump the id counter past the max numeric suffix of any preserved id so a
     newly-generated freshId() can't collide with a loaded step's id. */
  function seedIdCounter(ids) {
    (ids || []).forEach(function (id) {
      var m = /^c(\d+)$/.exec(String(id || ""));
      if (m) {
        var n = parseInt(m[1], 10);
        if (n > _idc) _idc = n;
      }
    });
  }

  /* Mirror the server's bool coercion (run.py _coerce_workflow_value): a native
     boolean passes through; a string is truthy only when it is one of
     "true"/"on"/"1"/"yes" (case-insensitive) — so a string "false"/"0" is
     False, NOT the truthy bool("false") (fix F). */
  function coerceBool(value) {
    if (typeof value === "boolean") return value;
    if (value === null || value === undefined) return false;
    return ["true", "on", "1", "yes"].indexOf(String(value).toLowerCase()) !== -1;
  }

  /* #11 (B5): new workflows no longer auto-bake the Command Center pinned scope
     (window.__CC.pinned) into their global target — that silent baked-in scope
     was the bug.  blankModel() starts a workflow portfolio-wide; the target is an
     explicit author-time (rail) or run-time (scope_override) choice.  The old
     pinnedScope() seed helper was removed with its only caller. */

  /* blankModel(kind) — scaffold model for each editor kind.
     kind ∈ {workflow, compound, comparison}; defaults to "workflow".
     compound: full compound shape with sections, cover, output.
     comparison: minimal scaffold (PR3 will add axis/facets).
     workflow: full workflow shape. */
  function blankModel(kind) {
    kind = kind || "workflow";
    /* Non-workflow kinds (compound/comparison) carry kind: kind so the editor
       canvas can gate on model.kind.  Compound gets its full shape immediately;
       comparison is a minimal scaffold until PR3 adds axis/facets. */
    if (kind === "compound" || kind === "comparison") {
      /* Compound: full editor shape with sections, cover, output. */
      if (kind === "compound") {
        return {
          kind: "compound",
          name: "",
          title: "",
          /* #20 (B6): authored compounds carry a Description + Type so they
             aren't all defaulted to "Executive" (and the serializer emits
             nav_category — root of the #22 warning). */
          description: "",
          nav_category: "Executive",
          sections: [],
          cover: {
            subtitle: "",
            logo: "",
            classification: "",
          },
          output: {
            formats: ["html", "pdf"],
            toc: true,
            page_numbers: true,
          },
          /* Task C: the compound Global-Properties rail is now LIVE (parity with
             the workflow rail), bound to model.global.  Seed the SAME intent
             flags the workflow global carries (target_agnostic / target_dirty /
             period_touched / range_touched) so the shared rail bindings, the
             scope-seeding sentinel guards (onGlobalScopeChange), and the
             persisted-vs-run-only save split (M2-1) all behave identically. */
          global: {
            project_filter: "",
            folder_filter: "",
            version_filter: "",
            period: "30d",
            start: "",
            end: "",
            /* General (portfolio) vs target-bound — see the workflow global
               below for the full semantics.  A general compound's rail target is
               run-only (not baked into the saved doc); a target-bound compound
               persists it. */
            target_agnostic: false,
            /* Client-only dirty sentinel — a programmatic re-seed never marks it
               (mirrors the workflow global; NOT persisted). */
            target_dirty: false,
            /* C1 date-mode intent flags (default-off) — steer period↔range
               precedence and round-trip through _compoundSaveBody/global. */
            period_touched: false,
            range_touched: false,
            finding_types: "",
            ai: false,
            ai_depth: "summary",
            cache_ttl: "4h",
          },
          steps: [],
        };
      }
      /* Comparison: full editor shape with L/R scope, sections, output.
         Left/Right hold NAME components (not scope-ref strings) — baking
         to scope-ref strings happens server-side via _build_scope_ref on Save. */
      return {
        kind: "comparison",
        name: "",
        title: "",
        /* #20 (B6): Description + Type, same as compound. */
        description: "",
        nav_category: "Executive",
        /* Left and Right scope name components.  The cascade selects use IDs
           as option VALUES; onChange handlers read selectedOptions[0].textContent
           to get the NAME (label) and write it here. */
        left: { project: "", folder: "", version: "" },
        right: { project: "", folder: "", version: "" },
        /* sections: array of comparison facet slugs selected from the diff rail. */
        sections: [],
        output: {
          formats: ["html", "pdf"],
          toc: true,
          page_numbers: true,
        },
        /* Include empty global/steps so shared code paths that read
           model.global or model.steps don't throw. */
        global: {
          project_filter: "",
          folder_filter: "",
          version_filter: "",
          period: "30d",
          start: "",
          end: "",
          ai: false,
          ai_depth: "summary",
          cache_ttl: "4h",
        },
        steps: [],
      };
    }
    /* workflow (default).  #11 (B5): do NOT bake the Command Center pinned
       scope into a new workflow's global target.  An auto-baked target was the
       "target baked in / can't re-target" bug — it silently scoped every run to
       whatever was pinned.  New workflows now start portfolio-wide (no global
       scope); setting a scope in the global rail is the explicit, persisted
       target (author-time), and scope_override re-targets a run without editing
       the saved doc (run-time, not persisted). */
    return {
      kind: "workflow",
      name: "",
      global: {
        project_filter: "",
        folder_filter: "",
        version_filter: "",
        period: "30d",
        start: "",
        end: "",
        /* C2: target-bound (default) vs general workflow.  A fresh workflow is
           target-bound (false) — the global rail target is the persisted target.
           Flip to true to author a "general"/portfolio workflow whose target is
           chosen at run time (Global-Properties → scope_override) and is NOT
           baked into the saved/exported doc. */
        target_agnostic: false,
        /* C2: client-only dirty sentinel — true once the USER picks a global
           target (so a programmatic re-seed / a load can't clobber their
           choice).  Reset on every blank/new/load.  NOT persisted (stripped in
           toEngineModel). */
        target_dirty: false,
        ai: false,
        ai_depth: "summary",
        cache_ttl: "4h",
      },
      steps: [],
    };
  }

  /* _loadEndpointFor(kind, slug) — pure helper: returns the API URL to load a
     doc given its kind and slug.  Compound/comparison → /api/builder/recipes/;
     workflow or no kind → /api/workflows/.  Exposed as a module-level helper
     so tests can exercise the routing logic without Alpine. */
  function _loadEndpointFor(kind, slug) {
    if (kind === "compound" || kind === "comparison") {
      return "/api/builder/recipes/" + encodeURIComponent(slug);
    }
    return "/api/workflows/" + encodeURIComponent(slug);
  }
  /* Expose for test harnesses. */
  window._loadEndpointFor = _loadEndpointFor;

  /* Lookup of recipe metadata (kind/title/tool/cat) by ref, built once from the
     library DOM so step cards can render a title/tool/icon from `ref` alone. */
  var LIB = {};
  function buildLibIndex(root) {
    LIB = {};
    root.querySelectorAll(".wfb-libitem").forEach(function (el) {
      var ref = el.getAttribute("data-ref");
      if (!ref || LIB[ref]) return;
      LIB[ref] = {
        kind: el.getAttribute("data-kind") || "recipe",
        title: el.getAttribute("data-title") || ref,
        tool: el.getAttribute("data-tool") || "run_recipe",
        cat: el.getAttribute("data-cat") || "",
        icon: (function () {
          var i = el.querySelector(".li-ic [data-lucide]");
          return i ? i.getAttribute("data-lucide") : "file-text";
        })(),
      };
    });
  }

  /* Canonical slug normalization — mirrors fs_report.slug.slug (lowercase,
     trim, map every non-alphanumeric run to "-", strip leading/trailing "-").
     The server resolves a step `ref` to a recipe by SLUG (_resolve_recipe_ref →
     slug(ref) == slug(recipe.name)), so the client MUST compare the same way or
     a slug-form ref (e.g. "executive-summary") is wrongly flagged unresolved
     here though the server runs it (M1-3).  The empty-input fallback differs
     from the Python helper's "section" sentinel only for an all-punctuation
     input, which can't be a real recipe ref — harmless for matching. */
  function slug(s) {
    return String(s == null ? "" : s)
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  function csrf() {
    return window.NONCE || "";
  }

  function apiJSON(method, url, body) {
    var opts = {
      method: method,
      headers: { "X-FS-Session": csrf() },
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(url, opts).then(function (r) {
      return r
        .json()
        .catch(function () {
          return {};
        })
        .then(function (data) {
          return { ok: r.ok, status: r.status, data: data };
        });
    }).catch(function (err) {
      /* fetch() itself rejected (offline / server unreachable).  Normalise to
         the same shape callers handle so no unhandled rejection escapes. */
      return { ok: false, status: 0, data: { error: "Network error: " + (err && err.message || err) } };
    });
  }

  function toast(msg) {
    /* Reuse the shell toast if present; otherwise fall back to a console log so
       the authoring flow never throws on a missing chrome element. */
    if (typeof window.fsToast === "function") {
      window.fsToast(msg);
      return;
    }
    var t = document.getElementById("toast");
    if (t) {
      var m = document.getElementById("toast-msg");
      if (m) m.textContent = msg;
      t.classList.add("show");
      clearTimeout(toast._t);
      toast._t = setTimeout(function () {
        t.classList.remove("show");
      }, 1800);
    } else {
      console.log("[builder]", msg);
    }
  }

  function relucide() {
    if (window.lucide) window.lucide.createIcons();
  }

  /* Canonical MCP-tool param specs (id -> {id,title,tool,icon,params}), bootstrapped
     from the page route via window.__WFB_MCP.  The inspector reads each tool's
     editable params from here so there is no second source of truth. */
  function mcpToolSpec(toolId) {
    var list = window.__WFB_MCP || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i] && list[i].id === toolId) return list[i];
    }
    return null;
  }

  /* Per-recipe requirement flags from the shell's window.__CC.recipes bootstrap
     (build_shell_context exposes requires_cve / requires_project /
     requires_project_or_folder + scope_req).  Matched by SLUG so the client and
     server agree on resolution: the server resolves a step `ref` by
     slug(ref) == slug(recipe.name) (_resolve_recipe_ref), so a slug-form ref
     like "executive-summary" must resolve here too (M1-3).  These are the SAME
     predicates the server preflight evaluates (the #10 mirror). */
  function recipeFlags(ref) {
    var cc = window.__CC || {};
    var recipes = cc.recipes || [];
    var want = slug(ref);
    for (var i = 0; i < recipes.length; i++) {
      var r = recipes[i];
      if (r && slug(r.name) === want) return r;
    }
    return null;
  }

  /* scope_req for a recipe ref ("project" | "project_or_folder" | "").  Prefer
     the dedicated scopeReq map (keyed lowercase by recipe name); a slug-form ref
     won't hit those lowercase-name keys directly, so probe by slug too — the
     resolved recipe's name keys the map.  Fall back to the recipe's own requires
     flags. */
  function recipeScopeReq(ref) {
    var cc = window.__CC || {};
    var scopeReq = cc.scopeReq || {};
    var want = slug(ref);
    /* Match a scopeReq entry whose (slugged) recipe-name key equals the slugged
       ref — so client and server resolve the same recipe regardless of whether
       the ref is a name or a slug. */
    var keys = Object.keys(scopeReq);
    for (var i = 0; i < keys.length; i++) {
      if (slug(keys[i]) === want) return scopeReq[keys[i]] || "";
    }
    var r = recipeFlags(ref);
    if (!r) return "";
    if (r.requires_project) return "project";
    if (r.requires_project_or_folder) return "project_or_folder";
    return "";
  }

  /* The Alpine component factory. Registered on window so the inline
     x-data="builder()" can find it. */
  function builderComponent() {
    return {
      model: blankModel(),
      saved: [],
      loadedSlug: "",
      selected: null,
      /* Task C: index of the selected compound SECTION (parallel to `selected`
         for steps), or null.  Drives inspSection() + the compound section
         inspector.  Reset on load / new / kind switch. */
      selectedSection: null,
      isSaving: false,
      _sortableInited: false,

      /* ---- compound-specific state ---- */
      _compoundSortableInited: false,
      _compoundSavedSnapshot: "",
      _comparisonSavedSnapshot: "",

      /* ---- comparison-specific state ---- */
      /* Guard flags so the two Left/Right scope cascades are only initialized
         once (mirrors the _inspScopeStep pattern for the inspector cascade). */
      _cmpScopesInited: false,

      /* ---- Task D: inline-run drawer state (compound/comparison) ----
         cpdRunOpen drives the right-side drawer that hosts the prerun fragment
         (the run surface for compound + comparison docs).  Opened by the
         runTriggers in _recipeKindCfg via __openInlineRun; closed by the
         fragment's Cancel/×, the scrim, or Escape. */
      cpdRunOpen: false,

      /* ---- run-view state (§6.3) ---- */
      runMode: false, // canvas flipped into the read-only run view
      runDone: false, // terminal `done` received
      isRunning: false, // in-flight guard on Run (mirrors isSaving)
      runId: null,
      runStatus: "", // last terminal status: success|error|cancelled
      runStates: {}, // step_id -> {state, message, files, report_url, reason}
      _es: null, // the live EventSource (closed on terminal done / leave)

      /* ---- export-modal state (§7) ---- */
      exportOpen: false,
      exportTarget: "cli",
      exportText: "",
      exportFilename: "",
      exportLoading: false,
      exportTargets: [
        { target: "cli", label: "CLI", icon: "terminal" },
        { target: "forge_yaml", label: "Forge YAML", icon: "file-text" },
        { target: "github_action", label: "GitHub Action", icon: "git-branch" },
        { target: "forge_mcp", label: "Forge MCP", icon: "bot" },
      ],

      /* ---- "+ New ▾" menu state ---- */
      newMenuOpen: false,

      /* ---- compound SECTION inspector cascade re-init guard (mirrors the
         per-step _inspScope* guards; keyed by selected-section index since a
         section has no stable id) ---- */
      _secScopeIndex: null,
      _secScopeTries: 0,
      _secScopeRetry: null,
      _secScopeBindingIndex: null,

      /* ---- inspector cascade re-init guard (I3 init-once trap) ---- */
      _inspScopeStep: null,
      /* Bounded retry counter for bindInspectorScope when the inspector's
         x-if selects haven't rendered yet (T6 self-healing bind). */
      _inspScopeTries: 0,
      _inspScopeRetry: null, // pending bind-retry timer; cleared on step change / success
      _inspScopeBindingStep: null, // step id the retry budget is currently counting for

      /* ---- C2: scope-seeding sentinel + generation guard ----
         _scopeSeeding is TRUE for the WHOLE programmatic seed cascade fired by
         initScope() (folder→project→version restore, incl. the async version
         resolve).  While true, the global cascade's onChange handlers
         (onGlobalScopeChange / onGlobalProjectChange) reflect the seeded scope
         into the model BUT must NOT mark the target dirty and must NOT clobber a
         user-dirty target — so a programmatic re-seed can never overwrite the
         user's chosen target.  It is cleared by initScope's onReady callback,
         fired only after the LAST seed emit lands.

         _scopeSeedGen is a monotonic token: each programmatic re-seed
         increments+captures it; a stale cycle's onReady (from an overlapping
         ?load deep-link double-init) only clears _scopeSeeding when its captured
         generation still equals the current token — so a stale onReady can't
         clear the sentinel of a newer in-flight seed. */
      _scopeSeeding: false,
      _scopeSeedGen: 0,

      /* ---- lifecycle ---- */
      init: function () {
        var self = this;
        /* #7 (B6): drop the Forge export targets unless the Forge/MCP surface is
           enabled (window.__WFB_FORGE_ENABLED, default OFF).  The backend export
           endpoint still accepts them — only the UI tabs are hidden. */
        if (!window.__WFB_FORGE_ENABLED) {
          this.exportTargets = this.exportTargets.filter(function (t) {
            return t.target !== "forge_yaml" && t.target !== "forge_mcp";
          });
        }
        buildLibIndex(this.$el);
        this.refreshSaved();
        /* C2: initScope() must run EXACTLY ONCE after the query-param dispatch,
           for ALL branches — load/blank the model FIRST, then seed the cascade
           once.  The old code called initScope() BEFORE the query block (so a
           ?load deep-link double-seeded: once here on the blank model, once
           again in loadBySlug's $nextTick).  Now:
             • ?load=<slug>  → loadByKindAndSlug → loadBySlug/loadRecipeBySlug
               own the single initScope() in their success $nextTick (model is
               loaded first), so init() does NOT seed here.
             • ?new=1 / default → init() seeds once below (model already
               blank). */
        var didLoad = false;
        try {
          var params = new URLSearchParams(window.location.search);
          var kindParam = params.get("kind") || "workflow";
          var newParam  = params.get("new");
          var loadSlug  = params.get("load");
          if (newParam === "1") {
            /* Fresh editor of the requested kind. */
            this.model = blankModel(kindParam);
          } else if (loadSlug) {
            /* Route by kind via _loadEndpointFor — single source of truth.  The
               loader re-seeds the cascade once on success (model loaded first). */
            didLoad = true;
            this.loadByKindAndSlug(kindParam, loadSlug);
          }
          /* Neither → model already set to blankModel("workflow") by default above. */
        } catch (e) {
          /* no query / unsupported — ignore */
        }
        /* Seed the global cascade exactly once for the non-load branches (the
           load branches seed inside their own success handler so the model is
           in place before seeding). */
        if (!didLoad) {
          this.initScope();
        }
        /* Task D: register the inline-run drawer open/close hooks with
           command-center.js so its inline ctx can flip the Alpine flag without
           knowing about Alpine.  Bound to this component instance. */
        if (typeof window.__registerInlineRunDrawer === "function") {
          window.__registerInlineRunDrawer(
            function () { self.openCpdRun(); },
            function () { self.closeCpdRun(); }
          );
        }
        /* Wire SortableJS after the first Alpine render flush so the pipeline
           container exists and x-for has painted any seeded steps. */
        this.$nextTick(function () {
          self.initSortable();
          self.initCompoundSortable();
          /* Load logos for compound editor if kind is compound. */
          if (self.model.kind === "compound") {
            self.loadLogos();
          }
          /* PR3.1: initialize comparison scope cascades when opening a comparison. */
          if (self.model.kind === "comparison") {
            self.initCmpScopes();
          }
          relucide();
        });
      },

      /* Root-scoped, folder-less Project -> Version cascade for the global
         scope. The {root} + optional-folderId form (Task 3) lets this coexist
         with the per-step inspector cascades added in Task 7.

         The MODEL is authoritative — it is seeded from the pinned scope (init,
         via blankModel) or from the loaded workflow (load, via fromEngineModel),
         and the `:data-value` bindings reflect that model onto the <select>s.
         initScopeDropdowns reads each select's data-value and SELECTS it once
         the async /fsapi options load — so the cascade DISPLAYS the model's
         scope.  There is NO read-back of the select values into the model: a
         programmatic `.value` write fires no `change` event (which is exactly
         why the model, not the select, must be the seed source), and the
         @change handlers are the only writers for subsequent user edits.
         Called on init AND on load (re-seeds the cascade for the new scope —
         the data-value attrs already reflect the updated model). */
      initScope: function () {
        if (typeof window.initScopeDropdowns !== "function") return;
        var self = this;
        /* C2: open a new seeding generation.  Set the sentinel BEFORE kicking
           off the cascade so EVERY programmatic onChange emit during this seed
           (folder/project/version) is treated as seeding (no dirty-mark, no
           clobber of a user-dirty target).  Capture the generation so a stale
           cycle's onReady can't clear a newer seed's sentinel. */
        this._scopeSeedGen++;
        var gen = this._scopeSeedGen;
        this._scopeSeeding = true;
        window.initScopeDropdowns({
          root: this.$el,
          /* Folder targeting (design §6): the global cascade now owns a folder
             select too (#g-folder).  onChange is the single writer that keeps
             the model's folder/project in sync as the cascade resolves — a
             folder change re-filters projects + clears the project, and the
             cascade applies project-wins by clearing folder when a project is
             chosen (mirrored into the model here). */
          folderId: "g-folder",
          projectId: "g-project",
          versionId: "g-version",
          onChange: function (scope) {
            self.onGlobalScopeChange(scope);
          },
          /* Cleared only after the LAST seed emit lands (incl. the async
             version restore).  Generation guard: a stale onReady (overlapping
             ?load double-init) is ignored. */
          onReady: function () {
            if (self._scopeSeedGen === gen) {
              self._scopeSeeding = false;
            }
          },
        });
      },

      /* The global scope cascade changed (folder / project / version).  Write
         the model authoritatively with project-wins precedence: when a project
         is selected the folder is only a UI filter, so clear the model's
         folder_filter (mirrors the server / serializer drop).  A folder-only
         selection (no project) keeps the folder and clears the version. */
      onGlobalScopeChange: function (scope) {
        /* C2: during the programmatic seed cascade (_scopeSeeding) this fires
           with the SEEDED scope.  Two guards:
             1. If the target is already user-dirty, DON'T let a programmatic
                re-seed clobber it (the user's choice wins over a stray re-seed).
             2. Never mark the target dirty for a seed emit — only a real user
                change (sentinel false) marks dirty. */
        if (this._scopeSeeding && this.model.global.target_dirty) return;
        scope = scope || {};
        var project = scope.project || "";
        this.model.global.project_filter = project;
        this.model.global.version_filter = scope.version || "";
        this.model.global.folder_filter = project ? "" : scope.folder || "";
        if (!this._scopeSeeding) this.model.global.target_dirty = true;
      },

      /* User picked a global project directly (kept for the @change binding):
         write it, clear the version, and drop any folder (project wins).
         C2: same seed/dirty guards as onGlobalScopeChange — a programmatic seed
         never clobbers a dirty target nor marks dirty. */
      onGlobalProjectChange: function (value) {
        if (this._scopeSeeding && this.model.global.target_dirty) return;
        this.model.global.project_filter = value || "";
        this.model.global.version_filter = "";
        if (value) this.model.global.folder_filter = "";
        if (!this._scopeSeeding) this.model.global.target_dirty = true;
      },

      /* C2: the current Global-Properties target as a run-time scope_override
         (project wins; folder-only otherwise).  Returns null when portfolio-wide
         (no project AND no folder) so a run doesn't force a deliberate clear —
         the server treats an absent override as "no override".  Sent by
         runWorkflow so the run honors the live target without editing the doc. */
      _currentScopeOverride: function () {
        var g = this.model.global || {};
        var project = String(g.project_filter || "").trim();
        var folder = String(g.folder_filter || "").trim();
        if (!project && !folder) return null;
        return {
          project: project,
          folder: project ? "" : folder,
          version: project ? g.version_filter || "" : "",
        };
      },

      /* Task D: open/close the inline-run drawer (compound/comparison run
         surface).  __openInlineRun (command-center.js) drives the actual
         fragment fetch + wiring; these only toggle the Alpine flag so the
         drawer slides in/out.  closeCpdRun is also wired to the scrim, Escape,
         and the fragment's Cancel/× via the container-aware close. */
      openCpdRun: function () {
        this.cpdRunOpen = true;
        this.$nextTick(function () { relucide(); });
      },
      closeCpdRun: function () {
        this.cpdRunOpen = false;
      },

      /* ---- "+ New ▾" menu (#4, B5) ----------------------------------------
         The dropdown is position:fixed (builder-page.css) so it escapes the
         .wfb-rail overflow clipping context that made the menu look dead.  We
         anchor it to the trigger button's viewport rect on open, right-aligned
         and viewport-clamped, and dismiss on any scroll/resize/Escape so a
         fixed layer never floats detached from its trigger. */
      toggleNewMenu: function (ev) {
        if (this.newMenuOpen) {
          this.closeNewMenu();
          return;
        }
        var btn = (ev && ev.currentTarget) || this.$el.querySelector("#wf-new");
        this.newMenuOpen = true;
        var self = this;
        this.$nextTick(function () { self._positionNewMenu(btn); });
        this._newMenuDismiss = function () {
          self.closeNewMenu();
        };
        /* capture=true so a scroll inside .wfb-rail (which doesn't bubble to
           window) still dismisses the anchored menu. */
        window.addEventListener("scroll", this._newMenuDismiss, true);
        window.addEventListener("resize", this._newMenuDismiss, true);
      },
      closeNewMenu: function () {
        this.newMenuOpen = false;
        if (this._newMenuDismiss) {
          window.removeEventListener("scroll", this._newMenuDismiss, true);
          window.removeEventListener("resize", this._newMenuDismiss, true);
          this._newMenuDismiss = null;
        }
      },
      _positionNewMenu: function (btn) {
        var menu = this.$refs.newMenu;
        if (!menu || !btn) return;
        var r = btn.getBoundingClientRect();
        /* offsetWidth is readable here because $nextTick defers until Alpine
           has applied x-show (display becomes block before this runs).
           Right-align to the button, then clamp into the viewport. */
        var w = menu.offsetWidth || 140;
        var left = Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8));
        menu.style.top = r.bottom + 4 + "px";
        menu.style.left = left + "px";
      },

      /* The global scope readout label (the canvas scope pill).  Project wins;
         else a folder shows its NAME (resolved from the #g-folder select's
         selected option, since the model stores the folder ID); else
         "Portfolio".  Folder targeting (design §6).  Read-only rendering — it
         reads option labels to display a name, never writes the model. */
      globalScopeLabel: function () {
        var g = this.model.global || {};
        if (g.project_filter) return g.project_filter;
        if (g.folder_filter) {
          var sel = this.$el.querySelector("#g-folder");
          if (sel) {
            for (var i = 0; i < sel.options.length; i++) {
              if (sel.options[i].value === String(g.folder_filter)) {
                /* The option label may carry tree-indent whitespace — trim it. */
                return (sel.options[i].textContent || "").trim() || g.folder_filter;
              }
            }
          }
          return g.folder_filter;
        }
        return "Portfolio";
      },

      /* True when the global scope targets a folder (no project) — drives the
         readout to hide the "@ version" suffix (folders have no version). */
      globalIsFolder: function () {
        var g = this.model.global || {};
        return !g.project_filter && !!g.folder_filter;
      },

      /* C2: the scope-pill tooltip.  A target-bound workflow with a concrete
         target is a "Pinned scope — applied to every run".  A GENERAL
         (target_agnostic) or portfolio-wide workflow has no pinned scope — the
         target is picked at run time — so it must NOT claim "Pinned scope". */
      globalScopePillTitle: function () {
        var g = this.model.global || {};
        var hasTarget = !!g.project_filter || !!g.folder_filter;
        // Mirror the preflight split: an explicitly general workflow picks its
        // target at run time, whereas a target-bound workflow that simply has
        // no scope yet should be told to set one (don't conflate the two).
        if (coerceBool(g.target_agnostic)) {
          return "Portfolio-wide — pick a target at run time";
        }
        if (!hasTarget) {
          return "No global scope set — set a target for this workflow";
        }
        return "Pinned scope — applied to every run";
      },

      /* ---- model -> card helpers (render purely from the model) ---- */
      meta: function (step) {
        return LIB[step.ref] || { title: step.ref, tool: step.kind === "mcp_tool" ? step.ref : "run_recipe", icon: "file-text", cat: "" };
      },
      titleFor: function (step) {
        return this.meta(step).title;
      },
      toolFor: function (step) {
        return this.meta(step).tool;
      },
      iconFor: function (step) {
        return this.meta(step).icon;
      },
      catColor: function (step) {
        if (step.kind === "mcp_tool") return "var(--blue)";
        return NAV_COLORS[this.meta(step).cat] || "var(--purple)";
      },
      overrideCount: function (step) {
        var ov = step.overrides || {};
        return Object.keys(ov).filter(function (k) {
          return ov[k] !== null && ov[k] !== undefined && ov[k] !== "";
        }).length;
      },
      aiOn: function (step) {
        var ov = step.overrides || {};
        if (ov.ai !== undefined && ov.ai !== null) return coerceBool(ov.ai);
        return coerceBool(this.model.global.ai);
      },

      /* A recipe step is UNRESOLVED when its `ref` is not in the known recipe
         set (window.__CC.recipes).  Per spec §10 an unresolvable recipe ref is
         flagged in the UI + excluded from the local run (still preserved for
         export).  MCP-tool steps are never "unresolved recipes". */
      isUnresolvedRecipe: function (step) {
        if (!step || step.kind !== "recipe") return false;
        return !recipeFlags(step.ref);
      },

      /* ---- step mutations (the model is the source of truth) ---- */
      addStep: function (kind, ref, index) {
        /* Seed an mcp_tool step's params with that tool's DECLARED defaults so
           the client model reflects them immediately (fix C) — mirrors the
           server's fill_mcp_defaults on normalize.  Declared defaults only;
           required-no-default params stay empty (validation catches them). */
        var seededParams = {};
        if (kind === "mcp_tool") {
          var spec = mcpToolSpec(ref);
          if (spec && spec.params) {
            Object.keys(spec.params).forEach(function (k) {
              var p = spec.params[k];
              if (p && Object.prototype.hasOwnProperty.call(p, "default")) {
                seededParams[k] = p.default;
              }
            });
          }
        }
        var step = { id: freshId(), kind: kind, ref: ref, overrides: {}, params: seededParams };
        var i = index;
        if (i === undefined || i === null || i > this.model.steps.length || i < 0) {
          i = this.model.steps.length;
        }
        this.model.steps.splice(i, 0, step);
        this.$nextTick(function () {
          relucide();
        });
        toast("Added " + this.titleFor(step));
      },
      removeStep: function (id) {
        this.model.steps = this.model.steps.filter(function (s) {
          return s.id !== id;
        });
        if (this.selected === id) this.selected = null;
      },
      moveStep: function (oldIndex, newIndex) {
        if (
          oldIndex === newIndex ||
          oldIndex < 0 ||
          newIndex < 0 ||
          oldIndex >= this.model.steps.length ||
          newIndex >= this.model.steps.length
        ) {
          return;
        }
        var arr = this.model.steps;
        var moved = arr.splice(oldIndex, 1)[0];
        arr.splice(newIndex, 0, moved);
      },
      /* ---- compound section ops (PR2.2a; Task C: sections-as-objects) ---- */
      /* secRecipe(sec) — read the recipe NAME from a section, tolerant of both
         the lean object shape ({recipe, overrides}) and a legacy bare string.
         The on-load migration (loadRecipeBySlug) normalizes to objects, but the
         render + helpers stay defensive so a stray string never throws. */
      secRecipe: function (sec) {
        if (sec == null) return "";
        return typeof sec === "string" ? sec : (sec.recipe || "");
      },

      /* addSection(recipeName) — append a section OBJECT ({recipe, overrides})
         to the compound section list.  Task C: sections are objects so each can
         carry per-section overrides (string back-compat is handled on load).
         Duplicate sections are allowed (mirrors workflow step allowance).  Wired
         from the Add-section palette click handlers. */
      addSection: function (recipeName) {
        if (!recipeName) return;
        if (!Array.isArray(this.model.sections)) this.model.sections = [];
        this.model.sections.push({ recipe: recipeName, overrides: {} });
        var self = this;
        this.$nextTick(function () {
          relucide();
        });
        toast("Added " + recipeName);
      },

      /* removeSection(index) — remove the section at the given index.  Keep the
         selection consistent (mirrors removeStep): clear it if the removed
         section was selected, else shift it down when a section before it went
         away so the inspector stays on the same section object. */
      removeSection: function (index) {
        if (!Array.isArray(this.model.sections)) return;
        this.model.sections.splice(index, 1);
        if (this.selectedSection === index) {
          this.selectedSection = null;
        } else if (this.selectedSection != null && this.selectedSection > index) {
          this.selectedSection -= 1;
        }
      },

      /* moveSectionByIndex(oldIndex, newIndex) — reorder a section in the list.
         Called by the SortableJS compound receiver's onUpdate handler.  Keep the
         selection pinned to the SAME section object as it moves. */
      moveSectionByIndex: function (oldIndex, newIndex) {
        if (!Array.isArray(this.model.sections)) return;
        var arr = this.model.sections;
        if (
          oldIndex === newIndex ||
          oldIndex < 0 ||
          newIndex < 0 ||
          oldIndex >= arr.length ||
          newIndex >= arr.length
        ) {
          return;
        }
        var moved = arr.splice(oldIndex, 1)[0];
        arr.splice(newIndex, 0, moved);
        /* Follow the moved section if it was the selected one; otherwise adjust
           the selected index for the shift. */
        if (this.selectedSection === oldIndex) {
          this.selectedSection = newIndex;
        } else if (this.selectedSection != null) {
          var s = this.selectedSection;
          if (oldIndex < s && newIndex >= s) this.selectedSection = s - 1;
          else if (oldIndex > s && newIndex <= s) this.selectedSection = s + 1;
        }
      },

      /* ---- compound SECTION inspector (Task C) ---- */
      /* selectSection(index) — toggle selection of a compound section row
         (parallel to selectStep).  Re-binds the section scope cascade on the
         next tick.  No-op in run-view (compounds don't run-stream in the canvas
         today, but mirror the workflow guard for safety). */
      selectSection: function (index) {
        if (this.runMode) return;
        this.selectedSection = this.selectedSection === index ? null : index;
        var self = this;
        this.$nextTick(function () {
          relucide();
          self.bindSectionScope();
        });
      },

      /* inspSection() — the currently-inspected SECTION object, or null.  The
         section is the LEAN {recipe, overrides} shape (NOT a step), so callers
         must NOT deref step-only fields.  Null-safe: returns null when nothing
         is selected, the index is out of range, or sections is absent. */
      inspSection: function () {
        if (this.model.kind !== "compound") return null;
        if (this.selectedSection == null) return null;
        var secs = this.model.sections;
        if (!Array.isArray(secs)) return null;
        var i = this.selectedSection;
        if (i < 0 || i >= secs.length) return null;
        var sec = secs[i];
        if (sec == null) return null;
        /* Defensive: a bare-string section (pre-migration / hand-authored) is
           upgraded in place so the inspector always edits an object with an
           overrides bag. */
        if (typeof sec === "string") {
          sec = { recipe: sec, overrides: {} };
          secs[i] = sec;
        }
        if (!sec.overrides || typeof sec.overrides !== "object") sec.overrides = {};
        return sec;
      },

      /* secOverrideCount(sec) — non-empty whitelisted override count for a
         section, for the row's "· N overrides" chip (mirrors overrideCount). */
      secOverrideCount: function (sec) {
        var ov = (sec && sec.overrides) || {};
        return Object.keys(ov).filter(function (k) {
          return ov[k] !== null && ov[k] !== undefined && ov[k] !== "";
        }).length;
      },

      /* secApplyOverride(key, value) — write (or CLEAR on empty) a per-SECTION
         override.  Mirrors applyOverride but targets inspSection().overrides
         (NOT step.overrides).  Same period↔range mutual exclusion. */
      secApplyOverride: function (key, value) {
        var sec = this.inspSection();
        if (!sec) return;
        if (!sec.overrides) sec.overrides = {};
        if (value === "" || value === null || value === undefined) {
          delete sec.overrides[key];
        } else {
          sec.overrides[key] = value;
          if (key === "start" || key === "end") {
            var willHaveStart = key === "start" ? !!value : !!sec.overrides.start;
            var willHaveEnd = key === "end" ? !!value : !!sec.overrides.end;
            if (willHaveStart && willHaveEnd) delete sec.overrides.period;
          } else if (key === "period" && value) {
            delete sec.overrides.start;
            delete sec.overrides.end;
          }
        }
        this.afterInspectorChange();
      },

      /* secResetOverrides() — clear all overrides for the selected section. */
      secResetOverrides: function () {
        var sec = this.inspSection();
        if (!sec) return;
        sec.overrides = {};
        /* Re-seed the section scope cascade so the dropdowns drop back to
           "(inherit from global)" — force a rebind by clearing the guard. */
        this._secScopeIndex = null;
        var self = this;
        this.$nextTick(function () {
          relucide();
          self.bindSectionScope();
        });
      },

      /* secAiOn(sec) — effective AI for a section: the section override when
         present, else the global (mirrors aiOn for steps). */
      secAiOn: function (sec) {
        var ov = (sec && sec.overrides) || {};
        if (ov.ai !== undefined && ov.ai !== null) return coerceBool(ov.ai);
        return coerceBool(this.model.global.ai);
      },

      /* secToggleAi() — per-section AI toggle: write `ai` only when it DIFFERS
         from the global (matching the global clears the override = inherit). */
      secToggleAi: function () {
        var sec = this.inspSection();
        if (!sec) return;
        if (!sec.overrides) sec.overrides = {};
        var now = !this.secAiOn(sec);
        if (now === coerceBool(this.model.global.ai)) {
          delete sec.overrides.ai;
        } else {
          sec.overrides.ai = now;
        }
        this.afterInspectorChange();
      },

      /* secCvoOn / secToggleCvo — DEFAULT-TRUE current_version_only override for
         a section (same semantics as cvoOn/toggleCvo for steps). */
      secCvoOn: function (sec) {
        if (!sec || !sec.overrides) return true;
        return sec.overrides.current_version_only === undefined
          ? true
          : coerceBool(sec.overrides.current_version_only);
      },
      secToggleCvo: function () {
        var sec = this.inspSection();
        if (!sec) return;
        if (!sec.overrides) sec.overrides = {};
        if (this.secCvoOn(sec)) {
          sec.overrides.current_version_only = false;
        } else {
          delete sec.overrides.current_version_only;
        }
        this.afterInspectorChange();
      },

      /* secFindingTypeChecked / secToggleFindingType — finding_types override for
         a section.  Reuses the shared normalize/effective helpers so the
         CVE-default + clear-on-default semantics match the step inspector. */
      secFindingTypeChecked: function (sec, token) {
        var raw = sec && sec.overrides && sec.overrides.finding_types;
        var eff = raw == null || raw === "" ? ["cve"] : this._normFindingTypes(raw);
        return eff.indexOf(String(token).trim().toLowerCase()) !== -1;
      },
      secToggleFindingType: function (token) {
        var sec = this.inspSection();
        if (!sec) return;
        if (!sec.overrides) sec.overrides = {};
        token = String(token).trim().toLowerCase();
        var raw = sec.overrides.finding_types;
        var tokens = raw == null || raw === "" ? ["cve"] : this._normFindingTypes(raw);
        var idx = tokens.indexOf(token);
        if (idx === -1) tokens.push(token);
        else tokens.splice(idx, 1);
        var norm = this._normFindingTypes(tokens.join(","));
        if (norm.length === 1 && norm[0] === "cve") {
          this.secApplyOverride("finding_types", "");
        } else {
          this.secApplyOverride("finding_types", norm.join(","));
        }
      },

      /* bindSectionScope() — the section inspector's per-section Folder/Project/
         Version cascade.  Mirrors bindInspectorScope (root-scoped to #inspector,
         document-level root lookup, bounded retry while the x-if selects render)
         but writes into sec.overrides via onSecScopeChange.  The section scope
         selects use SECTION-unique ids (sec-insp-*) so they never collide with
         the global (#g-*) or per-step (#insp-*) cascades. */
      bindSectionScope: function () {
        var sec = this.inspSection();
        if (!sec) {
          this._secScopeIndex = null;
          this._secScopeTries = 0;
          this._secScopeBindingIndex = null;
          this._clearSecScopeRetry();
          return;
        }
        var idx = this.selectedSection;
        if (this._secScopeIndex === idx) return; // already bound to this section
        var self = this;
        if (this._secScopeBindingIndex !== idx) {
          this._secScopeBindingIndex = idx;
          this._secScopeTries = 0;
          this._clearSecScopeRetry();
        }
        var root = document.getElementById("inspector");
        if (
          typeof window.initScopeDropdowns !== "function" ||
          !root ||
          !root.querySelector("#sec-insp-project") ||
          !root.querySelector("#sec-insp-version")
        ) {
          if ((this._secScopeTries = (this._secScopeTries || 0) + 1) > 200) {
            this._secScopeTries = 0;
            this._secScopeBindingIndex = null;
            if (window.console && console.warn) {
              console.warn(
                "[builder] section scope bind gave up (deps not ready) for section",
                idx
              );
            }
            return;
          }
          this._clearSecScopeRetry();
          this._secScopeRetry = setTimeout(function () {
            if (self.selectedSection === idx) self.bindSectionScope();
          }, 50);
          return;
        }
        this._clearSecScopeRetry();
        this._secScopeTries = 0;
        this._secScopeIndex = idx; // mark ONLY now that we will actually bind
        window.initScopeDropdowns({
          root: root,
          folderId: "sec-insp-folder",
          projectId: "sec-insp-project",
          versionId: "sec-insp-version",
          onChange: function (scope) {
            self.onSecScopeChange(scope);
          },
        });
      },

      _clearSecScopeRetry: function () {
        if (this._secScopeRetry) {
          clearTimeout(this._secScopeRetry);
          this._secScopeRetry = null;
        }
      },

      /* onSecScopeChange(scope) — the section cascade changed; write the
         section's scope overrides with project-wins precedence (mirrors
         onInspScopeChange but via secApplyOverride). */
      onSecScopeChange: function (scope) {
        var sec = this.inspSection();
        if (!sec) return;
        scope = scope || {};
        var project = scope.project || "";
        if (project) {
          this.secApplyOverride("project_filter", project);
          this.secApplyOverride("version_filter", scope.version || "");
          this.secApplyOverride("folder_filter", "");
        } else {
          this.secApplyOverride("project_filter", "");
          this.secApplyOverride("version_filter", "");
          this.secApplyOverride("folder_filter", scope.folder || "");
        }
      },

      /* toggleOutputFormat(fmt, checked) — add/remove an output format name
         from the model.output.formats array. */
      toggleOutputFormat: function (fmt, checked) {
        var formats = this.model.output && Array.isArray(this.model.output.formats)
          ? this.model.output.formats
          : [];
        if (checked) {
          if (formats.indexOf(fmt) === -1) formats.push(fmt);
        } else {
          var idx = formats.indexOf(fmt);
          if (idx !== -1) formats.splice(idx, 1);
        }
        this.model.output.formats = formats;
      },

      /* ---- compound logo helpers (PR2.2a) ---- */
      /* Load available logos from GET /api/logos and populate the
         #cpd-logo-select.  Mirrors the settings-page.js _wireLogo pattern. */
      loadLogos: function () {
        var self = this;
        var sel = document.getElementById("cpd-logo-select");
        if (!sel) return;
        var currentLogo = (self.model.cover && self.model.cover.logo) || "";
        fetch("/api/logos", { headers: { "X-FS-Session": csrf() } })
          .then(function (r) { return r.json(); })
          .then(function (data) {
            sel.innerHTML = '<option value="">(default Finite State logo)</option>';
            (data.logos || []).forEach(function (name) {
              var o = document.createElement("option");
              o.value = name;
              o.textContent = name;
              if (name === currentLogo) o.selected = true;
              sel.appendChild(o);
            });
          })
          .catch(function () { /* offline — default option only */ });
      },

      /* onLogoSelectChange — user selected a logo from the dropdown. Write the
         chosen logo name into model.cover.logo. */
      onLogoSelectChange: function (evt) {
        if (!this.model.cover) this.model.cover = {};
        this.model.cover.logo = evt.target.value || "";
      },

      /* onLogoUpload — user chose a file to upload.  POST to /api/logos/upload,
         reload the logo list, and select the newly-uploaded logo. */
      onLogoUpload: function (evt) {
        var self = this;
        var input = evt.target;
        var file = input && input.files && input.files[0];
        if (!file) return;
        if (file.size > 512000) {
          toast("File too large (max 500KB)");
          input.value = "";
          return;
        }
        var fd = new FormData();
        fd.append("file", file);
        fetch("/api/logos/upload", {
          method: "POST",
          headers: { "X-FS-Session": csrf() },
          body: fd,
        })
          .then(function (r) { return r.json(); })
          .then(function (data) {
            if (data.error) {
              toast(data.error);
            } else {
              toast("Logo uploaded");
              if (!self.model.cover) self.model.cover = {};
              self.model.cover.logo = data.filename || "";
              self.loadLogos();
            }
          })
          .catch(function () { toast("Upload failed"); });
        input.value = "";
      },

      /* ---- compound SortableJS (PR2.2a) ---- */
      /* initCompoundSortable — initialise a separate SortableJS instance on the
         compound section list (#wfb-section-list) for drag-to-reorder.  Guard
         with _compoundSortableInited so re-renders don't double-wire.  Called
         from init's $nextTick and from loadRecipeBySlug's compound branch (not
         needed at init for non-compound kinds since the element is x-cloak
         hidden, but harmless since Sortable on a zero-height list is benign). */
      initCompoundSortable: function () {
        if (this._compoundSortableInited) return;
        if (typeof window.Sortable === "undefined") return;
        var list = this.$el.querySelector("#wfb-section-list");
        if (!list) return;
        this._compoundSortableInited = true;
        var self = this;
        window.Sortable.create(list, {
          animation: 150,
          handle: ".sec-grip",
          draggable: ".wfb-section-row",
          ghostClass: "sortable-ghost",
          onUpdate: function (evt) {
            /* Revert SortableJS's DOM move — Alpine's keyed x-for owns DOM
               order. Restore the dragged item to its original position so
               Alpine reconciles from the model cleanly. */
            var refNode = evt.from.children[evt.oldIndex] || null;
            evt.from.insertBefore(evt.item, refNode);
            self.moveSectionByIndex(evt.oldIndex, evt.newIndex);
            self.$nextTick(function () {
              relucide();
            });
          },
        });
      },

      selectStep: function (id) {
        /* Toggle selection; clicking the selected card again closes the
           inspector.  In run-view the cards are read-only (no inspector). */
        if (this.runMode) return;
        this.selected = this.selected === id ? null : id;
        /* Rebind the per-step scope cascade for the newly-selected RECIPE step
           (the #117 root-scope + I3 init-once lesson — re-init each selection
           without leaking, since the inspector ids are reused across steps). */
        var self = this;
        this.$nextTick(function () {
          relucide();
          self.bindInspectorScope();
          self.wireUploads();
        });
      },

      /* The inspector's per-step Project/Version cascade.  Root-scoped to the
         inspector subtree with UNIQUE-on-the-page ids (insp-project /
         insp-version) so it can't collide with the global #g-project cascade.
         Re-initialized on every step selection (the dropdown's data-value seeds
         the loaded override), guarded so we only re-init when the selected step
         actually changed (mind the I3 "init once" trap). */
      bindInspectorScope: function () {
        var step = this.inspStep();
        if (!step || step.kind !== "recipe") {
          this._inspScopeStep = null;
          this._inspScopeTries = 0;
          this._inspScopeBindingStep = null;
          this._clearInspScopeRetry();
          return;
        }
        if (this._inspScopeStep === step.id) return; // already bound to this step
        var self = this;
        /* A NEW step (≠ the one the retry budget is counting for): reset the
           budget + cancel any pending retry from the previous step, so step B
           never inherits step A's exhausted budget or a stale timer (M1-1/M1-9). */
        if (this._inspScopeBindingStep !== step.id) {
          this._inspScopeBindingStep = step.id;
          this._inspScopeTries = 0;
          this._clearInspScopeRetry();
        }
        /* Resolve the inspector root at the DOCUMENT level (it has a unique id),
           NOT via this.$el.querySelector.  LIVE-confirmed (T6): on a cold load the
           component's $el subtree query returns null for seconds even though the
           inspector IS in the page (document.querySelector finds it) — an Alpine
           morph/render-timing artifact.  Querying $el made the bind silently fail
           and the override dropdowns stayed stuck on "(inherit from global)".

           Several cold-load races can still make a given attempt premature; bailing
           on any WITHOUT retrying would re-introduce the stuck state, so retry on a
           short timer WITHOUT marking the guard until ALL are ready:
             (1) the scope-helper script (_scope_dropdowns.html) hasn't executed yet
                 → window.initScopeDropdowns is undefined;
             (2) the inspector aside (#inspector) isn't in the DOM yet;
             (3) its scope selects live inside <template x-if> blocks Alpine renders
                 a tick after `selected` changes.  initScopeDropdowns needs BOTH the
                 project AND version selects (it silently returns if either is
                 absent), so gate on both — gating only on #insp-project would set
                 the guard + call init while #insp-version is still un-rendered →
                 silent no-op + stuck dropdowns (M2-1).
           setTimeout (not rAF) so it still fires in a backgrounded tab; bounded so
           it can never spin forever; the guard is set ONLY after a real bind. */
        var root = document.getElementById("inspector");
        if (
          typeof window.initScopeDropdowns !== "function" ||
          !root ||
          !root.querySelector("#insp-project") ||
          !root.querySelector("#insp-version")
        ) {
          if ((this._inspScopeTries = (this._inspScopeTries || 0) + 1) > 200) {
            // ~10s of cold-load retries elapsed — give up but leave a trail so a
            // genuinely never-ready environment is diagnosable (M1-2/M3-2).
            // Re-selecting the step resets the budget and tries again (M1-1).
            this._inspScopeTries = 0;
            this._inspScopeBindingStep = null;
            if (window.console && console.warn) {
              console.warn(
                "[builder] inspector scope bind gave up (deps not ready) for step",
                step.id
              );
            }
            return;
          }
          this._clearInspScopeRetry();
          this._inspScopeRetry = setTimeout(function () {
            var s = self.inspStep();
            if (s && s.id === step.id) self.bindInspectorScope();
          }, 50);
          return;
        }
        this._clearInspScopeRetry();
        this._inspScopeTries = 0;
        this._inspScopeStep = step.id; // mark ONLY now that we will actually bind
        window.initScopeDropdowns({
          root: root,
          /* Folder targeting (design §6): the per-step inspector cascade gets a
             folder select too (#insp-folder) so a step can re-target a different
             folder than the global.  onChange writes the per-step overrides with
             project-wins precedence (folder cleared when a project override is
             set), mirroring _effective_step_config. */
          folderId: "insp-folder",
          projectId: "insp-project",
          versionId: "insp-version",
          onChange: function (scope) {
            self.onInspScopeChange(scope);
          },
        });
      },

      /* Cancel a pending inspector-scope bind retry (T6) — called on step
         change, on successful bind, and when leaving recipe selection, so stale
         retry timers don't keep churning (M1-9). */
      _clearInspScopeRetry: function () {
        if (this._inspScopeRetry) {
          clearTimeout(this._inspScopeRetry);
          this._inspScopeRetry = null;
        }
      },

      /* The per-step inspector cascade changed.  Write the step's scope
         overrides (engine keys) with project-wins precedence: a project
         override clears the folder override (and vice-versa a folder-only
         selection clears project + version).  Uses applyOverride so the
         override count / card chip stay consistent. */
      onInspScopeChange: function (scope) {
        var step = this.inspStep();
        if (!step) return;
        scope = scope || {};
        var project = scope.project || "";
        if (project) {
          this.applyOverride("project_filter", project);
          this.applyOverride("version_filter", scope.version || "");
          this.applyOverride("folder_filter", "");
        } else {
          this.applyOverride("project_filter", "");
          this.applyOverride("version_filter", "");
          this.applyOverride("folder_filter", scope.folder || "");
        }
      },

      /* ---- inspector: selected step + per-step override writes (§5.4) ---- */
      /* The currently-inspected step object, or null.  Bound throughout the
         inspector markup so all fields read/write THIS step only. */
      inspStep: function () {
        if (this.selected == null) return null;
        var sel = this.selected;
        for (var i = 0; i < this.model.steps.length; i++) {
          if (this.model.steps[i].id === sel) return this.model.steps[i];
        }
        return null;
      },

      /* Write (or, on an empty value, CLEAR) a per-step override using the
         ENGINE keys (§4.1).  Clearing removes the key so the override count /
         card chip update; setting writes the value.
         Mutual exclusion: setting start or end (and both will be set) clears
         the period override; setting a non-empty period clears start+end. */
      applyOverride: function (key, value) {
        var step = this.inspStep();
        if (!step) return;
        if (!step.overrides) step.overrides = {};
        if (value === "" || value === null || value === undefined) {
          delete step.overrides[key];
        } else {
          step.overrides[key] = value;
          /* Mutual exclusion — per-step date range ↔ period. */
          if (key === "start" || key === "end") {
            /* When BOTH start and end will be set, clear period. */
            var willHaveStart = key === "start" ? !!value : !!step.overrides.start;
            var willHaveEnd   = key === "end"   ? !!value : !!step.overrides.end;
            if (willHaveStart && willHaveEnd) {
              delete step.overrides.period;
            }
          } else if (key === "period" && value) {
            /* Setting a period clears the date range. */
            delete step.overrides.start;
            delete step.overrides.end;
          }
        }
        this.afterInspectorChange();
      },

      /* Toggle a boolean per-step override (open_only, detailed, standalone,
         vex_override). "on" = override true, "off" = key absent. */
      toggleStepBool: function (key) {
        var step = this.inspStep();
        if (!step) return;
        if (!step.overrides) step.overrides = {};
        if (step.overrides[key]) {
          delete step.overrides[key];
        } else {
          step.overrides[key] = true;
        }
        this.afterInspectorChange();
      },

      /* Applicability helper: does this step's recipe have the given flag set?
         Used by the inspector to gate recipe-specific field groups. */
      stepApplies: function (step, flag) {
        var r = recipeFlags(step && step.ref);
        return !!(r && r.applicability && r.applicability[flag]);
      },

      /* Global period/range mutual exclusion handlers (wired via @input on the
         global date inputs and period text input).

         C1: these @input handlers fire ONLY on real user input, so they are the
         seam where the user's explicit Global-Properties date-mode choice is
         recorded via period_touched / range_touched. Those flags then OVERRIDE a
         step's card period at run/export/preview time (server _effective_step_
         config / export _effective_config / client effectiveConfig). Mutual
         exclusion: setting one mode clears the OTHER mode's value AND its touched
         flag. Reset: clearing the period (empty) — or leaving an INCOMPLETE
         range (only start OR only end) — drops that mode's touched flag. */
      onGlobalRangeInput: function () {
        var g = this.model.global;
        if (g.start && g.end) {
          /* A complete range was explicitly set — range wins. */
          g.range_touched = true;
          g.period = "";
          g.period_touched = false;
        } else {
          /* Incomplete range (only one bound) — not an explicit range choice. */
          g.range_touched = false;
        }
      },
      onGlobalPeriodInput: function () {
        var g = this.model.global;
        if (g.period) {
          /* A period was explicitly set — period wins. */
          g.period_touched = true;
          g.start = "";
          g.end = "";
          g.range_touched = false;
        } else {
          /* Period cleared (empty) — not an explicit period choice. */
          g.period_touched = false;
        }
      },

      /* #10B/B7: per-step FP-Analysis autotriage toggle (DESTRUCTIVE — writes
         VEX to the platform when the workflow runs, including unattended runs).
         Default off; turning it ON confirms first.  The persisted overrides.
         autotriage flag is the headless authorization (no run-time prompt). */
      toggleAutotriage: function () {
        var step = this.inspStep();
        if (!step) return;
        if (!step.overrides) step.overrides = {};
        var turningOn = !step.overrides.autotriage;
        if (
          turningOn &&
          !window.confirm(
            "Auto-apply VEX WRITES VEX statuses to the platform whenever this " +
              "workflow runs — including unattended (saved / scheduled / CI) runs, " +
              "with no further prompt. Enable it for this step?"
          )
        ) {
          return;
        }
        if (turningOn) {
          step.overrides.autotriage = true;
        } else {
          delete step.overrides.autotriage;
          delete step.overrides.autotriage_status;
        }
        this.afterInspectorChange();
      },

      /* Per-step AI toggle: write `ai` only when it DIFFERS from the global
         (so an override that matches the global is cleared — inherits). */
      toggleStepAi: function () {
        var step = this.inspStep();
        if (!step) return;
        if (!step.overrides) step.overrides = {};
        var now = !this.aiOn(step);
        if (now === coerceBool(this.model.global.ai)) {
          delete step.overrides.ai;
        } else {
          step.overrides.ai = now;
        }
        this.afterInspectorChange();
      },

      resetOverrides: function () {
        var step = this.inspStep();
        if (!step) return;
        step.overrides = {};
        /* Also clear any native file inputs — the model now shows "none" but an
           <input type=file> can retain a stale selection (confusing on
           re-upload). */
        var root = this.$el.querySelector("[data-inspector]");
        if (root) {
          root.querySelectorAll(".fs-upload-input").forEach(function (i) {
            i.value = "";
          });
        }
        this.afterInspectorChange();
        toast("Reset to globals");
      },

      /* Returns true when `token` is present in the comma-split of
         step.overrides[key].  Guards null step / overrides gracefully. */
      scanTokenChecked: function (step, key, token) {
        if (!step || !step.overrides) return false;
        var raw = step.overrides[key];
        if (!raw) return false;
        return String(raw).split(",").map(function (t) { return t.trim().toUpperCase(); }).indexOf(token.toUpperCase()) !== -1;
      },

      /* Toggle `token` in/out of the comma-joined set stored at
         inspStep().overrides[key].  Uses applyOverride so the write +
         afterInspectorChange are handled consistently. */
      toggleScanToken: function (key, token) {
        var step = this.inspStep();
        if (!step) return;
        if (!step.overrides) step.overrides = {};
        var raw = step.overrides[key] || "";
        var tokens = raw.split(",").map(function (t) { return t.trim().toUpperCase(); }).filter(Boolean);
        var upper = token.toUpperCase();
        var idx = tokens.indexOf(upper);
        if (idx === -1) {
          tokens.push(upper);
        } else {
          tokens.splice(idx, 1);
        }
        this.applyOverride(key, tokens.join(","));
      },

      /* finding_types: the engine's finding-type tokens are LOWERCASE (cve,
         sast, thirdparty, credentials, config_issues, crypto_material), unlike
         the UPPERCASE scan_types / scan_statuses tokens, and the ENGINE DEFAULT
         is "cve" (run.py _build_engine_config: effective.get("finding_types",
         "cve")).  So this surface mirrors _card_config.html's
         `eff.get('finding_types','cve')` semantics rather than treating an
         absent override as "nothing selected":
           - findingTypeChecked reflects the EFFECTIVE default — CVE is checked
             when there is NO override (M1-4).
           - the stored value is NORMALIZED on write (lowercase, deduped, stable
             canonical order, comma-joined no spaces) and READS are tolerant of
             casing / whitespace so a hand-edited / imported "CVE, sast" displays
             both boxes checked (M1-9).
           - a selection that equals the engine default (cve alone) CLEARS the
             override key — "inherit", matching card-config's clear-on-default —
             so it doesn't inflate overrideCount (M1-7). */

      /* Canonical engine finding-type order (mirrors the inspector checkbox
         group + _card_config.html); used to stable-sort a normalized set. */
      _FINDING_TYPE_ORDER: [
        "cve",
        "sast",
        "thirdparty",
        "credentials",
        "config_issues",
        "crypto_material",
      ],

      /* Normalize a comma-joined finding_types value to a deduped, stable,
         lowercase token array (canonical order; unknown tokens kept, appended
         after the known ones in first-seen order so a hand-edited value isn't
         silently dropped). */
      _normFindingTypes: function (raw) {
        var order = this._FINDING_TYPE_ORDER;
        var seen = {};
        var tokens = String(raw == null ? "" : raw)
          .split(",")
          .map(function (t) {
            return t.trim().toLowerCase();
          })
          .filter(function (t) {
            if (!t || seen[t]) return false;
            seen[t] = true;
            return true;
          });
        return tokens.sort(function (a, b) {
          var ia = order.indexOf(a);
          var ib = order.indexOf(b);
          if (ia === -1 && ib === -1) return 0; // both unknown — keep order
          if (ia === -1) return 1; // unknown after known
          if (ib === -1) return -1;
          return ia - ib;
        });
      },

      /* The EFFECTIVE finding-type token set for a step: the normalized stored
         override when present, else the engine default ["cve"] (M1-4). */
      _effectiveFindingTypes: function (step) {
        var raw = step && step.overrides && step.overrides.finding_types;
        if (raw == null || raw === "") return ["cve"];
        return this._normFindingTypes(raw);
      },

      findingTypeChecked: function (step, token) {
        return (
          this._effectiveFindingTypes(step).indexOf(
            String(token).trim().toLowerCase()
          ) !== -1
        );
      },
      toggleFindingType: function (token) {
        var step = this.inspStep();
        if (!step) return;
        if (!step.overrides) step.overrides = {};
        token = String(token).trim().toLowerCase();
        /* Seed from the EFFECTIVE selection (CVE when no override) so toggling a
           type from the default state preserves the implicit CVE rather than
           starting from an empty set. */
        var tokens = this._effectiveFindingTypes(step);
        var idx = tokens.indexOf(token);
        if (idx === -1) {
          tokens.push(token);
        } else {
          tokens.splice(idx, 1);
        }
        var norm = this._normFindingTypes(tokens.join(","));
        /* Clear-on-default (mirrors _card_config.html): a selection equal to the
           engine default (cve alone) reads as inherit — don't store it (M1-7).
           applyOverride clears the key on an empty value too. */
        if (norm.length === 1 && norm[0] === "cve") {
          this.applyOverride("finding_types", "");
        } else {
          this.applyOverride("finding_types", norm.join(","));
        }
      },

      /* current_version_only is a DEFAULT-TRUE bool override (engine default
         True, _build_engine_config in run.py).  Unlike the default-false bools
         (open_only / detailed / standalone), toggleStepBool can't drive it: its
         "off" deletes the key → inherits → the True default, so you could never
         turn it off.  Instead: absent ⇒ on (inherit True); turning OFF persists
         an explicit `false`; turning back ON removes the explicit false to
         inherit the default again (keeps the override count honest). */
      cvoOn: function (step) {
        if (!step || !step.overrides) return true;
        /* Coerce the stored value the same way the server/export path does
           (coerceBool ⇄ run.py _coerce_workflow_value): a hand-edited/imported
           override of the string "false" must read OFF, not the truthy
           bool("false").  Keep the absent ⇒ on (inherit default-True) branch. */
        return step.overrides.current_version_only === undefined
          ? true
          : coerceBool(step.overrides.current_version_only);
      },
      toggleCvo: function () {
        var step = this.inspStep();
        if (!step) return;
        if (!step.overrides) step.overrides = {};
        if (this.cvoOn(step)) {
          step.overrides.current_version_only = false; /* explicit off */
        } else {
          delete step.overrides.current_version_only; /* inherit default true */
        }
        this.afterInspectorChange();
      },

      afterInspectorChange: function () {
        this.$nextTick(function () {
          relucide();
        });
      },

      /* ---- SP3: uploaded scoring / context file overrides ---- */
      /* The basename of a per-step file override (or "none"), for the upload
         control's name span (x-text). Reads from the model so a step switch /
         clear / reset reflects the selected step's per-step value. */
      uploadName: function (step, key) {
        var ov = (step && step.overrides) || {};
        var v = ov[key] || "";
        if (!v) return "none";
        var parts = String(v).split("/");
        return parts[parts.length - 1] || "none";
      },

      /* fs-upload-done handler: mirror the stored upload path into the per-step
         override (applyOverride clears the key on an empty path — e.g. the
         clear affordance, which dispatches fs-upload-done with path "").  Any
         non-blocking upload warnings (scoring unknown-key) are surfaced as a
         toast since the model-bound name span can't carry them. */
      onUploadDone: function (key, ev) {
        var detail = (ev && ev.detail) || {};
        var path = detail.path || "";
        /* Target the step that INITIATED the upload (snapshotted at file-pick
           in wireUploads), not the now-current selection — an async upload that
           completes after the user switches steps must not write the path to
           the wrong step.  A clear (empty path) acts on the current selection. */
        var box = ev && ev.target;
        var stepId =
          path && box && box.__fsInitStepId != null
            ? box.__fsInitStepId
            : this.selected;
        this.setFileOverride(stepId, key, path);
        var warnings = detail.warnings || [];
        if (warnings.length) toast(warnings.join(" "));
      },

      /* Write (or clear, on an empty value) a per-step FILE override by step id
         — the file-input flavor of applyOverride that targets a specific step
         (so a late-completing upload writes to its initiating step, not the
         current selection).  No period/range mutual-exclusion (irrelevant for
         file keys). */
      setFileOverride: function (stepId, key, value) {
        var step = null;
        for (var i = 0; i < this.model.steps.length; i++) {
          if (this.model.steps[i].id === stepId) {
            step = this.model.steps[i];
            break;
          }
        }
        if (!step) return;
        if (!step.overrides) step.overrides = {};
        if (value === "" || value === null || value === undefined) {
          delete step.overrides[key];
        } else {
          step.overrides[key] = value;
        }
        this.afterInspectorChange();
      },

      /* (Re)wire the .fs-upload controls in the freshly-rendered inspector to
         POST /api/uploads (the spec's "call __fsWireUploads after the inspector
         renders").  Idempotent — uploads.js guards against double-wiring, and
         scoping to [data-inspector] leaves other surfaces' controls alone.
         Also snapshots the initiating step id at file-pick time so a
         late-completing upload writes to the right step (see onUploadDone). */
      wireUploads: function () {
        if (typeof window.__fsWireUploads !== "function") return;
        var root = this.$el.querySelector("[data-inspector]");
        if (!root) return;
        window.__fsWireUploads(root);
        var self = this;
        root.querySelectorAll(".fs-upload").forEach(function (box) {
          var input = box.querySelector(".fs-upload-input");
          if (!input || input.__fsStepSnap) return;
          input.__fsStepSnap = true;
          input.addEventListener("change", function () {
            box.__fsInitStepId = self.selected;
          });
        });
      },

      /* Does the inspected/selected recipe step's recipe require CVE IDs?
         Drives the conditional CVE field (§5.4) — the SAME requires_cve flag
         the server preflight reads. */
      recipeRequiresCve: function (step) {
        if (!step || step.kind !== "recipe") return false;
        var r = recipeFlags(step.ref);
        return !!(r && r.requires_cve);
      },

      /* Effective project label for a recipe step's chip (override wins). */
      effProject: function (step) {
        var ov = (step && step.overrides) || {};
        return ov.project_filter || this.model.global.project_filter || "";
      },

      /* ---- MCP-tool step params (§5.4) ---- */
      mcpToolSpec: function (step) {
        return step ? mcpToolSpec(step.ref) : null;
      },
      mcpParamKeys: function (step) {
        var spec = this.mcpToolSpec(step);
        if (!spec || !spec.params) return [];
        return Object.keys(spec.params);
      },
      mcpParamSpec: function (step, key) {
        var spec = this.mcpToolSpec(step);
        return (spec && spec.params && spec.params[key]) || {};
      },
      /* Current value: the step's saved param, else the spec default (so a
         required domain field like priority shows P0 rather than blank). */
      mcpParamValue: function (step, key) {
        if (step && step.params && step.params[key] !== undefined) {
          return step.params[key];
        }
        var ps = this.mcpParamSpec(step, key);
        return ps.default !== undefined ? ps.default : "";
      },
      /* Write into step.params (NOT overrides) — clearing a non-required value
         removes the key. */
      applyParam: function (key, value) {
        var step = this.inspStep();
        if (!step) return;
        if (!step.params) step.params = {};
        var ps = this.mcpParamSpec(step, key);
        if ((value === "" || value === null || value === undefined) && !ps.required) {
          delete step.params[key];
        } else {
          step.params[key] = value;
        }
      },

      /* ============================================================
       * Run animation + client preflight (§6.3 / §10)
       * ============================================================ */

      /* Effective config for a recipe step = global ← step overrides, over the
         engine override keys (mirrors the server _effective_step_config). Used
         by the client preflight so we evaluate the SAME predicates as Task 5. */
      effectiveConfig: function (step) {
        var g = this.model.global || {};
        var eff = {
          project_filter: g.project_filter || "",
          /* Folder targeting (design §6): seed the global folder so a
             folder-only scope satisfies a requires_project_or_folder step in the
             client preflight (mirrors _effective_step_config). */
          folder_filter: g.folder_filter || "",
          version_filter: g.version_filter || "",
          period: g.period || "30d",
          ai: coerceBool(g.ai),
          ai_depth: g.ai_depth || "summary",
          cache_ttl: g.cache_ttl || "4h",
          cve_filter: "",
        };
        var ov = (step && step.overrides) || {};
        /* Track whether the step's OWN override sets folder / project (mirrors
           the server's step_overrides_effective): empty/absent override values
           are dropped below, so capture the intent here, pre-merge. */
        var stepSetsFolder = !!String((ov.folder_filter == null ? "" : ov.folder_filter)).trim();
        var stepSetsProject = !!String((ov.project_filter == null ? "" : ov.project_filter)).trim();
        var stepSetsVersion = !!String((ov.version_filter == null ? "" : ov.version_filter)).trim();
        /* C1: when the USER explicitly set the Global-Properties date mode
           (g.period_touched / g.range_touched), that choice OVERRIDES a step's
           card period — mirrors the server _effective_step_config / export
           _effective_config. The touched flags steer precedence ONLY and must
           NEVER land in eff (read-and-strip): they are read here off the global
           block and never written into eff. When set, skip overlaying the step's
           date keys so the seeded global period/range survives; a complete
           global range additionally clears the seeded default period. Untouched
           ⇒ today's step-wins behavior. */
        var periodTouched = coerceBool(g.period_touched);
        /* range_touched only overrides the step's date keys when BOTH global
           bounds are present — a hand-edited range_touched:true with one bound
           can't force an incomplete range. The UI only sets it with both bounds;
           this hardens the preview to match the server _effective_step_config /
           export _effective_config both-bounds guard. Otherwise fall back to
           step-wins. */
        var rangeTouched =
          coerceBool(g.range_touched) &&
          !!String(g.start || "").trim() &&
          !!String(g.end || "").trim();
        if (rangeTouched) {
          /* The global range mode is explicitly set AND complete — seed start/end
             and clear the default period so the preview/preflight reflects the
             range, mirroring the server _effective_step_config / export
             _effective_config. */
          eff.start = g.start || "";
          eff.end = g.end || "";
          eff.period = "";
        }
        Object.keys(ov).forEach(function (k) {
          if (k === "error_policy") return;
          /* C1: a touched global date mode wins over the step's card period —
             skip the step's date keys so the global value (seeded above) holds. */
          if ((periodTouched || rangeTouched) &&
              (k === "period" || k === "start" || k === "end")) {
            return;
          }
          var v = ov[k];
          if (v === null || v === undefined || v === "") return;
          eff[k] = v;
        });
        /* Step folder overrides an INHERITED global project (Finding 5 /
           _effective_step_config). When the step's OWN override sets
           folder_filter and NOT its own project_filter, the only project in eff
           is the inherited global one — left in place, the project-wins drop
           below would silently discard the step's folder and run the global
           project. Clear the inherited global project for this step so
           folder-wins applies, exactly as the server does. (The step setting its
           OWN project keeps stepSetsProject true, so we don't clear and
           project-wins still drops the folder.) */
        if (stepSetsFolder && !stepSetsProject) {
          eff.project_filter = "";
          /* A version is project-specific; a folder-only step has no project to
             version. The inherited global version_filter would otherwise leave
             the step at folder + a stale version, which the engine rejects (a
             version requires a project). Clear it alongside the inherited
             project so a folder-only step previews as folder-only. (A step
             setting its OWN project keeps stepSetsProject true, so we don't
             reach here and its inherited/own version is preserved.) */
          eff.version_filter = "";
        }
        /* A version ID is scoped to ONE project (round-5; mirrors
           _effective_step_config / _effective_config). When the step retargets
           to its OWN project, the inherited global version belongs to the GLOBAL
           project — StepProj + a GlobalProj version ID is an invalid pairing.
           Drop it unless the step supplies its OWN version. */
        if (stepSetsProject && !stepSetsVersion) {
          eff.version_filter = "";
        }
        /* Project-wins precedence (mirrors _effective_step_config /
           _build_engine_config): when the effective config carries a specific
           project the folder was only a UI filter — drop it. */
        if (String(eff.project_filter || "").trim()) {
          eff.folder_filter = "";
        }
        /* Invariant: a version requires a project (mirrors _build_engine_config /
           _effective_config). version_filter is a project-scoped version ID,
           meaningless and engine-rejected without a project. Whenever the
           effective project_filter is empty — folder-only OR portfolio-wide —
           drop any inherited/leftover version_filter so the client preflight /
           preview never shows a project-less folder+version (or
           portfolio+version) scope. This general rule supersedes the narrow
           folder-only-step clear above (kept harmless) and covers a workflow
           whose GLOBAL scope is folder-only with a version. When a project IS set
           the version is kept. */
        if (!String(eff.project_filter || "").trim()) {
          eff.version_filter = "";
        }
        return eff;
      },

      /* A recipe step is runnable locally when its recipe is a known launcher
         recipe (the server re-derives runnable_locally and is the backstop).
         An UNRESOLVED recipe ref (not in window.__CC.recipes) has no flags, so
         it is excluded here — kept out of runnableCount()/preflight/run while
         still preserved in the model for export (fix D / spec §10). */
      isRunnableStep: function (step) {
        return !!(step && step.kind === "recipe" && recipeFlags(step.ref));
      },
      runnableCount: function () {
        var self = this;
        return this.model.steps.filter(function (s) {
          return self.isRunnableStep(s);
        }).length;
      },

      runRunTitle: function () {
        if (this.runMode) return "Stop the running workflow";
        if (!this.runnableCount()) {
          return "Add at least one runnable report step to run (MCP tools are export-only).";
        }
        return "Run this workflow locally";
      },

      /* Task D (T5): kind-aware run-button label.  ONE string per kind — no
         "Build report" / "coming soon".  workflow → "Run workflow";
         compound → "Run compound"; comparison → "Run comparison" (both open the
         inline run drawer).  Used for both the button text and its title. */
      runKindLabel: function () {
        if (this.model.kind === "compound") return "Run compound";
        if (this.model.kind === "comparison") return "Run comparison";
        return "Run workflow";
      },

      get runStatusText() {
        if (this.runDone) {
          if (this.runStatus === "error") return "failed";
          if (this.runStatus === "cancelled") return "cancelled";
          return "complete";
        }
        return "running";
      },

      /* Client-side preflight (§10): validate EVERY runnable recipe step against
         its EFFECTIVE config — recipe scope_req satisfied by effective
         project/folder, and requires_cve recipes need an effective cve_filter.
         Returns null on pass, else {step_id, message}. Mirrors the server. */
      preflight: function () {
        /* C2: distinguish a GENERAL workflow (target_agnostic — pick a target
           per run) from a TARGET-BOUND workflow with no global scope set (set the
           workflow's global scope) — don't conflate the two. A project-only step
           never suggests a folder (a folder can't satisfy it). Mirrors the server
           preflight wording. */
        var g = this.model.global || {};
        var agnostic = coerceBool(g.target_agnostic);
        var noGlobalTarget =
          !String(g.project_filter || "").trim() &&
          !String(g.folder_filter || "").trim();
        for (var i = 0; i < this.model.steps.length; i++) {
          var step = this.model.steps[i];
          if (!this.isRunnableStep(step)) continue;
          var flags = recipeFlags(step.ref);
          if (!flags) continue; // unknown → engine backstop
          var eff = this.effectiveConfig(step);
          var project = String(eff.project_filter || "").trim();
          var folder = String(eff.folder_filter || "").trim();
          var sr = recipeScopeReq(step.ref);
          if ((flags.requires_project || sr === "project") && !project) {
            // A PROJECT is required — never suggest a folder here.
            var projMsg;
            if (agnostic) {
              projMsg = "needs a project — pick a target (a project) for this run.";
            } else if (noGlobalTarget) {
              projMsg = "needs a project — set the workflow's global scope to a project.";
            } else {
              projMsg = "needs a project — set the step's project or the global project.";
            }
            return {
              step_id: step.id,
              message: "Step " + (i + 1) + " (" + step.ref + ") " + projMsg,
            };
          }
          if (
            (flags.requires_project_or_folder || sr === "project_or_folder") &&
            !project &&
            !folder
          ) {
            // A folder CAN satisfy this step, so "project or folder" is accurate.
            var pofMsg;
            if (agnostic) {
              pofMsg = "needs a project or folder — pick a target for this run.";
            } else if (noGlobalTarget) {
              pofMsg = "needs a project or folder — set the workflow's global scope.";
            } else {
              pofMsg = "needs a project or folder.";
            }
            return {
              step_id: step.id,
              message: "Step " + (i + 1) + " (" + step.ref + ") " + pofMsg,
            };
          }
          if (flags.requires_cve && !String(eff.cve_filter || "").trim()) {
            return {
              step_id: step.id,
              message: "Step " + (i + 1) + " (" + step.ref + ") needs CVE IDs.",
            };
          }
        }
        return null;
      },

      /* Run the current model in place: client preflight → POST → open SSE.
         Compound/comparison: delegate to _runRecipeDoc (save-gate → dirty-gate →
         run trigger).  Workflow: the original SSE path (unchanged). */
      runWorkflow: function () {
        /* ── Comparison: delegate to shared recipe-doc run flow ── */
        if (this.model.kind === "comparison") {
          this._runRecipeDoc("comparison");
          return;
        }
        /* ── Compound: delegate to shared recipe-doc run flow ── */
        if (this.model.kind === "compound") {
          this._runRecipeDoc("compound");
          return;
        }
        if (this.isRunning || this.runMode) return;
        if (!this.runnableCount()) {
          toast("Add a runnable report step first (MCP tools are export-only).");
          return;
        }
        /* Block on any unmet step — flag it in-place (toast + open its
           inspector) and do NOT POST (mirrors the server preflight). */
        var bad = this.preflight();
        if (bad) {
          this.selected = bad.step_id;
          var self0 = this;
          this.$nextTick(function () {
            self0.bindInspectorScope();
            self0.wireUploads();
            relucide();
          });
          toast(bad.message);
          return;
        }
        this.isRunning = true;
        this.runStates = {};
        this.runStatus = "";
        this.runDone = false;
        var self = this;
        /* C2: send the current Global-Properties target as scope_override so the
           run endpoint applies the LIVE target (the run endpoint already overlays
           it onto the in-memory model, project-wins, never persisted).  This is
           what lets a GENERAL workflow be re-targeted at run time without baking
           a target into the doc; a target-bound workflow sends its current rail
           target identically (idempotent re-application). */
        var runBody = { model: this.toEngineModel() };
        var ov = this._currentScopeOverride();
        if (ov) runBody.scope_override = ov;
        apiJSON("POST", "/api/workflows/run", runBody).then(
          function (res) {
            if (!res.ok || !res.data || !res.data.run_id) {
              /* Server preflight is the backstop — surface its step + message. */
              if (res.data && res.data.step_id) {
                self.selected = res.data.step_id;
                self.$nextTick(function () {
                  self.bindInspectorScope();
                  self.wireUploads();
                  relucide();
                });
              }
              toast((res.data && res.data.error) || "Couldn't start the workflow");
              self.isRunning = false;
              return;
            }
            self.runId = res.data.run_id;
            self.enterRun();
            self.openStream(res.data.run_id);
          }
        );
      },

      enterRun: function () {
        this.runMode = true;
        this.selected = null;
        this._inspScopeStep = null;
        this._inspScopeBindingStep = null;
        this._clearInspScopeRetry(); // M1-2: drop a pending bind-retry on run entry
        this.$nextTick(function () {
          relucide();
        });
      },

      /* Open the EXISTING SSE stream and route events onto step cards. */
      openStream: function (runId) {
        this.closeStream();
        var self = this;
        var es = new EventSource("/api/run/" + encodeURIComponent(runId) + "/events");
        this._es = es;
        es.addEventListener("step", function (e) {
          self.onStepEvent(e.data);
        });
        es.addEventListener("progress", function () {
          /* progress is reflected per-card by the step events; nothing extra. */
        });
        es.addEventListener("log", function () {
          /* live log lines are surfaced by the monitor; the canvas shows the
             per-step running message instead. */
        });
        es.addEventListener("done", function (e) {
          self.onDoneEvent(e.data);
        });
        es.onerror = function () {
          /* The stream drops on terminal done (server closes it).  If we haven't
             seen a terminal done, treat a hard error as a soft stop. */
          if (!self.runDone) {
            self.isRunning = false;
          }
        };
      },

      closeStream: function () {
        if (this._es) {
          try {
            this._es.close();
          } catch (err) {
            /* already closed */
          }
          this._es = null;
        }
      },

      /* Map a `step` SSE event onto its card's run-state (§6.3). */
      onStepEvent: function (raw) {
        var data;
        try {
          data = JSON.parse(raw);
        } catch (err) {
          return;
        }
        if (!data || !data.step_id) return;
        this.runStates[data.step_id] = {
          state: data.state || "queued",
          message: data.message || "",
          files: data.files || [],
          report_url: data.report_url || "",
          reason: data.reason || "",
        };
        /* Force Alpine to react to the keyed object mutation. */
        this.runStates = Object.assign({}, this.runStates);
        this.$nextTick(function () {
          relucide();
        });
      },

      onDoneEvent: function (raw) {
        var data = {};
        try {
          data = JSON.parse(raw);
        } catch (err) {
          data = {};
        }
        this.runStatus = data.status || "success";
        this.runDone = true;
        this.isRunning = false;
        this.closeStream();
        this.$nextTick(function () {
          relucide();
        });
        if (this.runStatus === "error") {
          toast("Workflow finished with an error");
        } else if (this.runStatus === "cancelled") {
          toast("Workflow cancelled");
        } else {
          toast("Workflow complete");
        }
      },

      /* Stop a running workflow — POST cancel (only sets cancel_event; the
         executor marks the rest skipped and emits a terminal done). */
      stopRun: function () {
        if (!this.runId) {
          this.exitRun();
          return;
        }
        apiJSON("POST", "/api/run/" + encodeURIComponent(this.runId) + "/cancel").then(
          function (res) {
            if (!res.ok) {
              toast((res.data && res.data.error) || "Couldn't stop the run");
            }
          }
        );
      },

      /* Edit toggle — leave run-view back to authoring (§6.3). */
      exitRun: function () {
        this.closeStream();
        this.runMode = false;
        this.runDone = false;
        this.isRunning = false;
        this.runId = null;
        this.runStatus = "";
        this.runStates = {};
        this.$nextTick(function () {
          relucide();
        });
      },

      /* Hand off to the standalone Run canvas (§9). SAME-TAB navigation — this
         tears down our EventSource so the canvas becomes the sole live SSE
         consumer (the stream is single-consumer per run). Never target=_blank. */
      openRunCanvas: function () {
        if (this.runId) {
          window.location.href = "/run/" + encodeURIComponent(this.runId);
        }
      },

      /* ---- per-card run helpers (read the runStates map) ---- */
      runState: function (step) {
        var rs = step && this.runStates[step.id];
        return rs ? rs.state : "queued";
      },
      runMessage: function (step) {
        var rs = step && this.runStates[step.id];
        return rs ? rs.message : "";
      },
      runReportUrl: function (step) {
        var rs = step && this.runStates[step.id];
        return rs ? rs.report_url : "";
      },
      /* Map the reason enum to a human note for a skipped card (§6.3). */
      skipNote: function (step) {
        var rs = step && this.runStates[step.id];
        var reason = rs ? rs.reason : "";
        if (reason === "export_only") return "Export-only — runs via Forge agent";
        if (reason === "halted") return "Skipped — an earlier step failed (halt)";
        if (reason === "cancelled") return "Skipped — run cancelled";
        return (rs && rs.message) || "Skipped";
      },
      /* Card classes: selection/mcp in authoring, run-* state in run-view.
         An unresolved recipe ref carries `unresolved` in BOTH modes (fix D) so
         the card is visibly flagged whether authoring or in a run. */
      runStepClass: function (step) {
        var unresolved = this.isUnresolvedRecipe(step);
        if (!this.runMode) {
          return {
            sel: this.selected === step.id,
            mcp: step.kind === "mcp_tool",
            unresolved: unresolved,
          };
        }
        var st = this.runState(step);
        return {
          mcp: step.kind === "mcp_tool",
          unresolved: unresolved,
          "run-queued": st === "queued",
          "run-running": st === "running",
          "run-done": st === "done",
          "run-error": st === "error",
          "run-skipped": st === "skipped",
        };
      },
      /* Connector lighting: lit up to the running cursor, flow on it. */
      runConnLit: function (i) {
        if (!this.runMode) return false;
        var step = this.model.steps[i];
        return step && this.runState(step) === "done";
      },
      runConnFlow: function (i) {
        if (!this.runMode) return false;
        var step = this.model.steps[i];
        return step && this.runState(step) === "running";
      },

      /* ============================================================
       * Export modal (§7) — four tabs, server-side serializers.
       * ============================================================ */
      openExport: function () {
        if (!this.model.steps.length) {
          toast("Add a step before exporting");
          return;
        }
        this.exportOpen = true;
        if (!this.exportTarget) this.exportTarget = "cli";
        this.$nextTick(function () {
          relucide();
          /* Move focus into the modal so keyboard/screen-reader users land
             on an interactive element (M-3 a11y). */
          var el = document.querySelector("#export-modal button");
          if (el) el.focus();
        });
        this.loadExport();
      },
      closeExport: function () {
        this.exportOpen = false;
      },
      selectExportTab: function (target) {
        if (this.exportTarget === target && this.exportText) return;
        this.exportTarget = target;
        this.loadExport();
      },
      /* POST the current model to the export endpoint for the active target and
         render {text, filename}.  Guarded against non-ok + network failure. */
      loadExport: function () {
        var self = this;
        var target = this.exportTarget;
        this.exportLoading = true;
        this.exportText = "";
        this.exportFilename = "";
        apiJSON(
          "POST",
          "/api/workflows/export?target=" + encodeURIComponent(target),
          { model: this.toEngineModel() }
        ).then(function (res) {
          /* Ignore a stale response if the user switched tabs meanwhile. */
          if (self.exportTarget !== target) return;
          self.exportLoading = false;
          if (!res.ok || !res.data) {
            self.exportText = "";
            toast((res.data && res.data.error) || "Export failed");
            return;
          }
          self.exportText = res.data.text || "";
          self.exportFilename = res.data.filename || "";
        });
      },
      copyExport: function () {
        if (!this.exportText) return;
        var text = this.exportText;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(
            function () {
              toast("Copied");
            },
            function () {
              toast("Couldn't copy to clipboard");
            }
          );
        } else {
          toast("Clipboard unavailable");
        }
      },
      /* Download via a Blob + transient anchor using the server's filename. */
      downloadExport: function () {
        if (!this.exportText) return;
        var fn = this.exportFilename || "workflow.txt";
        var blob = new Blob([this.exportText], { type: "text/plain" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = fn;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        toast("Downloaded " + fn);
      },
      clearCanvas: function () {
        if (this.runMode) this.exitRun();
        this.model.steps = [];
        this.selected = null;
        toast("Canvas cleared");
      },

      /* ---- SortableJS wiring ---- */
      initSortable: function () {
        if (this._sortableInited) return;
        this._sortableInited = true;
        if (typeof window.Sortable === "undefined") {
          console.warn("[builder] SortableJS not loaded — drag disabled");
          return;
        }
        var self = this;

        /* Library lists are CLONE sources: pull a clone, never accept drops. */
        ["lib-reports", "lib-tools"].forEach(function (listId) {
          var listEl = self.$el.querySelector("#" + listId);
          if (!listEl) return;
          window.Sortable.create(listEl, {
            group: { name: "wf", pull: "clone", put: false },
            sort: false,
            animation: 150,
            draggable: ".wfb-libitem",
          });
        });

        /* The pipeline is the RECEIVER. onAdd inserts a step from the dragged
           library card's data attrs at the drop index, then removes the clone
           (Alpine re-renders from the model). onUpdate reorders the model. */
        var pipeline = this.$el.querySelector("#wfb-steps");
        if (!pipeline) return;
        window.Sortable.create(pipeline, {
          group: "wf",
          animation: 150,
          handle: ".s-grip",
          draggable: ".wfb-step-wrap",
          ghostClass: "sortable-ghost",
          /* The receiver fills the canvas (CSS .wfb-steps flex:1); a generous
             threshold makes dropping onto the empty canvas forgiving. */
          emptyInsertThreshold: 40,
          onAdd: function (evt) {
            var item = evt.item;
            var kind = item.getAttribute("data-kind");
            var ref = item.getAttribute("data-ref");
            /* Remove the SortableJS-inserted clone — the model + Alpine own the
               real DOM. Read the drop index BEFORE removing. */
            var index = evt.newIndex;
            if (item.parentNode) item.parentNode.removeChild(item);
            if (kind && ref) self.addStep(kind, ref, index);
          },
          onUpdate: function (evt) {
            /* Revert SortableJS's DOM move — Alpine's keyed x-for owns DOM
               order. Restore the dragged item to its original position so
               Alpine reconciles from the model cleanly with no transient
               wrong-order frame. */
            var refNode = evt.from.children[evt.oldIndex] || null;
            evt.from.insertBefore(evt.item, refNode);
            self.moveStep(evt.oldIndex, evt.newIndex);
            self.$nextTick(function () {
              relucide();
            });
          },
        });
      },

      /* ---- saved-workflow dropdown ---- */

      /* _compoundGlobalBlock() — build the PERSISTED-DOC compound `global` block
         from model.global, matching the Task-A POST contract
         (COMPOUND_OVERRIDE_WHITELIST + the period_touched/range_touched/
         target_agnostic intent flags; the server runs normalize_compound_global
         on it).

         M2-1 — persisted vs run-only split.  Two fields are RUN-ONLY and MUST be
         excluded here (so they ride only the inline-run form POST in Task D, and
         so they never trip the dirty-gate which compares this same shape):
           1. The TARGET (project/folder/version) when the compound is GENERAL
              (target_agnostic): a general compound has no saved target — the rail
              target is picked at run time.  A TARGET-BOUND compound DOES persist
              its target (the normal case).
           2. The global FINDING-TYPES — always chosen at Run, never baked.

         Date-mode mutual exclusion mirrors toEngineModel: a complete range wins
         over a period (period sent absent so create_config can't shadow it). */
      _compoundGlobalBlock: function () {
        var g = this.model.global || {};
        var general = coerceBool(g.target_agnostic);
        var block = {
          /* Intent flags — always persisted (plain bools, steer precedence). */
          target_agnostic: general,
          period_touched: coerceBool(g.period_touched),
          range_touched: coerceBool(g.range_touched),
          ai: coerceBool(g.ai),
          ai_depth: g.ai_depth || "summary",
        };
        /* Scope (the TARGET) — persisted ONLY for a target-bound compound.  For a
           general compound the rail target is run-only (M2-1) → omit it. */
        if (!general) {
          var project = String(g.project_filter || "").trim();
          var folder = String(g.folder_filter || "").trim();
          /* Project wins: a project clears the folder; version only with a
             project (mirrors onGlobalScopeChange / the server drop). */
          if (project) {
            block.project_filter = project;
            if (g.version_filter) block.version_filter = g.version_filter;
          } else if (folder) {
            block.folder_filter = folder;
          }
        }
        /* Date mode (period XOR range) — range wins when both bounds present. */
        var start = String(g.start || "").trim();
        var end = String(g.end || "").trim();
        if (start && end) {
          block.start = start;
          block.end = end;
        } else {
          block.period = g.period || "30d";
        }
        /* NB: finding_types is RUN-ONLY (M2-1) — deliberately NOT included. */
        return block;
      },

      /* _compoundSaveBody() — single source of truth for the object POSTed by
         the compound save() path.  Used by both save() (the POST body) and the
         dirty-gate snapshot comparison in _runRecipeDoc() — same function → no
         field-ordering drift possible, and (M2-1) the dirty-gate therefore
         compares ONLY persisted-doc state: run-only fields (a general compound's
         target + global finding-types) are excluded from BOTH the body and the
         snapshot, so picking a runtime target for a general compound neither
         persists nor trips "save before running". */
      _compoundSaveBody: function () {
        var cpdName = (this.model.name || "").trim();
        var cover = this.model.cover || {};
        var output = this.model.output || {};
        /* Sections as {recipe, overrides} objects (Task C).  Emit a clean
           overrides object (whitelisted, non-empty values only); a section with
           no overrides serializes to {recipe} so the server/disk shape stays
           tidy and the dirty-gate snapshot is stable. */
        var sections = (Array.isArray(this.model.sections) ? this.model.sections : []).map(
          function (sec) {
            var recipe = typeof sec === "string" ? sec : (sec && sec.recipe) || "";
            var rawOv = (sec && typeof sec === "object" && sec.overrides) || {};
            var ov = {};
            Object.keys(rawOv).forEach(function (k) {
              var v = rawOv[k];
              if (v !== null && v !== undefined && v !== "") ov[k] = v;
            });
            var out = { recipe: recipe };
            if (Object.keys(ov).length) out.overrides = ov;
            return out;
          }
        );
        return {
          kind: "compound",
          name: cpdName,
          title: this.model.title || "",
          description: this.model.description || "",
          nav_category: this.model.nav_category || "Executive",
          sections: sections,
          global: this._compoundGlobalBlock(),
          cover_subtitle: cover.subtitle || null,
          logo: cover.logo || null,
          classification: cover.classification || null,
          output: {
            formats: Array.isArray(output.formats) ? output.formats.slice() : ["html", "pdf"],
            toc: output.toc !== false,
            page_numbers: output.page_numbers !== false,
          },
        };
      },

      /* _kindLabel(kind) — single source of truth for kind→display-label.
         "workflow" stays lowercase (matching the long-standing confirm/toast copy);
         all other kinds (compound, comparison, …) are title-cased so the picker,
         confirm dialog, and toast strings are consistent across PR2 and PR3. */
      _kindLabel: function (kind) {
        return kind === "workflow" ? "workflow" : kind.charAt(0).toUpperCase() + kind.slice(1);
      },

      /* _recipeKindCfg(kind) — per-kind descriptor for compound/comparison save+run.
         Workflow is handled separately; this covers only the two recipe-doc kinds.
         Returns an object with:
           buildBody   — fn() → the POST body object
           snapshotKey — string: component property name for the dirty-gate snapshot
           emptyMsg    — toast text when sections is empty
           kindLabel   — display label for the save toast ("compound" / "comparison")
           nameLabel   — prompt label for the name-empty toast
           runTrigger  — fn(name) → triggers the run (inline drawer / deep-link) */
      _recipeKindCfg: function (kind) {
        var self = this;
        /* Task D (T4): the run trigger opens the INLINE prerun drawer (not the
           centered modal) for both recipe-doc kinds.  __openInlineRun reuses the
           prerun machinery against #cpd-run-panel, pre-filling the LIVE
           Global-Properties target via _currentScopeOverride() (||{} so a
           portfolio-wide doc still opens cleanly).  Opening the Alpine flag here
           too guarantees the drawer host is shown synchronously before the
           fragment injects (belt-and-braces with the registered open hook). */
        var _inlineRunTrigger = function (name) {
          if (typeof window.__openInlineRun === "function") {
            self.openCpdRun();
            window.__openInlineRun(name, self._currentScopeOverride() || {}, "#cpd-run-panel");
          } else if (typeof window.__openConfigure === "function") {
            /* Fallback to the centered modal if the inline path isn't loaded. */
            window.__openConfigure(name, self._currentScopeOverride() || {});
          } else {
            location.href = "/#run=" + encodeURIComponent(name);
          }
        };
        if (kind === "comparison") {
          return {
            buildBody:  self._comparisonSaveBody.bind(self),
            snapshotKey: "_comparisonSavedSnapshot",
            emptyMsg:   "Select at least one diff facet before saving",
            kindLabel:  "comparison",
            nameLabel:  "Name the comparison before saving",
            runTrigger: _inlineRunTrigger,
          };
        }
        /* compound (default for recipe-doc kinds) */
        return {
          buildBody:  self._compoundSaveBody.bind(self),
          snapshotKey: "_compoundSavedSnapshot",
          emptyMsg:   "Add at least one section before saving",
          kindLabel:  "compound",
          nameLabel:  "Name the compound report before saving",
          runTrigger: _inlineRunTrigger,
        };
      },

      /* _saveRecipeDoc(kind) — shared save flow for compound and comparison docs.
         Parameterized entirely by _recipeKindCfg(kind) so both branches are
         byte-for-byte equivalent in behavior; only the descriptor values differ.
         Flow: validate name → validate sections → isSaving guard → build body →
               POST /api/builder/recipes → on success: stamp snapshot + rename-cleanup
               (DELETE old slug) + refreshSaved + picker-sync + toast; finally: clear
               isSaving.  Mirrors the old inline compound/comparison save() branches. */
      _saveRecipeDoc: function (kind) {
        var cfg = this._recipeKindCfg(kind);
        var name = (this.model.name || "").trim();
        if (!name) {
          toast(cfg.nameLabel);
          return;
        }
        if (!Array.isArray(this.model.sections) || this.model.sections.length < 1) {
          toast(cfg.emptyMsg);
          return;
        }
        /* Fix #3: compound (and comparison) must have at least one output format. */
        var _outputFmts = (this.model.output && Array.isArray(this.model.output.formats))
          ? this.model.output.formats : [];
        if (_outputFmts.length === 0) {
          toast("Select at least one output format (HTML or PDF)");
          return;
        }
        if (this.isSaving) return;
        this.isSaving = true;
        var self = this;
        var prevSlug = this.loadedSlug;
        var body = cfg.buildBody();
        apiJSON("POST", "/api/builder/recipes", body).then(function (res) {
          if (!res.ok) {
            toast((res.data && res.data.error) || "Save failed");
            return;
          }
          var newSlug = (res.data && res.data.slug) || "";
          var renamed = !!prevSlug && !!newSlug && prevSlug !== newSlug;
          /* Stamp the dirty-gate snapshot so _runRecipeDoc knows this version
             is clean (matches what was just written to disk).  Captured from
             body (pre-POST) so the snapshot matches exactly what was sent. */
          self[cfg.snapshotKey] = JSON.stringify(body);
          function finish() {
            self.loadedSlug = newSlug;
            self.refreshSaved().then(function () {
              var sel = self.$el.querySelector("#wf-saved");
              if (sel) sel.value = kind + ":" + newSlug;
            });
            if (renamed) {
              toast("Renamed to “" + name + "”");
            } else {
              toast("Saved “" + name + "”");
            }
          }
          if (renamed) {
            apiJSON(
              "DELETE",
              "/api/builder/recipes/" + encodeURIComponent(prevSlug)
            ).then(function (del) {
              if (!del.ok) {
                toast(
                  (del.data && del.data.error) ||
                    "Saved, but couldn't remove the old recipe file"
                );
              }
              finish();
            });
          } else {
            finish();
          }
        }).finally(function () {
          self.isSaving = false;
        });
      },

      /* _runRecipeDoc(kind) — shared run flow for compound and comparison docs.
         Parameterized by _recipeKindCfg(kind): save-gate (toast if no loadedSlug) →
         dirty-gate (toast if body ≠ snapshot) → trigger (openFR / openConfigure /
         deep-link).  Mirrors the old inline compound/comparison runWorkflow() branches. */
      _runRecipeDoc: function (kind) {
        var cfg = this._recipeKindCfg(kind);
        var kindLabel = cfg.kindLabel;
        /* Save-gate: the recipe must have been saved to disk before running
           (RecipeLoader resolves it by name from disk). */
        if (!this.loadedSlug) {
          toast("Save the " + kindLabel + " before running");
          return;
        }
        /* Dirty-gate: refuse to run if the model has been mutated since the last
           save (or load) — the on-disk version would be stale. */
        if (JSON.stringify(cfg.buildBody()) !== this[cfg.snapshotKey]) {
          toast("Save your changes before running");
          return;
        }
        cfg.runTrigger(this.model.name);
      },

      /* refreshSaved — merge /api/workflows (workflows) + /api/builder/recipes
         (compound + comparison user docs) into this.saved with kind tags.
         Degrades gracefully: if either fetch fails the other still feeds the list.
         Returns a promise that resolves when both fetches settle. */
      refreshSaved: function () {
        var self = this;
        var wfPromise = apiJSON("GET", "/api/workflows").then(function (res) {
          return (Array.isArray(res.data) ? res.data : []).map(function (w) {
            // Intentional narrowing: the picker only needs slug/name/kind.
            return { slug: w.slug, name: w.name, kind: "workflow" };
          });
        }).catch(function () { return []; });
        var rcPromise = apiJSON("GET", "/api/builder/recipes").then(function (res) {
          return Array.isArray(res.data) ? res.data : [];
        }).catch(function () { return []; });
        return Promise.all([wfPromise, rcPromise]).then(function (results) {
          self.saved = results[0].concat(results[1]);
        });
      },

      /* ---- save / new / load / delete ---- */
      save: function () {
        /* ── Comparison save: delegate to shared recipe-doc save flow ── */
        if (this.model.kind === "comparison") {
          this._saveRecipeDoc("comparison");
          return;
        }
        /* ── Compound save: delegate to shared recipe-doc save flow ── */
        if (this.model.kind === "compound") {
          this._saveRecipeDoc("compound");
          return;
        }
        var self = this;
        if (this.isSaving) return;
        var name = (this.model.name || "").trim();
        if (!name) {
          toast("Name the workflow before saving");
          return;
        }
        this.isSaving = true;
        var prevSlug = this.loadedSlug; // the slug we loaded from (if any)
        var body = this.toEngineModel();
        apiJSON("POST", "/api/workflows", body).then(function (res) {
          if (!res.ok) {
            toast((res.data && res.data.error) || "Save failed");
            return;
          }
          var newSlug = res.data.slug || "";
          /* Rename cleanup (fix E): a loaded workflow whose name change derived
             a NEW slug leaves the old slug file orphaned in the store/dropdown.
             Delete the old slug, then point loadedSlug at the new file.  Guard
             the delete so a failure toasts but never crashes the save flow. */
          var renamed = !!prevSlug && !!newSlug && prevSlug !== newSlug;
          function finish() {
            self.loadedSlug = newSlug;
            self.refreshSaved().then(function () {
              var sel = self.$el.querySelector("#wf-saved");
              /* Option values are "<kind>:<slug>" — prefix with "workflow:" so a
                 compound with the same slug is not accidentally selected (Option A fix). */
              if (sel) sel.value = "workflow:" + self.loadedSlug;
            });
            if (renamed) {
              toast("Renamed to “" + name + "”");
            } else {
              toast("Saved “" + name + "”");
            }
          }
          if (renamed) {
            apiJSON(
              "DELETE",
              "/api/workflows/" + encodeURIComponent(prevSlug)
            ).then(function (del) {
              if (!del.ok) {
                toast(
                  (del.data && del.data.error) ||
                    "Saved, but couldn't remove the old workflow file"
                );
              }
              finish();
            });
          } else {
            finish();
          }
        }).finally(function () {
          self.isSaving = false;
        });
      },

      newWorkflow: function () {
        var self = this;
        if (this.runMode) this.exitRun();
        this.model = blankModel("workflow");
        this.loadedSlug = "";
        this.selected = null;
        var sel = this.$el.querySelector("#wf-saved");
        if (sel) sel.value = "";
        this.$nextTick(function () {
          relucide();
          /* Re-seed the global scope cascade so the Project/Version dropdowns
             reflect the reset (pinned) model scope rather than the previously
             loaded workflow's scope (M2-1). Alpine has updated the :data-value
             attrs from blankModel() by now, so initScope re-seeds from them. */
          self.initScope();
        });
        toast("New workflow");
      },

      /* newOfKind(kind) — "+ New ▾" action for compound/comparison (scaffold).
         Navigates to the builder with the appropriate ?kind&new=1 params so the
         URL reflects the open document kind (simpler than in-place reset and
         consistent with the palette items). For workflow, delegates to newWorkflow
         to preserve existing behavior exactly. */
      newOfKind: function (kind) {
        if (!kind || kind === "workflow") {
          this.newWorkflow();
          return;
        }
        location.href = "/workflows/builder?kind=" + encodeURIComponent(kind) + "&new=1";
      },

      loadSelected: function (evt) {
        var raw = evt.target.value;
        if (!raw) return;
        /* Option values are encoded as "<kind>:<slug>" (Option A: kind encoded in
           value so slug collisions across stores are unambiguous).  Split on the
           first ":" only — slugs never contain ":" but we guard anyway. */
        var colonIdx = raw.indexOf(":");
        var kind, slug;
        if (colonIdx > 0) {
          kind = raw.slice(0, colonIdx);
          slug = raw.slice(colonIdx + 1);
        } else {
          /* Legacy fallback: bare slug with no kind prefix — read from data-kind. */
          slug = raw;
          var selOpt = evt.target.selectedOptions && evt.target.selectedOptions[0];
          kind = (selOpt && selOpt.dataset && selOpt.dataset.kind) || "workflow";
        }
        this.loadByKindAndSlug(kind, slug);
      },

      /* loadByKindAndSlug(kind, slug) — kind-aware load dispatcher.  Delegates
         to _loadEndpointFor(kind, slug) as the single source of truth for the
         compound/comparison vs. workflow routing decision, then calls the
         appropriate specialised loader.  All future load call sites (PR2/PR3)
         should route through this method so the routing logic never drifts. */
      loadByKindAndSlug: function (kind, slug) {
        var ep = _loadEndpointFor(kind, slug);
        if (ep.indexOf("/api/builder/recipes/") === 0) {
          this.loadRecipeBySlug(slug);
        } else {
          this.loadBySlug(slug);
        }
      },

      loadBySlug: function (slug) {
        var self = this;
        if (this.runMode) this.exitRun();
        apiJSON("GET", "/api/workflows/" + encodeURIComponent(slug)).then(function (res) {
          if (!res.ok) {
            toast((res.data && res.data.error) || "Couldn't load this workflow");
            return;
          }
          /* C2: a deliberate load resets the dirty sentinel up front so the
             loaded doc's saved target is ADOPTED — workflow A's dirty target
             can't leak into workflow B.  A GENERAL doc still keeps the user's
             current scope (fromEngineModel's target_agnostic branch). */
          if (self.model && self.model.global) self.model.global.target_dirty = false;
          self.fromEngineModel(res.data);
          self.loadedSlug = slug;
          self.selected = null;
          self.$nextTick(function () {
            relucide();
            /* Re-seed/re-init the global scope cascade for the loaded project
               so the Version dropdown shows the loaded project's versions (not
               the previous project's) and the selects match the loaded model
               (fix B).  Alpine has updated the :data-value attrs from the new
               model by now, so initScope re-seeds from them. */
            self.initScope();
          });
          toast("Loaded “" + self.model.name + "”");
        });
      },

      /* loadRecipeBySlug(slug) — load a compound/comparison doc from the
         /api/builder/recipes/{slug} endpoint.  On success, sets model.kind
         AUTHORITATIVELY from the response's `kind` field (derived from axis
         presence) rather than the URL hint — so a mismatched ?kind still opens
         the correct editor.  Deserializes compound fields (sections, cover,
         output) into the editor model; comparison fields are stashed raw for
         PR3 (the comparison load-inverse). */
      loadRecipeBySlug: function (slug) {
        var self = this;
        if (this.runMode) this.exitRun();
        apiJSON("GET", "/api/builder/recipes/" + encodeURIComponent(slug)).then(function (res) {
          if (!res.ok) {
            toast((res.data && res.data.error) || "Couldn't load this recipe");
            return;
          }
          var data = res.data || {};
          /* Authoritative kind from the loaded YAML's axis field (not URL hint). */
          var loadedKind = data.kind || "compound";
          self.model = blankModel(loadedKind);
          self.model.name  = data.name  || "";
          self.model.title = data.title || "";
          /* #20 (B6): repopulate Description + Type (both kinds). */
          self.model.description  = data.description  || "";
          self.model.nav_category = data.nav_category || "Executive";
          /* Deserialize compound fields into the editor model (PR2.2a; Task C). */
          if (loadedKind === "compound") {
            /* Sections-as-objects: the GET endpoint returns {recipe, overrides?}
               objects (bare strings already migrated server-side), but normalize
               defensively here too so a hand-authored bare string becomes a
               {recipe, overrides:{}} object the inspector can edit. */
            self.model.sections = (Array.isArray(data.sections) ? data.sections : []).map(
              function (sec) {
                if (typeof sec === "string") return { recipe: sec, overrides: {} };
                var ov = sec && typeof sec.overrides === "object" && sec.overrides ? sec.overrides : {};
                return { recipe: (sec && sec.recipe) || "", overrides: ov };
              }
            );
            /* Hydrate the Global-Properties rail from the loaded `global` block
               (Task A returns a normalized dict).  Seed the rail fields + the
               intent flags; a freshly-loaded target-bound compound starts clean
               (target_dirty=false) so a programmatic cascade re-seed can't trip
               the dirty sentinel.  finding_types is run-only (never persisted) so
               it loads back empty. */
            var lg = (data.global && typeof data.global === "object") ? data.global : {};
            var lgStart = lg.start || "";
            var lgEnd = lg.end || "";
            self.model.global = {
              project_filter: lg.project_filter || "",
              folder_filter: lg.folder_filter || "",
              version_filter: lg.version_filter || "",
              period: lgStart && lgEnd ? "" : (lg.period || "30d"),
              start: lgStart,
              end: lgEnd,
              target_agnostic: coerceBool(lg.target_agnostic),
              target_dirty: false,
              period_touched: coerceBool(lg.period_touched),
              range_touched: coerceBool(lg.range_touched),
              finding_types: "",
              ai: coerceBool(lg.ai),
              ai_depth: lg.ai_depth || "summary",
              cache_ttl: lg.cache_ttl || "4h",
            };
            var rawCover = data.cover || {};
            self.model.cover = {
              subtitle: rawCover.subtitle || "",
              logo: rawCover.logo || "",
              classification: rawCover.classification || "",
            };
            var rawOutput = data.output || {};
            self.model.output = {
              formats: Array.isArray(rawOutput.formats) ? rawOutput.formats.slice() : ["html", "pdf"],
              toc: rawOutput.toc !== false,
              page_numbers: rawOutput.page_numbers !== false,
            };
          } else {
            /* comparison (PR3.1) — deserialize L/R scope + sections + output. */
            /* sections: the YAML stores {recipe: slug} dicts; the GET endpoint
               returns them as plain strings (see get_builder_recipe normalisation). */
            self.model.sections = Array.isArray(data.sections) ? data.sections.slice() : [];
            /* axis: {left: "scope-ref", right: "scope-ref"} — decompose into
               name-component dicts for the editor (PR3.2 full load-inverse).
               For now we do a best-effort decomposition: if the ref is a
               project: ref, parse out project + version; if folder: parse folder. */
            var axis = (data.axis && typeof data.axis === "object") ? data.axis : {};
            self.model.left  = self._parseScopeRef(String(axis.left  || ""));
            self.model.right = self._parseScopeRef(String(axis.right || ""));
            var rawOutput = data.output || {};
            self.model.output = {
              formats:      Array.isArray(rawOutput.formats) ? rawOutput.formats.slice() : ["html", "pdf"],
              toc:          rawOutput.toc !== false,
              page_numbers: rawOutput.page_numbers !== false,
            };
            self.model.cover = data.cover || null;
          }
          self.loadedSlug = slug;
          /* Stamp the dirty-gate snapshot so a just-loaded doc is considered
             clean — runWorkflow() will only allow running if the model still
             matches this snapshot (i.e. no edits since load). */
          if (loadedKind === "compound") {
            self._compoundSavedSnapshot = JSON.stringify(self._compoundSaveBody());
          }
          if (loadedKind === "comparison") {
            self._comparisonSavedSnapshot = JSON.stringify(self._comparisonSaveBody());
          }
          self.selected = null;
          /* Task C: reset the section selection + its scope-cascade guard so the
             new compound's inspector starts closed and re-binds cleanly. */
          self.selectedSection = null;
          self._secScopeIndex = null;
          self._secScopeBindingIndex = null;
          self._clearSecScopeRetry();
          /* Reset comparison cascade guard so the new model's scopes are seeded. */
          self._cmpScopesInited = false;
          self.$nextTick(function () {
            if (loadedKind === "compound") {
              self.loadLogos();
              /* Re-seed the Global-Properties cascade for the loaded compound's
                 target (mirrors the workflow loadBySlug initScope re-seed) — the
                 :data-value attrs already reflect the hydrated model.global. */
              self.initScope();
            }
            if (loadedKind === "comparison") { self.initCmpScopes(); }
            relucide();
          });
          toast("Loaded “" + (self.model.name || slug) + "”");
        });
      },

      deleteLoaded: function () {
        if (!this.loadedSlug) return;
        var self = this;
        var slug = this.loadedSlug;
        /* Capture kind before resetting, for routing + toast. */
        var kind = (this.model && this.model.kind) || "workflow";
        var kindLabel = this._kindLabel(kind);
        if (!window.confirm("Delete this saved " + kindLabel + "? This cannot be undone.")) {
          return;
        }
        /* Route to the correct backend endpoint by loaded doc kind. */
        var endpoint = (kind === "compound" || kind === "comparison")
          ? "/api/builder/recipes/" + encodeURIComponent(slug)
          : "/api/workflows/" + encodeURIComponent(slug);
        apiJSON("DELETE", endpoint).then(function (res) {
          if (!res.ok) {
            toast((res.data && res.data.error) || "Delete failed");
            return;
          }
          /* Reset to a blank editor of the same kind as the deleted doc. */
          self.model = blankModel(kind);
          self.loadedSlug = "";
          self.selected = null;
          self.selectedSection = null;
          self._secScopeIndex = null;
          self._secScopeBindingIndex = null;
          self._clearSecScopeRetry();
          self.refreshSaved().then(function () {
            var sel = self.$el.querySelector("#wf-saved");
            if (sel) sel.value = "";
          });
          self.$nextTick(function () {
            relucide();
          });
          toast("Deleted " + kindLabel);
        });
      },

      /* ---- model <-> engine-key serialization ---- */
      /* The Alpine model already uses engine keys; we only shape the persisted
         payload (top-level start/end for the date range, and the
         steps carry only id/kind/ref/overrides/params). The store normalizes/
         derives the rest (slug, runnable_locally) server-side.
         Mutual-exclusion: if BOTH start AND end are set, period is sent as null
         (range wins) so the server never sees both. */
      toEngineModel: function () {
        var g = this.model.global;
        var hasRange = !!(g.start && g.end);
        var project = g.project_filter || null;
        return {
          schema_version: 1,
          name: (this.model.name || "").trim(),
          global: {
            project_filter: project,
            /* Folder targeting (design §6): send the global folder scope only
               when no project is set (project wins — the server re-applies the
               same drop in _build_engine_config, but keeping the payload clean
               matches the optimistic UI state). */
            folder_filter: project ? null : g.folder_filter || null,
            version_filter: g.version_filter || null,
            period: hasRange ? null : (g.period || "30d"),
            start: g.start || null,
            end: g.end || null,
            /* C1: persist the user's explicit Global-Properties date-mode intent
               (default-off). These steer step-period precedence at run/export/
               preview; they are NOT engine keys (read-and-stripped before the
               effective/engine config). Coerced so an absent/undefined flag
               serializes as a real `false` matching _GLOBAL_DEFAULTS. */
            period_touched: coerceBool(g.period_touched),
            range_touched: coerceBool(g.range_touched),
            /* C2: round-trip the target-bound vs general flag.  The current
               *_filter target is INTENTIONALLY kept in the payload (above) even
               for a general workflow — a RUN must honor the user's live
               Global-Properties target.  The save-side strip (server
               _model_to_yaml_dict) removes the baked target from the PERSISTED
               doc; toEngineModel feeds runs/preview/save-normalize, not the
               on-disk shape. */
            target_agnostic: coerceBool(g.target_agnostic),
            ai: coerceBool(g.ai),
            ai_depth: g.ai_depth || "summary",
            cache_ttl: g.cache_ttl || "4h",
          },
          steps: this.model.steps.map(function (s) {
            return {
              id: s.id,
              kind: s.kind,
              ref: s.ref,
              overrides: s.overrides || {},
              params: s.params || {},
            };
          }),
        };
      },

      fromEngineModel: function (data) {
        var g = (data && data.global) || {};
        var rawSteps = data && Array.isArray(data.steps) ? data.steps : [];
        /* C2: capture the CURRENT global scope + dirty state BEFORE rebuilding
           the model, so we can decide whether to ADOPT the loaded scope or
           PRESERVE the user's current Global-Properties selection.  The loaded
           doc's target_agnostic flag (default false for legacy docs) drives the
           "general" branch. */
        var curG = (this.model && this.model.global) || {};
        var loadedAgnostic = coerceBool(g.target_agnostic);
        var targetDirty = !!curG.target_dirty;
        /* General workflow OR a user-dirty target → keep the current scope (the
           user's Global-Properties selection); otherwise adopt the saved scope.
           Legacy/target-bound + clean ⇒ adopt the loaded *_filter. */
        var keepCurrentScope = loadedAgnostic || targetDirty;
        var scopeSrc = keepCurrentScope ? curG : g;
        /* Fix G: preserve the persisted step `id`s (they're stable, client-
           generated, unique within a workflow, and the reorder/inspector
           bindings key off them).  Seed the id counter past the max preserved
           numeric suffix so any later freshId() can't collide; only generate a
           fresh id when a loaded step LACKS one. */
        seedIdCounter(
          rawSteps.map(function (s) {
            return s && s.id;
          })
        );
        /* Respect period↔range mutual exclusion when seeding the model: a
           range-only workflow (server-normalized to start/end with NO period)
           must NOT get a phantom default "30d", or the Period input + the
           per-step "(global · …)" hint would show a stale period alongside the
           range.  Default to "30d" ONLY when no custom range is present. */
        var loadedStart = g.start || "";
        var loadedEnd = g.end || "";
        var loadedPeriod =
          loadedStart && loadedEnd ? "" : g.period || "30d";
        this.model = {
          kind: "workflow",
          name: data && data.name ? data.name : "",
          global: {
            /* C2: adopt the SAVED scope for a target-bound clean load; PRESERVE
               the user's current Global-Properties scope for a GENERAL workflow
               (target_agnostic) or a user-dirty target (scopeSrc resolves to
               whichever applies). */
            project_filter: scopeSrc.project_filter || "",
            /* Folder targeting (design §6): restore the saved global folder
               scope so the cascade re-seeds the folder select on load (unless
               keeping the current scope per C2). */
            folder_filter: scopeSrc.folder_filter || "",
            version_filter: scopeSrc.version_filter || "",
            period: loadedPeriod,
            start: loadedStart,
            end: loadedEnd,
            /* C1: restore the persisted date-mode intent flags so a loaded
               workflow keeps the user's "global overrides card period" choice.
               Coerced (a hand-edited string "false" reads as off). */
            period_touched: coerceBool(g.period_touched),
            range_touched: coerceBool(g.range_touched),
            /* C2: round-trip the target-bound vs general flag. */
            target_agnostic: loadedAgnostic,
            /* C2: a load that ADOPTS the saved scope starts clean; a load that
               PRESERVED a user-dirty target keeps it dirty so a later re-seed
               still can't clobber it.  (loadBySlug/newWorkflow reset this to
               false up front for a deliberate, fully-clean load.) */
            target_dirty: keepCurrentScope ? targetDirty : false,
            ai: coerceBool(g.ai),
            ai_depth: g.ai_depth || "summary",
            cache_ttl: g.cache_ttl || "4h",
          },
          steps: rawSteps.map(function (s) {
            return {
              id: s && s.id ? s.id : freshId(),
              kind: s.kind || "recipe",
              ref: s.ref || "",
              overrides: s.overrides || {},
              params: s.params || {},
            };
          }),
        };
      },

      /* ============================================================
       * PR3.1: Comparison editor — scope cascades, facets, title, save.
       * ============================================================ */

      /* _parseScopeRef(ref) — best-effort decomposition of a scope-ref string
         into a {project, folder, version} name dict.  Used when loading a
         comparison whose axis already has pre-baked scope-ref strings (PR3.2
         full load-inverse will refine this).  Returns an empty dict on failure. */
      _parseScopeRef: function (ref) {
        var blank = { project: "", folder: "", version: "" };
        if (!ref || typeof ref !== "string") return blank;
        ref = ref.trim();
        if (ref.indexOf("project:") === 0) {
          var rest = ref.slice("project:".length);
          var atIdx = rest.indexOf("@");
          var project = atIdx >= 0 ? rest.slice(0, atIdx) : rest;
          var version = atIdx >= 0 ? rest.slice(atIdx + 1) : "";
          return { project: project, folder: "", version: version };
        }
        if (ref.indexOf("folder:") === 0) {
          return { project: "", folder: ref.slice("folder:".length), version: "" };
        }
        /* Bare form (no prefix) — the scope-ref grammar infers project: (e.g. a
           hand-edited `axis.left: BN85@v1`).  Decompose as a project ref so the
           Left/Right pickers seed instead of loading empty. */
        var bareAt = ref.indexOf("@");
        return {
          project: bareAt >= 0 ? ref.slice(0, bareAt) : ref,
          folder: "",
          version: bareAt >= 0 ? ref.slice(bareAt + 1) : "",
        };
      },

      /* _cmpSelectName(selectEl) — read the NAME (display label) from a scope
         select's currently-selected option.  The cascade populates option values
         as IDs, but we store NAMES in model.left/right so scope-ref baking is
         name-based.  Trims surrounding whitespace (tree-indent). */
      _cmpSelectName: function (selectEl) {
        if (!selectEl) return "";
        var opt = selectEl.options[selectEl.selectedIndex];
        if (!opt || !opt.value) return "";
        return (opt.textContent || "").trim() || "";
      },

      /* initCmpScopes — initialize the two independent Left/Right scope
         cascades.  Called once on init/$nextTick when kind === 'comparison'.
         The _cmpScopesInited guard is reset when kind changes (newOfKind /
         loadRecipeBySlug) so a re-navigate re-seeds them from the new model. */
      initCmpScopes: function () {
        if (typeof window.initScopeDropdowns !== "function") return;
        if (this._cmpScopesInited) return;
        var self = this;
        /* Left cascade — ids: cmp-left-folder / cmp-left-project / cmp-left-version */
        window.initScopeDropdowns({
          root: this.$el,
          folderId:   "cmp-left-folder",
          projectId:  "cmp-left-project",
          versionId:  "cmp-left-version",
          folderEmptyLabel:  "(any folder)",
          projectEmptyLabel: "(pick a project)",
          onChange: function (scope) {
            self._onCmpScopeChange("left", scope);
          },
        });
        /* Right cascade — ids: cmp-right-folder / cmp-right-project / cmp-right-version */
        window.initScopeDropdowns({
          root: this.$el,
          folderId:   "cmp-right-folder",
          projectId:  "cmp-right-project",
          versionId:  "cmp-right-version",
          folderEmptyLabel:  "(any folder)",
          projectEmptyLabel: "(pick a project)",
          onChange: function (scope) {
            self._onCmpScopeChange("right", scope);
          },
        });
        this._cmpScopesInited = true;
      },

      /* _onCmpScopeChange(side, scope) — onChange callback from initScopeDropdowns
         for the Left or Right cascade.  scope = {folder (ID), project (name/ID), version (name/ID)}.
         We store NAMEs; the cascade emits names as option values for project/version
         (populateSelect uses p.name || p.id) and IDs for folder. To get the folder NAME
         we read the label from the select. */
      _onCmpScopeChange: function (side, scope) {
        scope = scope || {};
        var folderId  = scope.folder  || "";
        var projectVal = scope.project || "";
        var versionVal = scope.version || "";
        /* Resolve folder NAME from its select label (IDs are stored as values). */
        var folderName = "";
        if (folderId) {
          var folderSelId = "cmp-" + side + "-folder";
          var folderSel = this.$el.querySelector("#" + folderSelId);
          if (folderSel) {
            folderName = this._cmpSelectName(folderSel);
          }
        }
        /* project/version are already name-based in this cascade. */
        if (!this.model[side]) this.model[side] = { project: "", folder: "", version: "" };
        var m = this.model[side];
        m.project = projectVal;
        m.version = versionVal;
        m.folder  = projectVal ? "" : folderName; // project-wins: clear folder when project set
      },

      /* onCmpLeftScopeChange / onCmpRightScopeChange — called by the @change
         bindings on the individual selects in the template (a redundancy guard:
         the cascade's onChange already writes the model; these are insurance
         for direct user edits that bypass the cascade callback). */
      onCmpLeftScopeChange: function () {
        /* Read names directly from the select labels. */
        var folderSel   = this.$el.querySelector("#cmp-left-folder");
        var projectSel  = this.$el.querySelector("#cmp-left-project");
        var versionSel  = this.$el.querySelector("#cmp-left-version");
        var project = this._cmpSelectName(projectSel);
        var version = this._cmpSelectName(versionSel);
        var folder  = project ? "" : this._cmpSelectName(folderSel);
        if (!this.model.left) this.model.left = { project: "", folder: "", version: "" };
        this.model.left.project = project;
        this.model.left.version = version;
        this.model.left.folder  = folder;
      },

      onCmpRightScopeChange: function () {
        var folderSel  = this.$el.querySelector("#cmp-right-folder");
        var projectSel = this.$el.querySelector("#cmp-right-project");
        var versionSel = this.$el.querySelector("#cmp-right-version");
        var project = this._cmpSelectName(projectSel);
        var version = this._cmpSelectName(versionSel);
        var folder  = project ? "" : this._cmpSelectName(folderSel);
        if (!this.model.right) this.model.right = { project: "", folder: "", version: "" };
        this.model.right.project = project;
        this.model.right.version = version;
        this.model.right.folder  = folder;
      },

      /* cmpSideLabel(side) — human-readable label for a comparison side:
         "project version" / "project" / "folder: name"; empty string when the
         side has nothing.  Used for the scope-preview under each cascade and
         for auto-title. */
      cmpSideLabel: function (side) {
        var s = (this.model && this.model[side]) || {};
        var project = (s.project || "").trim();
        var version = (s.version || "").trim();
        var folder  = (s.folder  || "").trim();
        if (project) {
          return version ? project + " " + version : project;
        }
        if (folder) {
          return "folder: " + folder;
        }
        return "";
      },

      /* cmpAutoTitle() — the auto-derived "<left> → <right>" title.
         Used as the title input's placeholder and as the default when empty. */
      cmpAutoTitle: function () {
        var leftLabel  = this.cmpSideLabel("left");
        var rightLabel = this.cmpSideLabel("right");
        if (!leftLabel && !rightLabel) return "Left → Right";
        return (leftLabel || "Left") + " → " + (rightLabel || "Right");
      },

      /* toggleComparisonFacet(slug, checked) — add/remove a comparison facet
         slug from model.sections. */
      toggleComparisonFacet: function (facetSlug, checked) {
        if (!Array.isArray(this.model.sections)) this.model.sections = [];
        if (checked) {
          if (this.model.sections.indexOf(facetSlug) === -1) {
            this.model.sections.push(facetSlug);
          }
        } else {
          var idx = this.model.sections.indexOf(facetSlug);
          if (idx !== -1) this.model.sections.splice(idx, 1);
        }
      },

      /* _comparisonSaveBody() — single source of truth for the comparison POST
         body.  Produces per-side NAME dicts (model.left/right) so the server can
         call _build_scope_ref for baking + grammar hard-block validation. */
      _comparisonSaveBody: function () {
        var left  = this.model.left  || { project: "", folder: "", version: "" };
        var right = this.model.right || { project: "", folder: "", version: "" };
        var output = this.model.output || {};
        /* Cover metadata: comparison docs carry cover (subtitle/logo/classification)
           authored via `compare --save-as`.  The editor has no cover UI today, so
           model.cover is populated only from loadRecipeBySlug — but we MUST echo it
           back here (mirroring _compoundSaveBody) or a load→save round-trip silently
           drops CLI-authored cover settings. */
        var cover = this.model.cover || {};
        /* Derive title: use model.title if non-empty; else compute the auto title. */
        var title = (this.model.title || "").trim() || this.cmpAutoTitle();
        return {
          kind: "comparison",
          name: (this.model.name || "").trim(),
          title: title,
          description: this.model.description || "",
          nav_category: this.model.nav_category || "Executive",
          sections: Array.isArray(this.model.sections) ? this.model.sections.slice() : [],
          left:  { project: left.project  || "", folder: left.folder  || "", version: left.version  || "" },
          right: { project: right.project || "", folder: right.folder || "", version: right.version || "" },
          cover_subtitle: cover.subtitle || null,
          logo: cover.logo || null,
          classification: cover.classification || null,
          output: {
            formats:      Array.isArray(output.formats) ? output.formats.slice() : ["html", "pdf"],
            toc:          output.toc !== false,
            page_numbers: output.page_numbers !== false,
          },
        };
      },

      /* exposed for inline x-init on the step icon so a freshly-rendered card
         gets its lucide glyph painted. */
      relucide: relucide,
    };
  }

  /* Register the component. Support both eager (Alpine already present) and the
     `alpine:init` event so load order with the deferred alpine.min.js is safe. */
  window.builder = builderComponent;
  /* Expose blankModel so test harnesses (node --eval) can call it directly. */
  window.blankModel = blankModel;
  document.addEventListener("alpine:init", function () {
    if (window.Alpine && typeof window.Alpine.data === "function") {
      window.Alpine.data("builder", builderComponent);
    }
  });
})();
