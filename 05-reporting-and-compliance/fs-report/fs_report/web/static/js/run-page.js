/* ===================================================================
 * Run canvas page (Pass 4 · Task 6) — the LIVE controller.
 *
 * ONE Alpine component (`runCanvas()`) drives the Run canvas: it opens the
 * EXISTING per-run SSE stream (`/api/run/<id>/events`), maps each `step` /
 * `progress` / `done` event onto the server-rendered node DOM, lays the nodes
 * out per run KIND (workflow/report serpentine, compound fan-in), draws the
 * neon bezier edges, drives the brand orb, and wires the Stop / Replay
 * transport.  The template (run.html, Task 5) DEFINES the contract this file
 * implements against — the data-field names + method names below MUST match it
 * exactly (see the template's top comment).
 *
 * Deliberate non-import (spec §6.5): the SSE handling here is a COPY-ALIGNMENT
 * of builder-page.js's openStream/onStepEvent/onDoneEvent — NOT an import — so
 * the two stay behaviorally consistent without coupling. The geometry helpers
 * (path/edgePath) are ported verbatim from the mockup
 * (docs/design/phase2/Phase 2 Run.html); the mockup HARDCODES positions for 8
 * named nodes, so layout() here COMPUTES positions from the actual node count.
 *
 * Backend contract this file relies on (fs_report/web/routers/run.py):
 *   step   → {step_index, step_id, state, message, files, report_url, reason}
 *   progress (report)   → {completed, total, recipe}
 *   progress (compound) → {completed, total}            (section hook)
 *   progress (workflow) → {completed, total}
 *   done (report/compound) → {status, error, files, ...}
 *   done (workflow)        → {status, error?, log_file?}
 *   status ∈ "success" | "cancelled" | "error"
 *   node ids == SSE step_ids (workflow: step.id; compound child: slug(recipe);
 *   plain report: recipe NAME) — the node-id ↔ step-id invariant (spec §4.2).
 *   The SSE stream re-emits the full buffered history on connect, so a refresh
 *   / late-join rebuilds runStates + lights nodes (incl. an already-terminal
 *   run, whose buffered `done` flips the orb + transport).
 * =================================================================== */

(function () {
  "use strict";

  var SVG_NS = "http://www.w3.org/2000/svg";

  /* Stage dims — mirror the .stage CSS box + the edges <svg viewBox> (1120×600
     in run-page.css / run.html). Edge coordinates are in this unscaled space;
     the SVG's preserveAspectRatio="none" maps them onto the rendered stage. */
  var STAGE_W = 1120;
  var STAGE_H = 600;
  /* Minimum gap between paced replay events — must exceed the longest CSS
     fill transition (600ms) so animations complete before the next state
     change arrives. */
  var REPLAY_CADENCE_MS = 650;

  /* Node box sizes per kind — the CSS positions absolutely but does NOT size
     the nodes, so JS sets width/height (the mockup did the same). Ported from
     the mockup's W/H (source) / RW/RH (recipe) / BW (deliverable). */
  var SIZE = {
    source: { w: 160, h: 140 },
    recipe: { w: 180, h: 150 },
    mcp_tool: { w: 180, h: 150 },
    deliverable: { w: 170, h: 140 },
  };
  function sizeFor(kind) {
    return SIZE[kind] || SIZE.recipe;
  }

  /* ── tiny shared helpers (copy-aligned with builder-page.js) ──────── */

  function csrf() {
    return window.NONCE || "";
  }

  /* Minimal JSON POST (no body) — used for the cancel transport. Mirrors
     builder-page.js's apiJSON shape (CSRF header, normalised {ok,status,data}
     so a network reject never escapes as an unhandled rejection). */
  function apiPOST(url) {
    return fetch(url, { method: "POST", headers: { "X-FS-Session": csrf() } })
      .then(function (r) {
        return r
          .json()
          .catch(function () {
            return {};
          })
          .then(function (data) {
            return { ok: r.ok, status: r.status, data: data };
          });
      })
      .catch(function (err) {
        return {
          ok: false,
          status: 0,
          data: { error: "Network error: " + ((err && err.message) || err) },
        };
      });
  }

  function relucide() {
    if (window.lucide) window.lucide.createIcons();
  }

  function toast(msg) {
    if (typeof window.fsToast === "function") {
      window.fsToast(msg);
      return;
    }
    console.warn("[run]", msg);
  }

  /* Map a skipped step's reason enum to a human note (port builder-page.js's
     skipNote — same reason vocabulary the executor emits). */
  function skipNote(reason, fallback) {
    if (reason === "export_only") return "Runs via Forge agent — export to run";
    if (reason === "halted") return "Skipped — an earlier step failed (halt)";
    if (reason === "cancelled") return "Skipped — run cancelled";
    return fallback || "Skipped";
  }

  /* ── geometry (bezier path helpers ported verbatim from the mockup) ─ */

  function path(x1, y1, x2, y2, vert) {
    if (vert) {
      var dy = Math.max(40, (y2 - y1) * 0.5);
      return (
        "M" + x1 + "," + y1 + " C" + x1 + "," + (y1 + dy) + " " + x2 + "," + (y2 - dy) + " " + x2 + "," + y2
      );
    }
    var dx = (x2 - x1) * 0.45;
    return (
      "M" + x1 + "," + y1 + " C" + (x1 + dx) + "," + y1 + " " + (x2 - dx) + "," + y2 + " " + x2 + "," + y2
    );
  }

  /* ── the Alpine component factory ─────────────────────────────────── */

  function runCanvas() {
    return {
      /* ---- reactive (template-bound) ---- */
      orbState: "idle",
      runState: "running",
      elapsed: "00:00",
      stepDone: 0,
      stepTotal: 0,
      unitLabel: "steps",
      pct: "0%",
      canStop: false,
      canReplay: false,

      /* ---- internal (non-template) ---- */
      runStates: {},
      _es: null,
      _timer: null,
      _replayTimer: null,
      _startMs: 0,
      kind: "report",
      runId: "",
      nodes: [],
      _pos: {}, // {id: [left, top]} computed by layout()
      _deliverableUrl: "",
      _terminal: false,
      /* True only when the page LOADED in terminal mode (a historical replay) —
         distinct from `_terminal`, which onDoneEvent also flips on a live finish.
         Used to suppress the live "finished with an error" toast when merely
         re-opening a past failed/cancelled run. */
      _replay: false,
      _keyHandler: null,

      /* ============================================================ */
      init: function () {
        var boot = window.__RUN || {};
        this.kind = boot.kind || "report";
        this.runId = boot.runId || "";
        this.nodes = boot.nodes || [];
        /* Terminal mode (spec §5.2): a past run re-rendered from its persisted
           _run.json — replay saved events, no socket, no live timer. */
        this._terminal = !!boot.terminal;
        this._replay = !!boot.terminal;

        this.unitLabel =
          this.kind === "compound"
            ? "sections"
            : this.kind === "workflow"
            ? "steps"
            : "reports";

        /* stepTotal = the count of work nodes (everything after the source).
           For compound, the deliverable is a terminal node, not a section, so
           it's excluded too → the child count. */
        var self = this;
        var total = 0;
        this.nodes.forEach(function (n) {
          if (n.kind === "source") return;
          if (self.kind === "compound" && n.kind === "deliverable") return;
          total += 1;
        });
        this.stepTotal = total;
        this.stepDone = 0;
        this.pct = "0%";

        this.runState = "running";
        this.orbState = "running";
        /* A terminal (past) run is over — Stop is disabled; the replayed `done`
           re-enables Replay if a replay blob was persisted. */
        this.canStop = !this._terminal;
        this.canReplay = false;

        /* Place nodes + draw the dormant edge skeleton. */
        this.layout();
        this.buildDorm();
        this.redrawEdges();

        /* T4: keep the stage fitted as the viewport changes — window resize AND
           a vertical scrollbar appearing (which shrinks the viewport's
           clientWidth WITHOUT a window resize, M1-1). Prefer a ResizeObserver on
           the viewport; fall back to the window resize event. Guarded so a
           minimal node-eval stub doesn't throw in init(). */
        var vpEl =
          typeof document.getElementById === "function" &&
          document.getElementById("stage") &&
          document.getElementById("stage").parentElement;
        if (vpEl && typeof ResizeObserver === "function") {
          this._resizeObserver = new ResizeObserver(function () {
            self._fitStage();
          });
          this._resizeObserver.observe(vpEl);
        } else if (typeof window.addEventListener === "function") {
          this._resizeHandler = function () {
            self._fitStage();
          };
          window.addEventListener("resize", this._resizeHandler);
        }

        /* Keyboard a11y: a single delegated keydown on .nodes activates a
           focused clickable node (Enter/Space) — closes the Task-5 review gap. */
        var nodesLayer = document.getElementById("nodes");
        if (nodesLayer) {
          this._keyHandler = function (e) {
            if (e.key !== "Enter" && e.key !== " " && e.key !== "Spacebar") return;
            var el = e.target;
            while (el && el !== nodesLayer && !el.getAttribute("data-node-id")) {
              el = el.parentElement;
            }
            if (el && el.getAttribute("data-node-id")) {
              e.preventDefault();
              self.onNodeClick(el.getAttribute("data-node-id"));
            }
          };
          nodesLayer.addEventListener("keydown", this._keyHandler);
        }

        if (this._terminal) {
          /* Terminal mode (spec §5.2): NO EventSource, NO live timer. Show the
             final elapsed from persisted timing, then feed the saved events
             through the SAME onStep/onProgress/onDone handlers a live SSE replay
             uses — settling the graph, the deliverable, the orb (from the
             replayed terminal `done`), and the Replay gate. */
          this._setTerminalElapsed(boot);
          var events = boot.events || [];
          this._replayEvents(events);
          /* Belt-and-suspenders: persistence only writes a summary that has a
             terminal `done`, so the replay above settles the orb. But if a
             hand-crafted _run.json carried no done, fall back to the persisted
             `result` so the canvas never reads as perpetually running.
             Gate on the absence of a `done` event in the list — NOT on the
             post-replay runState, which is still "running" when paced replay
             has only scheduled (not yet fired) the done event. */
          var hasDoneEvent = events.some(function (ev) { return ev && ev.event === "done"; });
          if (!hasDoneEvent) this._settleFromResult(boot.result);
        } else {
          /* Live: start the elapsed timer + open the SSE stream. */
          this._startMs = Date.now();
          this.elapsed = "00:00";
          this._timer = setInterval(function () {
            self._tick();
          }, 1000);
          this.openStream(this.runId);
        }

        this.$nextTick(function () {
          relucide();
        });
      },

      /* Set the static elapsed readout from persisted timing (finished−started),
         formatted mm:ss. Terminal mode never starts the live timer (which would
         render 00:00) — spec §5.2. */
      _setTerminalElapsed: function (boot) {
        var started = boot.startedAt;
        var finished = boot.finishedAt;
        if (
          typeof started === "number" &&
          typeof finished === "number" &&
          finished >= started
        ) {
          var s = Math.floor(finished - started);
          var mm = Math.floor(s / 60);
          var ss = s % 60;
          this.elapsed =
            (mm < 10 ? "0" + mm : "" + mm) + ":" + (ss < 10 ? "0" + ss : "" + ss);
        } else {
          this.elapsed = "00:00";
        }
      },

      /* Settle the orb / run-state / transport from a persisted result word
         (success|error|cancelled) — the fallback when a terminal summary's
         events lacked a replayable `done`. */
      _settleFromResult: function (result) {
        this.canStop = false;
        if (result === "error") {
          this.runState = "error";
          this.orbState = "error";
        } else if (result === "cancelled") {
          this.runState = "cancelled";
          this.orbState = "idle";
        } else if (result === "success") {
          this.runState = "complete";
          this.orbState = "complete";
        }
      },

      /* Replay the persisted canvas events (step/progress/done) through the live
         handlers, in order. Each event's `data` is the SAME JSON string the SSE
         stream carried, so the handlers parse it identically — no socket. The
         terminal `done` flips the orb + transport via onDoneEvent.

         Motion-on: events are paced at REPLAY_CADENCE_MS intervals (≥ the
         longest CSS transition, 600ms fill) so the same CSS transitions that
         animate a live run fire with gaps between events. The handle is stored
         in `this._replayTimer` so destroy() can cancel a pending chain.
         Motion-off (body.no-motion): fires all events synchronously — identical
         to the old behavior, no animation. */
      _replayEvents: function (events) {
        var self = this;
        /* Cancel any in-flight paced chain before starting a new one, so a
           re-entrant replay can't orphan a pending timer (defensive: today
           there is one call-site per page load). */
        if (this._replayTimer) {
          clearTimeout(this._replayTimer);
          this._replayTimer = null;
        }
        var evList = (events || []).filter(function (ev) { return ev && ev.event; });

        function _fireEvent(ev) {
          if (ev.event === "step") self.onStepEvent(ev.data);
          else if (ev.event === "progress") self.onProgressEvent(ev.data);
          else if (ev.event === "done") self.onDoneEvent(ev.data);
        }

        if (document.body.classList.contains("no-motion")) {
          /* Instant settle — no animation. */
          evList.forEach(_fireEvent);
          return;
        }

        /* Paced replay: fire the FIRST event immediately so the canvas starts
           animating at once (no ~cadence-long idle gap), then schedule each
           subsequent event REPLAY_CADENCE_MS after the previous so CSS
           transitions complete before the next state change arrives. */
        if (evList.length) _fireEvent(evList[0]);
        var idx = 1;
        function _scheduleNext() {
          if (idx >= evList.length) {
            self._replayTimer = null;
            return;
          }
          var ev = evList[idx++];
          self._replayTimer = setTimeout(function () {
            _fireEvent(ev);
            _scheduleNext();
          }, REPLAY_CADENCE_MS);
        }
        _scheduleNext();
      },

      destroy: function () {
        this.closeStream();
        if (this._timer) {
          clearInterval(this._timer);
          this._timer = null;
        }
        if (this._replayTimer) {
          clearTimeout(this._replayTimer);
          this._replayTimer = null;
        }
        if (this._resizeObserver) {
          this._resizeObserver.disconnect();
          this._resizeObserver = null;
        }
        if (this._resizeHandler && typeof window.removeEventListener === "function") {
          window.removeEventListener("resize", this._resizeHandler);
          this._resizeHandler = null;
        }
        var nodesLayer = document.getElementById("nodes");
        if (nodesLayer && this._keyHandler) {
          nodesLayer.removeEventListener("keydown", this._keyHandler);
        }
      },

      _tick: function () {
        if (this._terminal) return;
        var s = Math.floor((Date.now() - this._startMs) / 1000);
        var mm = Math.floor(s / 60);
        var ss = s % 60;
        this.elapsed =
          (mm < 10 ? "0" + mm : "" + mm) + ":" + (ss < 10 ? "0" + ss : "" + ss);
      },

      /* ============================================================
       * SSE — open / close / route (copy-aligned with builder-page.js)
       * ============================================================ */
      openStream: function (runId) {
        this.closeStream();
        if (!runId) return;
        var self = this;
        var es = new EventSource("/api/run/" + encodeURIComponent(runId) + "/events");
        this._es = es;
        es.addEventListener("step", function (e) {
          self.onStepEvent(e.data);
        });
        es.addEventListener("progress", function (e) {
          self.onProgressEvent(e.data);
        });
        es.addEventListener("log", function () {
          /* live log lines are surfaced by the run log; the canvas shows the
             per-node running message instead. */
        });
        es.addEventListener("done", function (e) {
          self.onDoneEvent(e.data);
        });
        es.onerror = function () {
          /* The stream drops on terminal done (server closes it). If we have
             NOT seen a terminal done, treat a hard error as a soft stop —
             leave the nodes as-is rather than forcing a misleading state. */
          if (!self._terminal) {
            self.canStop = false;
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

      /* Map a `step` event onto its node's run-state (spec §6.3). Drives the
         compound section + workflow step lighting. */
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
        this._refreshFill(data.step_id);
        this.redrawEdges();
        var self = this;
        this.$nextTick(function () {
          relucide();
        });
      },

      /* Map a `progress` event (spec §6.3 toolbar N/M + §7 plain-report node
         lighting). For a plain `report` run (which emits NO step events) a
         progress event with `recipe` is the SOLE signal a recipe finished — we
         light the matching node here. For workflow/compound, progress ONLY
         updates the toolbar N/M; node lighting comes from step events. */
      onProgressEvent: function (raw) {
        var data;
        try {
          data = JSON.parse(raw);
        } catch (err) {
          return;
        }
        if (!data) return;
        var completed = data.completed || 0;
        var total = data.total || 0;
        this.stepDone = completed;
        this.stepTotal = total;
        this.pct = total ? Math.round((completed / total) * 100) + "%" : "0%";

        if (this.kind === "report" && data.recipe) {
          /* Match by node id (== recipe name for a plain report, §4.3), NOT the
             display title. Pick the FIRST not-yet-done node with that id so the
             same-recipe-twice case lights one node per completion. */
          for (var i = 0; i < this.nodes.length; i++) {
            var n = this.nodes[i];
            if (n.kind === "source") continue;
            if (n.id !== data.recipe) continue;
            var rs = this.runStates[n.id];
            if (rs && rs.state === "done") continue;
            this.runStates[n.id] = {
              state: "done",
              message: "",
              files: [],
              report_url: "",
              reason: "",
            };
            this.runStates = Object.assign({}, this.runStates);
            break;
          }
          this.redrawEdges();
          var self = this;
          this.$nextTick(function () {
            relucide();
          });
        }
      },

      /* Terminal reconciliation (spec §6.6). Flips orb + transport, force-
         resolves any dangling node, and (compound) lights the deliverable from
         done.files[0]. */
      onDoneEvent: function (raw) {
        var data = {};
        try {
          data = JSON.parse(raw);
        } catch (err) {
          data = {};
        }
        var status = data.status || "success";

        this._terminal = true;
        if (this._timer) {
          clearInterval(this._timer);
          this._timer = null;
        }
        this.canStop = false;
        this.canReplay = !!(window.__RUN && window.__RUN.replay);
        this.closeStream();

        if (status === "cancelled") {
          this.runState = "cancelled";
          this.orbState = "idle";
        } else if (status === "error") {
          this.runState = "error";
          this.orbState = "error";
        } else {
          this.runState = "complete";
          this.orbState = "complete";
        }

        this._reconcile(status, data);

        /* Deliverable lighting — compound only. The combined report's SERVABLE
           URL is computed by the backend (done.report_url) — NOT built from
           done.files[0], so an output_dir override off the served root leaves
           it null and the deliverable is NOT clickable (no 404). It stays
           clickable whenever the backend gave a servable URL, even a partial
           bundle (fix ①). */
        var deliv = this._nodeById("deliverable");
        if (deliv) {
          var files = data.files || [];
          this._deliverableUrl = data.report_url || null;
          if (files.length) {
            /* A combined HTML exists (success OR a partial bundle). Lit
               s-done on success; error-tinted on a partial/failed bundle.
               Clickable iff the backend gave a servable URL. */
            this.runStates["deliverable"] = {
              state: status === "success" ? "done" : "error",
              message:
                status === "success"
                  ? ""
                  : data.error || "Bundle finished with an error",
              files: files,
              report_url: "",
              reason: "",
            };
          } else if (status === "error") {
            /* No combined HTML — the deliverable failed; surface the engine's
               actionable error message. Not clickable (no url). */
            this.runStates["deliverable"] = {
              state: "error",
              message: data.error || "Report generation failed",
              files: [],
              report_url: "",
              reason: "",
            };
          } else if (status === "cancelled") {
            this.runStates["deliverable"] = {
              state: "skipped",
              message: skipNote("cancelled"),
              files: [],
              report_url: "",
              reason: "cancelled",
            };
          }
        }

        this.runStates = Object.assign({}, this.runStates);
        this.redrawEdges();
        var self = this;
        this.$nextTick(function () {
          relucide();
        });

        /* Suppress the live finish toast when this is a historical replay
           (re-opening a past run) — only a live finish toasts. */
        if (!this._replay) {
          if (status === "error") toast("Run finished with an error");
          else if (status === "cancelled") toast("Run cancelled");
        }
      },

      /* Force-resolve every work node still queued/running (or never seen).
         Gives compound-cancel parity: a cancelled compound emits NO per-child
         skipped events, so without this the trailing nodes strand. The single
         in-flight node on an error becomes "error"; everything else dangling
         becomes "skipped" (cancel) / "skipped" (error tail) / "done" (success). */
      _reconcile: function (status, data) {
        var self = this;
        this.nodes.forEach(function (n) {
          if (n.kind === "source") return;
          if (n.kind === "deliverable") return; // handled separately
          var rs = self.runStates[n.id];
          var st = rs ? rs.state : "queued";
          if (st === "done" || st === "error" || st === "skipped") return;
          var newState;
          var msg = "";
          var reason = "";
          if (status === "success") {
            newState = "done";
          } else if (status === "cancelled") {
            newState = "skipped";
            reason = "cancelled";
            msg = skipNote("cancelled");
          } else {
            /* error: the running node is the failure point; the rest were never
               reached → skipped (halt). */
            if (st === "running") {
              newState = "error";
              msg = (rs && rs.message) || data.error || "Step failed";
            } else {
              newState = "skipped";
              reason = "halted";
              msg = skipNote("halted");
            }
          }
          self.runStates[n.id] = {
            state: newState,
            message: msg,
            files: rs ? rs.files : [],
            report_url: rs ? rs.report_url : "",
            reason: reason,
          };
        });
      },

      _nodeById: function (id) {
        for (var i = 0; i < this.nodes.length; i++) {
          if (this.nodes[i].id === id) return this.nodes[i];
        }
        return null;
      },

      /* Nudge the running-node progress fill so a live node reads as active
         (the CSS .fill is 0% until set; done/error states set their own). */
      _refreshFill: function (id) {
        var rs = this.runStates[id];
        if (!rs) return;
        var el = document.getElementById("n-" + id);
        if (!el) return;
        var fill = el.querySelector(".fill");
        if (!fill) return;
        if (rs.state === "running") {
          if (!fill.style.width || fill.style.width === "0%") {
            fill.style.width = "62%";
          }
        }
      },

      /* ============================================================
       * Layout + edges (port + generalize from the mockup)
       * ============================================================ */

      /* Compute {id: [left, top]} for every node from the node count + stage
         box, size each node element, and apply the positions. CSS animates
         left/top so a refresh settles smoothly. */
      layout: function () {
        var self = this;
        var pos = {};
        var work = this.nodes.filter(function (n) {
          return n.kind !== "source";
        });

        if (this.kind === "compound") {
          /* Fan: source at left-center, children stacked in a middle column
             evenly distributed, the gold deliverable at right-center. */
          var children = work.filter(function (n) {
            return n.kind !== "deliverable";
          });
          var src = this._nodeById("source");
          if (src) pos["source"] = [40, (STAGE_H - sizeFor("source").h) / 2];

          var midX = (STAGE_W - sizeFor("recipe").w) / 2;
          var ch = sizeFor("recipe").h;
          var n = children.length;
          var gap = 18;
          var totalH = n * ch + (n - 1) * gap;
          var startY = Math.max(8, (STAGE_H - totalH) / 2);
          children.forEach(function (node, i) {
            pos[node.id] = [midX, startY + i * (ch + gap)];
          });

          var deliv = this._nodeById("deliverable");
          if (deliv) {
            pos["deliverable"] = [
              STAGE_W - sizeFor("deliverable").w - 40,
              (STAGE_H - sizeFor("deliverable").h) / 2,
            ];
          }
        } else {
          /* Serpentine (workflow / report): source far-left center, then the
             work nodes flowing left→right, wrapping to a new row on overflow.
             The mockup's fixed 2-row layout, generalized to N nodes / R rows. */
          var nodeW = sizeFor("recipe").w;
          var nodeH = sizeFor("recipe").h;
          var colGap = 100;
          var rowGap = 60;
          var pad = 20;

          /* Source occupies column 0 of row 0. The chain (source + work) wraps
             across rows; cols-per-row is driven by the stage width. */
          var stepX = nodeW + colGap;
          var cols = Math.max(2, Math.floor((STAGE_W - 2 * pad + colGap) / stepX));
          var chain = [this._nodeById("source")].concat(work).filter(Boolean);
          var rows = Math.ceil(chain.length / cols);
          var rowStepY = nodeH + rowGap;
          var blockH = rows * nodeH + (rows - 1) * rowGap;
          var topPad = Math.max(8, (STAGE_H - blockH) / 2);

          chain.forEach(function (node, idx) {
            var row = Math.floor(idx / cols);
            var col = idx % cols;
            /* Boustrophedon: even rows L→R, odd rows R→L, so the chain snakes
               back without a long return connector. */
            var visualCol = row % 2 === 0 ? col : cols - 1 - col;
            var x = pad + visualCol * stepX;
            var y = topPad + row * rowStepY;
            pos[node.id] = [x, y];
          });
        }

        this._pos = pos;

        /* Apply: size + position every node element. */
        this.nodes.forEach(function (node) {
          var el = document.getElementById("n-" + node.id);
          if (!el) return;
          var sz = sizeFor(node.kind);
          el.style.width = sz.w + "px";
          el.style.height = sz.h + "px";
          var p = pos[node.id];
          if (p) {
            el.style.left = p[0] + "px";
            el.style.top = p[1] + "px";
          }
          /* a11y: clickable nodes are focusable links; others are inert. */
          if (self._isClickable(node)) {
            el.setAttribute("tabindex", "0");
            el.setAttribute("role", "link");
          } else {
            el.removeAttribute("tabindex");
            el.removeAttribute("role");
          }
        });

        /* T4: scale the fixed 1120×600 stage to fit a narrow viewport so the
           far-right deliverable is never clipped / hidden behind a scroll. */
        this._fitStage();
      },

      /* T4: fit-to-viewport — scale the stage so every node (incl. the
         right-edge deliverable) is visible without horizontal scrolling on a
         narrow window. A CSS transform also shrinks the scroll footprint, so
         there's no scrollbar to empty space. Recomputed on resize (the listener
         is wired in init() and removed in destroy()). */
      _fitStage: function () {
        // getElementById("stage") — matches the template id + this file's other
        // node lookups; guarded for the minimal node-eval DOM stubs.
        var stage =
          typeof document.getElementById === "function" &&
          document.getElementById("stage");
        if (!stage) return;
        var vp = stage.parentElement; // .run-viewport
        if (!vp) return;
        var reset = function () {
          stage.style.transform = "";
          stage.style.transformOrigin = "";
          stage.style.marginRight = "";
          stage.style.marginBottom = "";
        };
        // 16px breathing room so the scaled stage clears the viewport edges + a
        // vertical scrollbar. Width-only fit: vertical scroll is acceptable; the
        // bug was the right-edge deliverable clipped HORIZONTALLY.
        var avail = (vp.clientWidth || 0) - 16;
        // Degenerate / hidden / transient-zero width: undo any prior scale so the
        // stage can never get stuck mirrored or scaled (M1-5).
        if (avail < 1) {
          reset();
          return;
        }
        var s = Math.min(1, avail / STAGE_W);
        if (s >= 1) {
          reset();
          return;
        }
        /* Scale from the top-left and COLLAPSE the layout footprint with negative
           margins: a CSS transform alone shrinks the visual but the element still
           reserves its full 1120×600 box, so the viewport would scroll to empty
           space and the right-edge deliverable would still be cut off. The
           negative right/bottom margins pull the reserved box down to the scaled
           size; margin-left:auto (from the .stage rule) then re-centers it. */
        stage.style.transformOrigin = "top left";
        stage.style.transform = "scale(" + s.toFixed(4) + ")";
        stage.style.marginRight = (-(1 - s) * STAGE_W).toFixed(1) + "px";
        stage.style.marginBottom = (-(1 - s) * STAGE_H).toFixed(1) + "px";
      },

      /* Edge geometry — read off the COMPUTED positions (not the mockup's fixed
         LAYOUT). cx/cy/L/R/edgePath mirror the mockup, parameterised by _pos. */
      _cx: function (id) {
        var p = this._pos[id];
        if (!p) return 0;
        return p[0] + sizeFor((this._nodeById(id) || {}).kind).w / 2;
      },
      _cy: function (id) {
        var p = this._pos[id];
        if (!p) return 0;
        return p[1] + sizeFor((this._nodeById(id) || {}).kind).h / 2;
      },
      _left: function (id) {
        var p = this._pos[id];
        return p ? p[0] : 0;
      },
      _right: function (id) {
        var p = this._pos[id];
        if (!p) return 0;
        return p[0] + sizeFor((this._nodeById(id) || {}).kind).w;
      },
      _top: function (id) {
        var p = this._pos[id];
        return p ? p[1] : 0;
      },
      _bottom: function (id) {
        var p = this._pos[id];
        if (!p) return 0;
        return p[1] + sizeFor((this._nodeById(id) || {}).kind).h;
      },

      edgePath: function (a, b) {
        /* Compound fan-in (T4): ALWAYS connect the facing edges in flow
           direction (source right-center → child left-center; child right-center
           → deliverable left-center) with a smooth horizontal-tangent curve,
           regardless of vertical offset.  The generic |Δy|≥60 vertical-drop
           branch below made the offset top/bottom children swing from the
           source's BOTTOM up to the child's TOP ("lines go to the top"); the
           nearest-edge routing reads as N parallel curves diverging from the
           source and re-converging into the deliverable (prototype-verified). */
        if (this.kind === "compound") {
          if (this._cx(b) >= this._cx(a)) {
            return path(this._right(a), this._cy(a), this._left(b), this._cy(b), false);
          }
          return path(this._left(a), this._cy(a), this._right(b), this._cy(b), false);
        }
        var ay = this._cy(a);
        var by = this._cy(b);
        if (Math.abs(ay - by) < 60) {
          /* horizontal — connect the facing edges in flow direction */
          if (this._cx(b) > this._cx(a)) {
            return path(this._right(a), ay, this._left(b), by, false);
          }
          return path(this._left(a), ay, this._right(b), by, false);
        }
        /* vertical drop — bottom of a to top of b (serpentine row-wrap) */
        return path(this._cx(a), this._bottom(a), this._cx(b), this._top(b), true);
      },

      /* The edge model per kind, using the REAL node ids from __RUN.
           compound  → source→child for every child, then child→deliverable.
           serpentine → the linear chain source→n1→…→nN. */
      edgeList: function () {
        var work = this.nodes.filter(function (n) {
          return n.kind !== "source";
        });
        var edges = [];
        if (this.kind === "compound") {
          var children = work.filter(function (n) {
            return n.kind !== "deliverable";
          });
          var deliv = this._nodeById("deliverable");
          children.forEach(function (c) {
            edges.push(["source", c.id]);
          });
          if (deliv) {
            children.forEach(function (c) {
              edges.push([c.id, "deliverable"]);
            });
          }
          return edges;
        }
        var chain = [this._nodeById("source")].concat(work).filter(Boolean);
        for (var i = 0; i < chain.length - 1; i++) {
          edges.push([chain[i].id, chain[i + 1].id]);
        }
        return edges;
      },

      /* Draw all edges faint into #e-dorm (the dormant skeleton). */
      buildDorm: function () {
        var g = document.getElementById("e-dorm");
        if (!g) return;
        g.innerHTML = "";
        var self = this;
        this.edgeList().forEach(function (pair) {
          var p = document.createElementNS(SVG_NS, "path");
          p.setAttribute("d", self.edgePath(pair[0], pair[1]));
          g.appendChild(p);
        });
      },

      /* Rebuild #e-done (both endpoints resolved → teal→violet gradient) and
         #e-live (target running → animated cyan dash; compound child→deliverable
         goes gold when the deliverable is running). Clears each group first. */
      redrawEdges: function () {
        var eDone = document.getElementById("e-done");
        var eLive = document.getElementById("e-live");
        if (!eDone || !eLive) return;
        eDone.innerHTML = "";
        eLive.innerHTML = "";
        var self = this;

        var stateOf = function (id) {
          if (id === "source") return "done"; // source is always satisfied
          var rs = self.runStates[id];
          return rs ? rs.state : "queued";
        };

        this.edgeList().forEach(function (pair) {
          var a = pair[0];
          var b = pair[1];
          var sa = stateOf(a);
          var sb = stateOf(b);
          var d = self.edgePath(a, b);

          if (sa === "done" && sb === "done") {
            var pd = document.createElementNS(SVG_NS, "path");
            pd.setAttribute("d", d);
            eDone.appendChild(pd);
          } else if (sb === "running") {
            var pl = document.createElementNS(SVG_NS, "path");
            pl.setAttribute("d", d);
            /* Compound: a running deliverable lights its incoming edges gold. */
            if (b === "deliverable") {
              pl.style.stroke = "var(--rc-gold)";
              pl.style.filter =
                "drop-shadow(0 0 3px var(--rc-gold)) drop-shadow(0 0 12px rgba(251,191,36,1)) drop-shadow(0 0 30px rgba(251,191,36,.6))";
            }
            eLive.appendChild(pl);
          }
        });
      },

      /* ============================================================
       * Template helpers (nodeClass / nodeBadge / nodeMsg / onNodeClick)
       * ============================================================ */
      nodeClass: function (id) {
        // The source is the run's origin — always settled, never a queued
        // (dimmed) node. Render it neutral (no state class), matching the edge
        // logic which treats source as "done".
        if (id === "source") return "";
        var rs = this.runStates[id];
        return "s-" + (rs ? rs.state : "queued");
      },

      nodeBadge: function (id) {
        // The source is a neutral origin node, not a queued work node.
        if (id === "source") return "";
        var rs = this.runStates[id];
        var st = rs ? rs.state : "queued";
        /* done hides the badge (the check renders instead — matches the CSS
           `.s-done .nbadge { display: none }` + builder-page.js). */
        if (st === "done") return "";
        if (st === "running") return "running";
        if (st === "error") return "error";
        if (st === "skipped") return "skipped";
        return "queued";
      },

      nodeMsg: function (id) {
        var rs = this.runStates[id];
        if (!rs) return "";
        if (rs.state === "skipped") return skipNote(rs.reason, rs.message);
        return rs.message || "";
      },

      /* Decide clickability by node kind + run kind (spec §2.4 / §4.4). */
      _isClickable: function (node) {
        if (!node) return false;
        if (node.kind === "deliverable") return true; // compound combined report
        if (node.kind === "source") return false;
        if (node.kind === "mcp_tool") return false;
        /* A workflow step opens its own report when done. A compound child is a
           section of one file — not independently clickable. */
        if (this.kind === "workflow" && node.kind === "recipe") return true;
        return false;
      },

      onNodeClick: function (id) {
        var node = this._nodeById(id);
        if (!node) return;
        if (node.kind === "deliverable") {
          if (this._deliverableUrl) window.open(this._deliverableUrl, "_blank");
          return;
        }
        if (this.kind === "workflow" && node.kind === "recipe") {
          var rs = this.runStates[id];
          if (rs && rs.state === "done" && rs.report_url) {
            window.open(rs.report_url, "_blank");
          }
          return;
        }
        /* source + compound child → no-op. */
      },

      /* ============================================================
       * Transport — Stop / Replay
       * ============================================================ */
      stop: function () {
        if (!this.canStop) return;
        var self = this;
        /* #13: IMMEDIATE feedback — flip the state word + disable Stop the
           moment it's pressed, independent of where the engine is parked. The
           engine's own delays (batch cooldown etc.) now cancel at the next
           ~0.5s chunk, but an in-flight network/LLM step must finish first — so
           set THAT expectation rather than promise an instant stop. */
        this.canStop = false;
        this.runState = "cancelling…";
        toast("Cancelling — the current step must finish first…");
        apiPOST("/api/run/" + encodeURIComponent(this.runId) + "/cancel").then(
          function (res) {
            if (!res.ok) {
              toast((res.data && res.data.error) || "Couldn't stop the run");
              /* Cancel POST failed — restore so the user can retry. */
              self.canStop = !self._terminal;
              self.runState = "running";
            }
            /* On success the server sets cancel_event + emits a terminal
               `done`; onDoneEvent's reconciliation settles to "cancelled". */
          }
        );
      },

      replay: function () {
        if (!this.canReplay) return;
        var blob = window.__RUN && window.__RUN.replay;
        if (!blob) return;
        this.submitReplay(blob);
      },

      /* A replay ALWAYS produces a NEW run_id and NAVIGATES — it never mutates
         the viewed run. */
      submitReplay: function (replay) {
        if (replay.encoding === "form") {
          /* report / compound — re-POST the FORM endpoint via the shared helper,
             which TRANSPARENTLY satisfies the autotriage needs_confirm gate
             (the destructive-confirm flow, spec §8). DON'T re-implement it. */
          var params = new URLSearchParams();
          var fields = replay.fields || {};
          Object.keys(fields).forEach(function (k) {
            var v = fields[k];
            if (v === null || v === undefined) return;
            if (typeof v === "boolean") {
              params.set(k, v ? "true" : "false");
            } else {
              params.set(k, String(v));
            }
          });
          window
            .__sp2PostRun(params, window.NONCE, {
              onError: function (body) {
                toast("Replay failed: " + ((body && body.error) || "error"));
              },
            })
            .then(function (body) {
              if (!body) return; /* error or user-cancelled confirm — handled */
              if (body.run_id) {
                location.href = "/run/" + body.run_id;
              }
            })
            .catch(function (err) {
              toast("Replay failed: " + ((err && err.message) || "Network error"));
            });
          return;
        }

        if (replay.encoding === "json") {
          /* workflow — re-POST /api/workflows/run with the saved slug or the
             normalized model (spec §8). A workflow replay is non-destructive
             so it submits directly. */
          fetch(replay.endpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-FS-Session": window.NONCE,
            },
            body: JSON.stringify(replay.body || {}),
          })
            .then(function (r) {
              return r
                .json()
                .catch(function () {
                  return {};
                })
                .then(function (data) {
                  return { ok: r.ok, data: data };
                });
            })
            .then(function (res) {
              if (res.ok && res.data && res.data.run_id) {
                location.href = "/run/" + res.data.run_id;
              } else {
                toast(
                  "Replay failed: " +
                    ((res.data && res.data.error) || "Couldn't start the run")
                );
              }
            })
            .catch(function (err) {
              toast("Replay failed: " + ((err && err.message) || "Network error"));
            });
          return;
        }

        toast("Replay unavailable for this run");
      },
    };
  }

  /* Register on alpine:init so load order with the deferred alpine.min.js is
     safe (same pattern as builder-page.js). */
  document.addEventListener("alpine:init", function () {
    if (window.Alpine && typeof window.Alpine.data === "function") {
      window.Alpine.data("runCanvas", runCanvas);
    }
  });
})();
