/* SP3 file uploads — wires `.fs-upload` controls to POST /api/uploads.
 *
 * Each control:
 *   <div class="fs-upload" data-kind="scoring|context|recs" data-target="<hidden id>">
 *     <input type="file" class="fs-upload-input" accept=".yaml,.yml">
 *     <span class="fs-upload-name">…current name…</span>
 *   </div>
 *
 * On a successful upload it sets the hidden field (data-target) to the stored
 * path, shows the filename (+ a ⚠ with warnings as a tooltip), and dispatches a
 * bubbling `fs-upload-done` CustomEvent ({kind, path, name, warnings}) so Alpine
 * surfaces (the Builder) can mirror it into their model. Dynamically-injected
 * surfaces (card-back, prerun modal) call window.__fsWireUploads(root) after
 * inject; static pages are wired on DOMContentLoaded.
 */
(function () {
  function _nonce() {
    var m = document.querySelector('meta[name="fs-csrf"]');
    return m ? m.content : '';
  }

  /* Resolve the hidden target field SCOPED to the control's own form/container
   * (not document.getElementById) so coexisting fragments with the same fixed
   * id — e.g. two card backs mid-flip — never cross-write each other's path. */
  function _target(box) {
    var id = box.getAttribute('data-target') || '';
    if (!id) return null;
    var scope = box.closest('form, .wf-cfg, #cfg-modal, #settings-form') || document;
    return scope.querySelector('#' + (window.CSS && CSS.escape ? CSS.escape(id) : id));
  }

  function _wireOne(box) {
    var input = box.querySelector('.fs-upload-input');
    if (!input || input.__fsWired) return;
    input.__fsWired = true;

    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      if (!file) return;
      var kind = box.getAttribute('data-kind') || 'scoring';
      var hidden = _target(box);
      var nameEl = box.querySelector('.fs-upload-name');

      var fd = new FormData();
      fd.append('file', file);
      fd.append('kind', kind);
      if (nameEl) nameEl.textContent = 'Uploading…';

      fetch('/api/uploads', {
        method: 'POST',
        headers: { 'X-FS-Session': _nonce() },
        body: fd,
      })
        .then(function (r) {
          return r.json().then(function (b) {
            return { ok: r.ok, b: b };
          });
        })
        .then(function (res) {
          if (!res.ok) {
            if (nameEl) nameEl.textContent = 'Error: ' + (res.b.error || 'upload failed');
            input.value = '';
            return;
          }
          var warnings = res.b.warnings || [];
          if (hidden) hidden.value = res.b.path;
          if (nameEl) {
            nameEl.textContent = res.b.name + (warnings.length ? ' ⚠' : '');
            nameEl.title = warnings.length ? warnings.join('\n') : '';
          }
          box.dispatchEvent(
            new CustomEvent('fs-upload-done', {
              bubbles: true,
              detail: { kind: kind, path: res.b.path, name: res.b.name, warnings: warnings },
            })
          );
        })
        .catch(function () {
          if (nameEl) nameEl.textContent = 'Error: network';
          input.value = '';
        });
    });

    // A "clear" affordance (optional) resets the hidden field + name.
    var clearBtn = box.querySelector('.fs-upload-clear');
    if (clearBtn && !clearBtn.__fsWired) {
      clearBtn.__fsWired = true;
      clearBtn.addEventListener('click', function () {
        var hidden = _target(box);
        var nameEl = box.querySelector('.fs-upload-name');
        if (hidden) hidden.value = '';
        if (input) input.value = '';
        if (nameEl) {
          nameEl.textContent = 'none';
          nameEl.title = '';
        }
        box.dispatchEvent(
          new CustomEvent('fs-upload-done', {
            bubbles: true,
            detail: { kind: box.getAttribute('data-kind'), path: '', name: '', warnings: [] },
          })
        );
      });
    }
  }

  function wire(root) {
    (root || document).querySelectorAll('.fs-upload').forEach(_wireOne);
  }

  window.__fsWireUploads = wire;
  document.addEventListener('DOMContentLoaded', function () {
    wire(document);
  });
})();
