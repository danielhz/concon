/*
 * concon discussion notes — add, edit and delete without reloading the page
 * (issue #9).
 *
 * Progressive enhancement of the note forms on resource views
 * (templates/entity.html, templates/entity_note.html). Without this script
 * the forms are plain POSTs answered with a redirect; with it, a form marked
 * `data-note-form` is sent in the background with `X-Concon-Fragment: note`,
 * and the server answers with the note rendered exactly as the page renders
 * it (add, edit) or 204 (delete). The page is patched in place, so the scroll
 * position is kept and the typed text survives an error, which is shown next
 * to the form with the server's status text (size limit, expired session) or
 * a connection message.
 *
 * The browser never renders Markdown or builds note HTML itself: the only
 * thing inserted is the server's fragment, parsed with DOMParser (inert, no
 * script execution). Same-origin, vanilla DOM + fetch, no dependencies.
 */
(function () {
  "use strict";

  if (
    !window.fetch ||
    !window.FormData ||
    !window.URLSearchParams ||
    !window.DOMParser ||
    !Element.prototype.closest ||
    !Element.prototype.replaceWith
  ) {
    return; // the forms keep working as plain POSTs
  }

  var FRAGMENT_HEADER = "X-Concon-Fragment";

  function submitButton(form) {
    return form.querySelector("button[type=submit]");
  }

  function clearError(form) {
    var box = form.querySelector(".annotate-error");
    if (box) box.parentNode.removeChild(box);
  }

  // One `<p class="annotate-error" role="alert">` per form, placed just above
  // its buttons. `text` is shown as text; `loginLink` adds a link to /_login.
  function showError(form, text, loginLink) {
    clearError(form);
    var box = document.createElement("p");
    box.className = "annotate-error";
    box.setAttribute("role", "alert");
    box.appendChild(document.createTextNode(text));
    if (loginLink) {
      box.appendChild(document.createTextNode(" "));
      var a = document.createElement("a");
      a.href = "/_login";
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = "Log in";
      box.appendChild(a);
      box.appendChild(document.createTextNode(" in a new tab, then try again."));
    }
    var button = submitButton(form);
    var anchor = button && button.parentNode !== form ? button.parentNode : button;
    form.insertBefore(box, anchor);
    var field = form.querySelector("textarea");
    if (field) field.focus();
  }

  // The server answers note errors with a short plain-text reason; anything
  // else (an HTML error page, an empty body) gets a generic message.
  function messageFor(status, text) {
    var reason = text && text.length < 400 && text.charAt(0) !== "<" ? text.trim() : "";
    if (status === 401) {
      return reason || "Your session has expired.";
    }
    return reason || "The server answered with status " + status + ".";
  }

  // Parse the server's fragment into a detached `<li class="annotation">`,
  // or null when the reply is not one (then the page is left untouched).
  function parseNote(html) {
    var doc = new DOMParser().parseFromString(html, "text/html");
    var li = doc.body.firstElementChild;
    if (!li || li.tagName !== "LI" || !li.classList.contains("annotation")) return null;
    return document.importNode(li, true);
  }

  // Keep "Discussion (N)", the list and the "No notes yet." line in step.
  function updateCount() {
    var list = document.querySelector("ul.annotations");
    var n = list ? list.querySelectorAll("li.annotation").length : 0;
    var count = document.querySelector(".annotation-count");
    if (count) count.textContent = String(n);
    var empty = document.querySelector(".annotations-empty");
    if (empty) empty.hidden = n > 0;
    if (list) list.hidden = n === 0;
  }

  function submitNote(form) {
    var kind = form.getAttribute("data-note-form"); // add | edit | delete
    var button = submitButton(form);
    var headers = {
      "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
    };
    headers[FRAGMENT_HEADER] = "note";
    clearError(form);
    if (button) button.disabled = true;

    fetch(form.action, {
      method: "POST",
      credentials: "same-origin",
      redirect: "manual",
      headers: headers,
      body: new URLSearchParams(new FormData(form)).toString()
    })
      .then(function (r) {
        if (r.type === "opaqueredirect") {
          return { status: 0, ok: false, text: "", html: false };
        }
        var isHtml = (r.headers.get("Content-Type") || "").indexOf("text/html") === 0;
        return r.text().then(function (text) {
          return { status: r.status, ok: r.ok, text: text, html: isHtml };
        });
      })
      .then(function (res) {
        if (res.status === 0) {
          showError(form, "Unexpected reply from the server. Reload the page and try again.");
          return;
        }
        if (!res.ok) {
          showError(form, messageFor(res.status, res.text), res.status === 401);
          return;
        }
        if (kind === "delete") {
          var gone = form.closest("li.annotation");
          if (gone) gone.parentNode.removeChild(gone);
          updateCount();
          return;
        }
        var note = res.html ? parseNote(res.text) : null;
        if (!note) {
          showError(form, "Unexpected reply from the server. Reload the page to see the current notes.");
          return;
        }
        if (kind === "edit") {
          var old = form.closest("li.annotation");
          if (!old) {
            showError(form, "Saved, but the page could not be updated. Reload it.");
            return;
          }
          old.replaceWith(note);
        } else {
          var list = document.querySelector("ul.annotations");
          if (!list) {
            showError(form, "Saved, but the page could not be updated. Reload it.");
            return;
          }
          list.appendChild(note);
          var field = form.querySelector("textarea");
          if (field) field.value = "";
        }
        updateCount();
      })
      .catch(function () {
        showError(
          form,
          "Could not reach the server. Check your connection and try again; your text is still here."
        );
      })
      .then(function () {
        if (button) button.disabled = false;
      });
  }

  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!form || !form.hasAttribute || !form.hasAttribute("data-note-form")) return;
    e.preventDefault();
    submitNote(form);
  });
})();
