(function () {
  "use strict";

  const root = document.documentElement;
  const events = Array.from(document.querySelectorAll("[data-history-event]"));
  const panels = Array.from(document.querySelectorAll("[data-inspector-panel]"));
  if (events.length === 0 || panels.length === 0) return;
  const fallback = events.find((event) => event.getAttribute("aria-selected") === "true") || events[0];

  function select(panelID, moveFocus, historyMode) {
    const selected = events.find((event) => event.dataset.panel === panelID);
    if (!selected) return false;

    const selectedPath = selected.dataset.path;
    events.forEach((event) => {
      const active = event === selected;
      event.setAttribute("aria-selected", String(active));
      event.tabIndex = active ? 0 : -1;
      event.classList.toggle("is-selected", active);
      event.classList.toggle("is-path", event.dataset.path === selectedPath);
    });
    panels.forEach((panel) => {
      panel.hidden = panel.id !== "panel-" + panelID;
    });

    if (historyMode && window.location.hash !== "#" + panelID) {
      const fragment = "#" + encodeURIComponent(panelID);
      if (historyMode === "push") {
        window.history.pushState(null, "", fragment);
      } else {
        window.history.replaceState(null, "", fragment);
      }
    }
    if (moveFocus) selected.focus();
    return true;
  }

  function move(offset) {
    const current = events.findIndex((event) => event.getAttribute("aria-selected") === "true");
    const target = Math.max(0, Math.min(events.length - 1, current + offset));
    select(events[target].dataset.panel, true, "push");
  }

  function fragmentID() {
    try {
      return decodeURIComponent(window.location.hash.slice(1));
    } catch (_) {
      return "";
    }
  }

  events.forEach((event) => {
    event.addEventListener("click", () => select(event.dataset.panel, false, "push"));
  });

  document.addEventListener("click", (click) => {
    if (!(click.target instanceof Element)) return;
    const control = click.target.closest("[data-select-panel]");
    if (control) select(control.dataset.selectPanel, true, "push");
  });

  document.addEventListener("keydown", (key) => {
    if (key.altKey || key.ctrlKey || key.metaKey || key.shiftKey) return;
    if (key.key === "ArrowLeft") {
      key.preventDefault();
      move(-1);
    } else if (key.key === "ArrowRight") {
      key.preventDefault();
      move(1);
    }
  });

  function restoreFragment() {
    if (!select(fragmentID(), false, false)) {
      select(fallback.dataset.panel, false, "replace");
    }
  }

  window.addEventListener("hashchange", restoreFragment);
  window.addEventListener("popstate", restoreFragment);

  root.classList.add("interaction-ready");
  const requested = fragmentID();
  if (!select(requested, false, false)) select(fallback.dataset.panel, false, "replace");
}());
