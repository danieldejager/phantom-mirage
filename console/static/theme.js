/* Light / dark theme toggle. Loaded from <head> as a same-origin file
   (CSP script-src 'self', no inline script) so a saved choice is applied to
   <html data-theme> before first paint. With no saved choice the attribute
   is absent and the CSS follows prefers-color-scheme; the toggle then flips
   the mode currently shown and stores an explicit "light" or "dark" under
   pm_theme in localStorage only (nothing sent to the server). */
(function () {
  "use strict";
  var KEY = "pm_theme", root = document.documentElement, mem = "";
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
  function stored() { try { var v = localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : mem; } catch (e) { return mem; } }
  function current() { return stored() || (mq && mq.matches ? "light" : "dark"); }
  function apply() {
    var s = stored(), cur = current();
    if (s) root.setAttribute("data-theme", s); else root.removeAttribute("data-theme");
    var bs = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < bs.length; i++) {
      var b = bs[i], dark = cur === "dark";
      /* a menu item (profile menu) reports its state as checked, a button as pressed */
      b.setAttribute(b.getAttribute("role") === "menuitemcheckbox" ? "aria-checked" : "aria-pressed", dark ? "true" : "false");
      b.setAttribute("aria-label", "Dark theme");
      b.setAttribute("title", dark ? "Dark theme on: switch to light" : "Light theme on: switch to dark");
      var ic = b.querySelector(".ti"), lb = b.querySelector(".tl");
      if (ic) ic.textContent = dark ? "\u263E" : "\u2600";
      if (lb) lb.textContent = dark ? "Dark" : "Light";
    }
  }
  function toggle() {
    mem = current() === "dark" ? "light" : "dark";   /* also used if storage is blocked */
    try { localStorage.setItem(KEY, mem); } catch (e) { /* ignore */ }
    apply();
  }
  apply();
  document.addEventListener("DOMContentLoaded", function () {
    apply();
    document.addEventListener("click", function (ev) {
      var b = ev.target.closest && ev.target.closest("[data-theme-toggle]");
      if (b) toggle();
    });
  });
  if (mq && mq.addEventListener) mq.addEventListener("change", function () { if (!stored()) apply(); });
  window.addEventListener("storage", function (ev) { if (ev.key === KEY) apply(); });
})();
