/* Light / Dark / Auto theme switch. Loaded from <head> as a same-origin file
   (CSP script-src 'self', no inline script) so the saved choice is applied to
   <html data-theme> before first paint. Auto (default) removes the attribute
   and the CSS follows prefers-color-scheme. Stored in localStorage only. */
(function () {
  "use strict";
  var KEY = "pm_theme", root = document.documentElement;
  function get() { try { var v = localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : "auto"; } catch (e) { return "auto"; } }
  function apply(v) {
    if (v === "light" || v === "dark") root.setAttribute("data-theme", v); else root.removeAttribute("data-theme");
    var bs = document.querySelectorAll("[data-theme-pick]");
    for (var i = 0; i < bs.length; i++) bs[i].setAttribute("aria-checked", bs[i].getAttribute("data-theme-pick") === v ? "true" : "false");
  }
  function set(v) { try { if (v === "auto") localStorage.removeItem(KEY); else localStorage.setItem(KEY, v); } catch (e) { /* ignore */ } apply(v); }
  apply(get());
  document.addEventListener("DOMContentLoaded", function () {
    apply(get());
    document.addEventListener("click", function (ev) {
      var b = ev.target.closest && ev.target.closest("[data-theme-pick]");
      if (b) set(b.getAttribute("data-theme-pick"));
    });
  });
  window.addEventListener("storage", function (ev) { if (ev.key === KEY) apply(get()); });
})();
