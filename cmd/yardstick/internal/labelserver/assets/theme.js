// theme.js runs before the page renders (it isn't deferred) so an explicit theme doesn't flash.
// "system" leaves data-theme unset, so the stylesheet follows prefers-color-scheme. It also keeps
// the dark class Basecoat themes by on <html>: set from data-theme when there is one, else from the
// OS, and kept in step when either changes.
"use strict";
(() => {
  const root = document.documentElement;
  let t = null;
  try { t = localStorage.getItem("yardstick.theme"); } catch (_) { /* no storage: follow the OS */ }
  if (t === "light" || t === "dark") root.dataset.theme = t;
  const os = matchMedia("(prefers-color-scheme: dark)");
  const sync = () => root.classList.toggle("dark", root.dataset.theme ? root.dataset.theme === "dark" : os.matches);
  sync();
  os.addEventListener("change", sync);
  new MutationObserver(sync).observe(root, { attributes: true, attributeFilter: ["data-theme"] });
})();
