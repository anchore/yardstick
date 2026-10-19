// theme.js runs before the page renders (it isn't deferred) so an explicit theme doesn't flash.
// "system" leaves data-theme unset, so the stylesheet follows prefers-color-scheme.
"use strict";
(() => {
  const t = localStorage.getItem("yardstick.theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
})();
