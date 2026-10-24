// live reload for a dev build (make dev): the server adds this to every page and sends an event on
// /dev/reload after each rebuild. A CSS-only change swaps the stylesheet, anything else reloads.
(() => {
  let opened = false;
  const events = new EventSource("/dev/reload");

  // a reconnect means the server restarted, with new assets and a new token
  events.onopen = () => {
    if (opened) location.reload();
    opened = true;
  };

  events.onmessage = (e) => {
    const { changed, errors } = JSON.parse(e.data);
    showErrors(errors);
    if (errors.length || !changed.length) return;
    if (!changed.every((path) => path.endsWith(".css"))) {
      location.reload();
      return;
    }
    for (const link of document.querySelectorAll('link[rel="stylesheet"]')) {
      const url = new URL(link.href);
      if (changed.includes(url.pathname)) {
        url.searchParams.set("t", Date.now());
        link.href = url.href;
      }
    }
  };

  function showErrors(errors) {
    document.getElementById("dev-errors")?.remove();
    if (!errors.length) return;
    console.error("build failed:\n" + errors.join("\n"));
    const pre = document.createElement("pre");
    pre.id = "dev-errors";
    pre.textContent = "build failed\n\n" + errors.join("\n");
    // the CSP has no inline styles, but setting them from script is allowed
    Object.assign(pre.style, {
      position: "fixed", left: "0", right: "0", bottom: "0", zIndex: "99999", margin: "0", padding: "12px",
      maxHeight: "40vh", overflow: "auto", background: "#300", color: "#fcc", font: "12px monospace",
    });
    (document.body ?? document.documentElement).append(pre);
  }
})();
