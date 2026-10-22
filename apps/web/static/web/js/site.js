// Progressive enhancement for the landing page. Everything works without it:
// the server renders the status line, and the local nav is plain anchors.
(() => {
  "use strict";

  // Mark the section in view in the sticky local nav.
  const links = [...document.querySelectorAll(".lnav-links a[href^='#']")];
  const sections = links
    .map((link) => document.getElementById(link.hash.slice(1)))
    .filter(Boolean);
  if ("IntersectionObserver" in window && sections.length) {
    const visible = new Set();
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) visible.add(entry.target.id);
          else visible.delete(entry.target.id);
        }
        const current = sections.find((section) => visible.has(section.id));
        for (const link of links) {
          if (current && link.hash === `#${current.id}`) link.setAttribute("aria-current", "true");
          else link.removeAttribute("aria-current");
        }
      },
      { rootMargin: "-45% 0px -50% 0px" },
    );
    sections.forEach((section) => observer.observe(section));
  }

  // Let the translucent local nav turn dark while it floats over a dark section.
  const lnav = document.querySelector(".lnav");
  const darkSections = [...document.querySelectorAll("section.inverse")];
  if (lnav && darkSections.length && "IntersectionObserver" in window) {
    const under = new Set();
    const toneObserver = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) under.add(entry.target);
          else under.delete(entry.target);
        }
        if (under.size) lnav.dataset.tone = "dark";
        else delete lnav.dataset.tone;
      },
      { rootMargin: `0px 0px -${Math.max(0, window.innerHeight - 52)}px 0px` },
    );
    darkSections.forEach((section) => toneObserver.observe(section));
  }

  // Re-check readiness every 30 seconds while the page is visible, using the
  // same public probe a load balancer would call.
  const status = document.querySelector("[data-status]");
  if (!status || !window.fetch) return;
  const label = status.querySelector("[data-status-label]");
  const checked = status.querySelector("[data-checked]");
  const dot = status.querySelector(".status-dot");
  const pad = (n) => String(n).padStart(2, "0");

  const render = (ready, checks) => {
    status.dataset.ready = String(ready);
    label.textContent = ready ? "This server is ready" : "This server is degraded";
    for (const [name, result] of Object.entries(checks)) {
      const node = status.querySelector(`[data-check="${name}"]`);
      if (node) node.textContent = result;
    }
    const now = new Date();
    checked.dateTime = now.toISOString();
    checked.textContent = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())} UTC`;
    // Restart the (finite) pulse so each fresh check is visible.
    dot.classList.remove("is-fresh");
    void dot.offsetWidth;
    dot.classList.add("is-fresh");
  };

  const refresh = async () => {
    if (document.visibilityState !== "visible") return;
    try {
      const response = await fetch(status.dataset.url || "/health/ready/", {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      const body = await response.json();
      render(response.ok && body.status === "ok", body.checks || {});
    } catch {
      render(false, { database: "unreachable", cache: "unreachable" });
    }
  };

  setInterval(refresh, 30_000);
  document.addEventListener("visibilitychange", refresh);
})();
