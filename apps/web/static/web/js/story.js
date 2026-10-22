// Fallback for the isolation story on browsers without CSS scroll timelines.
// site.css builds the figure natively where `animation-timeline: view()` and
// `timeline-scope` exist; there this file does nothing. Elsewhere it computes the
// same per-step progress (--p1 to --p4) from the step markers, and only then adds
// `js-scrub`, the class that lets site.css hide what has not been reached yet.
// Without this file, or with reduced motion, the figure is simply complete.
(() => {
  "use strict";

  const story = document.querySelector("[data-story]");
  if (!story || !("IntersectionObserver" in window) || !window.requestAnimationFrame) return;
  const supports = (css) => Boolean(window.CSS && CSS.supports && CSS.supports(css));
  if (supports("animation-timeline: view()") && supports("timeline-scope: --a")) return;

  // The same window as the native timelines: a step builds while its marker
  // moves from 85% to 50% of the viewport height (cover 15% to 50%).
  const START = 0.15;
  const SPAN = 0.35;
  const marks = [...story.querySelectorAll(".story-mark")];
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  let frame = 0;
  let listening = false;

  const update = () => {
    frame = 0;
    const height = window.innerHeight || 1;
    marks.forEach((mark, index) => {
      const cover = 1 - mark.getBoundingClientRect().top / height;
      const progress = Math.min(1, Math.max(0, (cover - START) / SPAN));
      // A custom property through the CSSOM, which a strict CSP allows.
      story.style.setProperty(`--p${index + 1}`, progress.toFixed(4));
    });
  };
  const schedule = () => {
    if (!frame) frame = requestAnimationFrame(update);
  };
  const listen = (on) => {
    if (on === listening) return;
    listening = on;
    const method = on ? "addEventListener" : "removeEventListener";
    window[method]("scroll", schedule, { passive: true });
    window[method]("resize", schedule, { passive: true });
  };

  // Only follow the scroll while the story is on screen.
  const observer = new IntersectionObserver((entries) => {
    const visible = entries.some((entry) => entry.isIntersecting);
    if (visible) update();
    listen(visible);
  });

  const apply = () => {
    if (reduce.matches) {
      observer.disconnect();
      listen(false);
      story.classList.remove("js-scrub");
      return;
    }
    update();
    story.classList.add("js-scrub");
    observer.observe(story);
  };
  apply();
  if (reduce.addEventListener) reduce.addEventListener("change", apply);
})();
