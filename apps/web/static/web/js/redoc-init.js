// Initialise Redoc from data attributes (no inline script, so the page runs
// under script-src 'self'). The theme is read from the same CSS custom
// properties as the landing page, and rebuilt when the OS theme changes.
(() => {
  "use strict";
  const container = document.getElementById("redoc-container");
  if (!container || !window.Redoc) return;
  const query = window.matchMedia("(prefers-color-scheme: dark)");

  const token = (name) =>
    getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  const theme = () => {
    const dark = query.matches;
    const sans = token("--font-sans");
    const mono = token("--font-mono");
    const accent = token("--accent-ink");
    const ink = token("--ink");
    const ink2 = token("--ink-2");
    const danger = token("--danger");
    return {
      spacing: { unit: 5, sectionHorizontal: 40, sectionVertical: 36 },
      colors: {
        tonalOffset: 0.2,
        primary: { main: accent },
        success: { main: accent },
        error: { main: danger },
        text: { primary: ink, secondary: ink2 },
        border: { dark: token("--hairline-strong"), light: token("--hairline") },
        responses: {
          success: { color: accent, backgroundColor: token("--accent-soft") },
          error: { color: danger, backgroundColor: token("--danger-soft") },
          redirect: { color: ink2, backgroundColor: token("--bg-sunk") },
          info: { color: ink2, backgroundColor: token("--bg-sunk") },
        },
        // Redoc draws method labels as white text on these colours, so they
        // are fixed mid-tones that keep 4.5:1 in both themes.
        http: {
          get: "#0f766e",
          post: "#4a5563",
          put: "#4a5563",
          patch: "#4a5563",
          options: "#4a5563",
          head: "#4a5563",
          link: "#4a5563",
          basic: "#4a5563",
          delete: "#b4231a",
        },
      },
      schema: {
        linesColor: token("--hairline-strong"),
        typeNameColor: ink2,
        typeTitleColor: ink,
        requireLabelColor: danger,
        nestedBackground: token("--bg-alt"),
        arrow: { color: ink2 },
      },
      typography: {
        fontSize: "15px",
        lineHeight: "1.5em",
        fontWeightRegular: "400",
        fontWeightBold: "600",
        fontWeightLight: "400",
        fontFamily: sans,
        smoothing: "antialiased",
        headings: { fontFamily: sans, fontWeight: "600", lineHeight: "1.2em" },
        code: {
          fontSize: "13px",
          fontFamily: mono,
          color: ink,
          backgroundColor: token("--bg-sunk"),
          wrap: true,
        },
        links: { color: accent, visited: accent, hover: token("--accent-hover") },
      },
      sidebar: {
        width: "280px",
        backgroundColor: token("--bg-alt"),
        textColor: ink,
        activeTextColor: accent,
        groupItems: { activeBackgroundColor: token("--bg-sunk"), activeTextColor: accent, textTransform: "none" },
        level1Items: { activeBackgroundColor: token("--bg-sunk"), activeTextColor: accent, textTransform: "none" },
        arrow: { color: ink2 },
      },
      rightPanel: {
        backgroundColor: dark ? "#05080b" : "#0b0f14",
        textColor: "#e7ebef",
        servers: { overlay: { backgroundColor: "#151b22", textColor: "#e7ebef" }, url: { backgroundColor: "#0b0f14" } },
      },
      codeBlock: { backgroundColor: dark ? "#10151b" : "#151b22" },
      fab: { backgroundColor: token("--accent"), color: token("--on-accent") },
    };
  };

  const render = () =>
    window.Redoc.init(
      container.dataset.specUrl,
      {
        theme: theme(),
        nonce: container.dataset.nonce,
        scrollYOffset: ".docs-bar",
        expandResponses: "200,201",
        pathInMiddlePanel: true,
        hideLoading: true,
        sortTagsAlphabetically: false,
      },
      container,
    );

  render();
  query.addEventListener("change", render);
})();
