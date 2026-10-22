// Follow the OS colour scheme in Swagger UI, which ships its own dark theme
// behind `html.dark-mode`. Loaded in <head> so the first paint is correct.
(() => {
  "use strict";
  const query = window.matchMedia("(prefers-color-scheme: dark)");
  const apply = () => document.documentElement.classList.toggle("dark-mode", query.matches);
  apply();
  query.addEventListener("change", apply);
})();
