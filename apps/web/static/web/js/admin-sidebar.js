// Restore the admin's navigation sidebar state before the page first paints.
// Django's nav_sidebar.js does the same, but it is deferred, so the content
// renders full width and then jumps right (a 0.17 layout shift). This file is
// loaded synchronously right after the sidebar markup, inside #main.
(() => {
  "use strict";
  const main = document.getElementById("main");
  if (!main || !document.getElementById("toggle-nav-sidebar")) return;
  let open = null;
  try {
    open = localStorage.getItem("django.admin.navSidebarIsOpen");
  } catch {
    // Storage blocked: Django treats a missing value as open, and so do we.
  }
  main.classList.toggle("shifted", open === null || open === "true");
})();
