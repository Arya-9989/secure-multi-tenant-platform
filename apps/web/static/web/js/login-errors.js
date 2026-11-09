// Focus the submitted form's error summary before users retry their credentials.
(() => {
  "use strict";
  const summary = document.getElementById("login-errors");
  if (!summary) return;
  document.querySelector("[autofocus]")?.removeAttribute("autofocus");
  summary.focus();
})();
