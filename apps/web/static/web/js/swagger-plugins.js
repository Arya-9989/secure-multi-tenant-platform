// Accessibility fixes for Swagger UI, loaded after its bundle and before the
// init script. The init script calls SwaggerUIBundle(config); this file wraps
// that function so every instance also gets the plugin below.
(() => {
  "use strict";
  const Bundle = window.SwaggerUIBundle;
  if (typeof Bundle !== "function") return;

  const AccessibleLayout = (system) => {
    const h = system.React.createElement;
    // With deep linking on, Swagger UI renders each operation's path as an
    // <a href="#/tag/operation"> inside the summary <button>, nesting one
    // control in another (axe: nested-interactive). The link adds nothing the
    // button lacks: expanding an operation already writes its deep link to the
    // address bar, and opening that URL expands it again. So the path renders
    // as text, while the tag headings keep their own anchors.
    const PathText = ({ text }) => h("span", null, text);
    const withPlainPath = (getComponent) => (name, ...rest) =>
      name === "DeepLink" ? PathText : getComponent(name, ...rest);

    return {
      wrapComponents: {
        OperationSummaryPath: (Original) => (props) =>
          h(Original, { ...props, getComponent: withPlainPath(props.getComponent) }),
        // Everything on the page sits in a landmark (axe: region).
        InfoContainer: (Original) => (props) =>
          h("section", { "aria-label": "About this API" }, h(Original, props)),
        AuthorizeBtnContainer: (Original) => (props) =>
          h("section", { className: "docs-auth", "aria-label": "Authorization" }, h(Original, props)),
        FilterContainer: (Original) => (props) =>
          h("div", { role: "search", "aria-label": "Filter operations by tag" }, h(Original, props)),
        // The API title is the page's h1 and tag headings are h3: give the
        // operation list the h2 that belongs between them (axe: heading-order).
        operations: (Original) => (props) =>
          h(
            system.React.Fragment,
            null,
            h("h2", { className: "visually-hidden" }, "Operations"),
            h(Original, props),
          ),
      },
    };
  };

  const bundle = (config) =>
    Bundle({ ...config, plugins: [...(config.plugins || []), AccessibleLayout] });
  Object.assign(bundle, Bundle); // presets, plugins and the other static members
  window.SwaggerUIBundle = bundle;
})();
