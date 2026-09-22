/* Hide automation tells before page scripts run. */
(function () {
  try {
    Object.defineProperty(navigator, "webdriver", { get: function () { return false; }, configurable: true });
  } catch (e) {}
  try {
    if (!window.chrome) {
      window.chrome = { runtime: {}, loadTimes: function () { return {}; }, csi: function () { return {}; } };
    }
  } catch (e) {}
  try {
    Object.defineProperty(navigator, "languages", { get: function () { return ["en-US", "en"]; } });
  } catch (e) {}
  try {
    Object.defineProperty(navigator, "platform", { get: function () { return "Win32"; } });
  } catch (e) {}
  try {
    Object.defineProperty(navigator, "plugins", {
      get: function () {
        return [
          { name: "PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
          { name: "Chrome PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
          { name: "Chromium PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" }
        ];
      }
    });
  } catch (e) {}
  try {
    Object.defineProperty(navigator, "maxTouchPoints", { get: function () { return 0; } });
  } catch (e) {}
  try {
    var orig = WebGLRenderingContext && WebGLRenderingContext.prototype.getParameter;
    if (orig) {
      WebGLRenderingContext.prototype.getParameter = function (p) {
        if (p === 37445) return "Google Inc. (NVIDIA)";
        if (p === 37446) return "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0)";
        return orig.apply(this, arguments);
      };
    }
  } catch (e) {}
  try {
    if (window.outerWidth === 0) {
      Object.defineProperty(window, "outerWidth", { get: function () { return window.innerWidth || 1920; } });
      Object.defineProperty(window, "outerHeight", { get: function () { return window.innerHeight || 1080; } });
    }
  } catch (e) {}
  try {
    var origQuery = navigator.permissions && navigator.permissions.query;
    if (origQuery) {
      navigator.permissions.query = function (par) {
        if (par && par.name === "notifications") {
          return Promise.resolve({ state: Notification.permission });
        }
        return origQuery.apply(this, arguments);
      };
    }
  } catch (e) {}
})();
