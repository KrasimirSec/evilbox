/* Log eval / Function / setTimeout(string) to same-origin analytics beacon. */
(function () {
  var MODE = "__MODE__";
  function report(kind, code) {
    try {
      var body = String(kind) + "\n" + String(code == null ? "" : code);
      if (navigator.sendBeacon) {
        navigator.sendBeacon("/cdn/l.gif", body);
      } else {
        var x = new XMLHttpRequest();
        x.open("POST", "/cdn/l.gif", true);
        x.send(body);
      }
    } catch (e) {}
  }
  function wrapEval(orig) {
    return function (code) {
      report("eval", code);
      if (MODE === "dump") return undefined;
      return orig.apply(this, arguments);
    };
  }
  try {
    window.eval = wrapEval(window.eval);
  } catch (e) {}
  try {
    var OrigFn = window.Function;
    window.Function = function () {
      var args = Array.prototype.slice.call(arguments);
      report("Function", args.join("\n"));
      if (MODE === "dump") {
        return function () { return undefined; };
      }
      return OrigFn.apply(this, args);
    };
    window.Function.prototype = OrigFn.prototype;
  } catch (e) {}
  function wrapTimer(orig) {
    return function (handler, timeout) {
      if (typeof handler === "string") {
        report("setTimeout", handler);
        if (MODE === "dump") return 0;
      }
      return orig.apply(this, arguments);
    };
  }
  try { window.setTimeout = wrapTimer(window.setTimeout); } catch (e) {}
  try { window.setInterval = wrapTimer(window.setInterval); } catch (e) {}
})();
