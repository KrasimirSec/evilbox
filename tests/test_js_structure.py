from evilbox.pipeline import deobfuscate


def test_js_dead_string_comparison_keeps_live_branch():
    src = """
if ("a" === "a") {
  console.log("foo");
} else {
  console.log("bar");
}
if ("a" !== "a") {
  console.log("nope");
}
var x = ("a" == "a") ? "yes" : "no";
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert "foo" in result.text
    assert "bar" not in result.text
    assert "nope" not in result.text
    assert "yes" in result.text
    assert "no" not in result.text
    assert "Removed dead string-comparison branch" in result.warnings


def test_js_real_comparison_is_kept():
    src = 'if (user === "a") { keep(); } else { also(); }'
    result = deobfuscate(src, language="js")
    assert "keep" in result.text
    assert "also" in result.text
    assert "===" in result.text


def test_js_dispatcher_object_is_inlined():
    src = """
var obj = {
  QuFtJ: function (n, r) { return n === r; },
  aokfw: function (a, b) { return b + a; },
  callx: function (a, b, c) { return a(b, c); }
};
var z = obj.QuFtJ(u, v);
var y = obj.aokfw(left, right);
var w = obj.callx(fn, one, two);
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert "u === v" in result.text or "(u) === (v)" in result.text
    assert "right + left" in result.text or "(right) + (left)" in result.text
    assert "fn(one, two)" in result.text or "fn((one), (two))" in result.text
    assert "QuFtJ" not in result.text
    assert "Inlined control-flow dispatcher" in result.warnings


def test_js_spread_dispatcher_is_inlined():
    src = """
var obj = {
  spr: function (a, ...b) { return a(...b); }
};
obj.spr(fn, x, y);
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert "fn(x, y)" in result.text or "fn((x), (y))" in result.text
    assert "spr" not in result.text


def test_js_anonymous_dispatcher_and_literal_member():
    src = """
({ QuFtJ: function (n, r) { return n === r; } }).QuFtJ(u, v);
({ YhxvC: "default" }).YhxvC;
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert "u === v" in result.text or "(u) === (v)" in result.text
    assert "default" in result.text
    assert "YhxvC" not in result.text


def test_js_constant_object_properties_are_inlined():
    src = """
var k = { c: 0x2f2, d: "0x396" };
var c = i(k.d, k.c);
side(k);
"""
    result = deobfuscate(src, language="js")
    assert "side(k)" in result.text
    assert "var k" in result.text or "k =" in result.text

    src = """
var k = { c: 0x2f2, d: "0x396" };
var c = i(k.d, k.c);
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert 'i("0x396", 0x2f2)' in result.text or "i('0x396', 0x2f2)" in result.text
    assert "Inlined constant object properties" in result.warnings


def test_js_transform_object_keys_alias():
    src = """
var obj = {};
obj.HLAuI = function (a, b) { return a < b; };
obj.aokfw = "0|1";
var alias = obj;
if (alias.HLAuI(one, two)) console.log(alias.aokfw);
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert "one < two" in result.text or "(one) < (two)" in result.text
    assert "0|1" in result.text
    assert "alias" not in result.text
    assert "HLAuI" not in result.text


def test_js_control_flow_switch_order():
    src = """
function f() {
  var d = "2|0|1".split("|");
  var e = 0;
  while (true) {
    switch (d[e++]) {
      case "0":
        console.log("a");
        continue;
      case "1":
        console.log("b");
        continue;
      case "2":
        console.log("c");
        continue;
    }
    break;
  }
  return 1;
}
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert result.text.index('log("c")') < result.text.index('log("a")') < result.text.index('log("b")')
    assert "switch" not in result.text
    assert "while" not in result.text
    assert "return 1" in result.text
    assert "Flattened control-flow switch" in result.warnings


def test_js_control_flow_switch_with_dispatcher():
    src = """
function applyTransforms() {
  var c = {
    HLAuI: "1|0",
    aokfw: function (a, b) { return a + b; }
  };
  var d = c.HLAuI.split("|");
  var e = 0;
  while (!![]) {
    switch (d[e++]) {
      case "0":
        var r = c.aokfw("hello", "world");
        continue;
      case "1":
        console.log("first");
        continue;
    }
    break;
  }
  return r;
}
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert result.text.index('log("first")') < result.text.index("helloworld")
    assert "switch" not in result.text
    assert "aokfw" not in result.text


def test_js_void_zero_sequence_and_computed_member():
    src = """
var x = void 0;
var y = 1 / 0;
function f() { return a(), b(), c; }
console["log"]("hi");
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert "undefined" in result.text
    assert "void" not in result.text
    assert "Infinity" in result.text
    assert "a();" in result.text
    assert "return c" in result.text
    assert "console.log" in result.text


def test_js_void_zero_kept_when_undefined_is_bound():
    src = "var undefined = 1; var x = void 0;"
    result = deobfuscate(src, language="js")
    assert "void" in result.text


def test_js_debug_protection_stub_is_removed():
    src = """
function anti(ret) {
  function trap(counter) {
    debugger;
    trap(++counter);
  }
  try {
    if (ret) { return trap; } else { trap(0); }
  } catch (e) {}
}
setInterval(anti, 4000);
console.log("payload");
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert "payload" in result.text
    assert "debugger" not in result.text
    assert "setInterval" not in result.text
    assert "Removed debug-protection stub" in result.warnings


def test_js_self_defending_wrapper_is_removed():
    src = """
var gate = (function () {
  var first = true;
  return function (context, fn) {
    var rfn = first ? function () {
      if (fn) {
        var res = fn.apply(context, arguments);
        fn = null;
        return res;
      }
    } : function () {};
    first = false;
    return rfn;
  };
})();
gate(this, function () {
  var check = function () {}.constructor("debugger");
})();
console.log("payload");
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert "payload" in result.text
    assert "gate" not in result.text
    assert "debugger" not in result.text
    assert "Removed self-defending wrapper" in result.warnings
