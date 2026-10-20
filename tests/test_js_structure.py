from evilbox.parsers import parse_js
from evilbox.pipeline import deobfuscate
from evilbox.rewrite import node_text, walk


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


def _fn(source: str, name: str):
    tree = parse_js(source)
    for node in walk(tree.root_node):
        if node.type != "function_declaration":
            continue
        ident = node.child_by_field_name("name")
        if ident is not None and node_text(source, ident) == name:
            return node
    raise AssertionError(f"missing function {name}")


def test_js_sequence_split_stays_inside_single_statement_body():
    src = """
a(), b();
function f(cond, ready) {
  if (cond) c(), d();
  else return e(), fval;
  while (ready) next(), work();
  for (var i = 0; i < 2; i++) log(i), bump();
  do step(), more(); while (ok);
  with (box) left(), right();
  label: head(), tail();
  return 1;
}
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    text = result.text
    program = parse_js(text).root_node
    top = [child for child in program.named_children if child.type != "comment"]
    assert [node_text(text, top[0]), node_text(text, top[1])] == ["a();", "b();"]
    fn = _fn(text, "f")
    body = [child for child in fn.child_by_field_name("body").named_children if child.type != "comment"]
    if_stmt, while_stmt, for_stmt, do_stmt, with_stmt, labeled, ret = body
    assert if_stmt.type == "if_statement"
    consequence = if_stmt.child_by_field_name("consequence")
    assert "c()" in node_text(text, consequence) and "d()" in node_text(text, consequence)
    alternative = if_stmt.child_by_field_name("alternative")
    alt = node_text(text, alternative)
    assert "e()" in alt and "return" in alt and "fval" in alt
    assert "return" in node_text(text, ret) and "fval" not in node_text(text, ret)
    assert while_stmt.type == "while_statement"
    while_body = while_stmt.child_by_field_name("body")
    assert "next()" in node_text(text, while_body) and "work()" in node_text(text, while_body)
    assert for_stmt.type == "for_statement"
    for_body = for_stmt.child_by_field_name("body")
    assert "log(i)" in node_text(text, for_body) and "bump()" in node_text(text, for_body)
    assert do_stmt.type == "do_statement"
    do_body = do_stmt.child_by_field_name("body")
    assert "step()" in node_text(text, do_body) and "more()" in node_text(text, do_body)
    assert with_stmt.type == "with_statement"
    with_body = with_stmt.child_by_field_name("body")
    assert "left()" in node_text(text, with_body) and "right()" in node_text(text, with_body)
    assert labeled.type == "labeled_statement"
    labeled_body = labeled.child_by_field_name("body")
    assert "head()" in node_text(text, labeled_body) and "tail()" in node_text(text, labeled_body)


def test_js_switch_default_sequence_splits_in_place():
    src = """
function f(x) {
  switch (x) {
    default:
      a(), b();
      break;
  }
}
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    fn = _fn(result.text, "f")
    switch = next(node for node in walk(fn) if node.type == "switch_statement")
    default = next(node for node in walk(switch) if node.type == "switch_default")
    body = node_text(result.text, default)
    assert body.index("a()") < body.index("b()") < body.index("break")


def test_js_debug_protection_keeps_unrelated_timer_callback():
    src = """
function report(n) {
  var msg = "debugger detected: " + n;
  try {
    send(msg);
  } catch (e) {}
  n++;
}
setInterval(report, 1000);
console.log("payload");
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert "send(msg)" in result.text
    assert "setInterval" in result.text
    assert "Removed debug-protection stub" not in result.warnings


def test_js_control_flow_switch_does_not_miscompile_prefix_or_break():
    prefix = """
function f() {
  var d = "0|1".split("|");
  var e = 0;
  while (true) {
    switch (d[++e]) {
      case "0":
        console.log("a");
        continue;
      case "1":
        console.log("b");
        continue;
    }
    break;
  }
}
"""
    result = deobfuscate(prefix, language="js")
    assert result.parse_ok
    assert "switch" in result.text
    assert "Flattened control-flow switch" not in result.warnings

    broken = """
function f() {
  while (outer) {
    var d = "0|1".split("|");
    var e = 0;
    while (true) {
      switch (d[e++]) {
        case "0":
          console.log("a");
          break;
        case "1":
          console.log("b");
          continue;
      }
      break;
    }
    after();
  }
}
"""
    result = deobfuscate(broken, language="js")
    assert result.parse_ok
    assert "switch" in result.text
    assert "after()" in result.text
    fn = _fn(result.text, "f")
    brk = next(node for node in walk(fn) if node.type == "break_statement" and node_text(result.text, node).strip() == "break;")
    parent = brk.parent
    assert parent is not None and parent.type == "switch_case"

    labeled = """
function f() {
  var d = "0|1".split("|");
  var e = 0;
  while (true) {
    switch (d[e++]) {
      case "0":
        console.log("a");
        continue;
      case "1":
        continue outer;
    }
    break;
  }
}
"""
    result = deobfuscate(labeled, language="js")
    assert result.parse_ok
    assert "continue outer" in result.text
    assert "switch" in result.text


def test_js_chained_member_is_not_copied_per_access():
    src = """
var obj = { a: function (x, y) { return x + y; } };
obj.a.extra = 1;
sink(obj.a.extra);
"""
    result = deobfuscate(src, language="js")
    assert result.parse_ok
    assert result.text.count("function") == 1
    assert "obj.a.extra" in result.text
