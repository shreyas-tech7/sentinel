"""Unit tests for the taint model."""

import unittest

from sentinel.taint import (
    build_context,
    in_string_context,
    in_string_context as isc,
    taint_vars_in,
)


class TestStringContext(unittest.TestCase):
    def test_php_double_quote_interpolates(self):
        self.assertTrue(isc("php", '"SELECT * FROM t WHERE a = \'$id\'"', {"id": "source"}))

    def test_php_single_quote_is_not_string_context(self):
        self.assertFalse(isc("php", "'SELECT * FROM t WHERE a = $id'", {"id": "source"}))

    def test_php_unquoted_interpolation_is_string_context(self):
        # user_id = $id inside a double-quoted literal: escaped-but-unquoted
        self.assertTrue(isc("php", '"SELECT * FROM t WHERE user_id = $id"', {"id": "source"}))

    def test_js_template_interpolation(self):
        self.assertTrue(isc("js", "`SELECT * FROM t WHERE a = '${crit}'`", {"crit": "source"}))

    def test_js_plain_literal_is_not(self):
        self.assertFalse(isc("js", "'SELECT * FROM t WHERE a = crit'", {"crit": "source"}))

    def test_python_fstring(self):
        self.assertTrue(isc("py", 'f"SELECT * FROM t WHERE a = \'{acc}\'"', {"acc": "source"}))

    def test_python_plain_literal_is_not(self):
        self.assertFalse(isc("py", '"SELECT * FROM t WHERE a = acc"', {"acc": "source"}))

    def test_concat_adjacent(self):
        self.assertTrue(isc("php", "'SELECT ... ' . $id", {"id": "source"}))

    def test_member_access_is_not_concat(self):
        self.assertFalse(isc("js", "req.query.customer", {}))

    def test_param_context_is_not_string(self):
        self.assertFalse(isc("py", "cursor.execute(sql, (acct,))", {"acct": "source"}))


class TestPropagation(unittest.TestCase):
    def scan(self, code: str, lang: str = "php"):
        return build_context("test", lang, code)

    def test_simple_source_assignment(self):
        ctx = self.scan("<?php\n$id = $_GET['id'];\necho $id;")
        self.assertIn("id", ctx.source_tainted_vars)

    def test_string_built_query_marks_var_string_tainted(self):
        ctx = self.scan('<?php\n$id = $_GET["id"];\n$q = "SELECT ... \'$id\'";')
        self.assertIn("q", ctx.string_tainted_vars)

    def test_intval_defuses(self):
        ctx = self.scan("<?php\n$id = intval($_GET['id']);\necho \"x $id\";")
        self.assertNotIn("id", ctx.var_kinds)

    def test_escape_string_is_weak_not_strong(self):
        ctx = self.scan(
            "<?php\n$id = mysqli_real_escape_string($c, $_POST['id']);\n"
            "$q = \"SELECT ... '$id'\";"
        )
        self.assertIn("id", ctx.var_kinds)
        self.assertIn("id", ctx.escaped_vars)

    def test_last_assignment_wins_defuse(self):
        ctx = self.scan("<?php\n$id = $_GET['id'];\n$id = intval($id);\necho \"x $id\";")
        self.assertNotIn("id", ctx.var_kinds)

    def test_is_numeric_fences_indexed_tokens(self):
        code = (
            "<?php $t = $_REQUEST['ip']; $oct = explode('.', $t); "
            "if (is_numeric($oct[0]) && is_numeric($oct[1])) { "
            "$t = $oct[0] . '.' . $oct[1]; shell_exec('ping ' . $t); }"
        )
        ctx = self.scan(code)
        self.assertNotIn("t", ctx.var_kinds)

    def test_typescript_type_annotation_assignment(self):
        ctx = self.scan("let q: string = req.query.x;", lang="js")
        self.assertIn("q", ctx.source_tainted_vars)

    def test_java_request_param_seeding(self):
        code = (
            "@PostMapping(\"/x\")\n"
            "public R go(@RequestParam String region) throws Exception {\n"
            "  return run(region);\n"
            "}"
        )
        ctx = self.scan(code, lang="java")
        self.assertIn("region", ctx.source_tainted_vars)

    def test_java_numeric_params_not_seeded(self):
        code = (
            "@GetMapping\n"
            "public R go(@RequestParam Long id) {\n"
            "  return load(id);\n"
            "}"
        )
        ctx = self.scan(code, lang="java")
        self.assertNotIn("id", ctx.var_kinds)

    def test_multi_line_assignment(self):
        code = (
            "@PostMapping(\"/x\")\n"
            "public R go(@RequestParam String username) {\n"
            "  String checkUserQuery =\n"
            "      \"select userid from users where userid = '\" + username + \"'\";\n"
            "  return run(checkUserQuery);\n"
            "}"
        )
        ctx = self.scan(code, lang="java")
        self.assertIn("checkUserQuery", ctx.string_tainted_vars)

    def test_allowlist_guard_detected(self):
        ctx = self.scan(
            "const ALLOWED = ['/a'];\n"
            "if (ALLOWED.includes(req.query.p)) { res.sendFile(req.query.p); }",
            lang="js",
        )
        self.assertTrue(ctx.has_allowlist_guard)


class TestVarMatching(unittest.TestCase):
    def test_php_requires_sigil(self):
        ctx = build_context("t", "php", "<?php $exists = 1;")
        ctx.var_kinds["exists"] = "source"
        self.assertEqual({}, taint_vars_in(ctx, "User ID exists in the database."))

    def test_bare_word_in_plain_literal_ignored(self):
        ctx = build_context("t", "py", "x = request.args.get('q')")
        self.assertEqual({}, taint_vars_in(ctx, "log.info('account query ran')"))


if __name__ == "__main__":
    unittest.main()
