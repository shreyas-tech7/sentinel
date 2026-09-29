"""Per-rule detection tests: vulnerable shapes fire, safe counterparts don't."""

import unittest

from sentinel.rules import ALL_RULES
from sentinel.rules import sqli, xss, cmdi, path_traversal, deserialization, secrets, ssrf
from sentinel.taint import build_context


def check(rule, code: str, lang: str):
    ctx = build_context("t", lang, code)
    for i, line in enumerate(ctx.lines):
        f = rule.check(ctx, i, line)
        if f is not None:
            return f
    return None


class TestSqli(unittest.TestCase):
    rule = sqli.RULE

    def test_php_mysqli_concat(self):
        code = "<?php\n$id = $_GET['id'];\n$r = mysqli_query($c, \"SELECT * FROM u WHERE id = '$id'\");"
        self.assertIsNotNone(check(self.rule, code, "php"))

    def test_php_prepared_statement_clean(self):
        code = ("<?php\n$id = $_GET['id'];\n"
                "$st = $pdo->prepare('SELECT * FROM u WHERE id = :id');\n"
                "$st->execute(['id' => $id]);")
        self.assertIsNone(check(self.rule, code, "php"))

    def test_escaped_but_unquoted_still_flags(self):
        code = ("<?php\n$id = mysqli_real_escape_string($c, $_POST['id']);\n"
                "$q = \"SELECT * FROM u WHERE user_id = $id\";\n$r = mysqli_query($c, $q);")
        self.assertIsNotNone(check(self.rule, code, "php"))

    def test_escaped_and_quoted_clean(self):
        code = ("<?php\n$n = mysqli_real_escape_string($c, $_POST['n']);\n"
                "$q = \"INSERT INTO g VALUES ('$n')\";\n$r = mysqli_query($c, $q);")
        self.assertIsNone(check(self.rule, code, "php"))

    def test_js_template_literal(self):
        code = "const q = req.query.q;\nsequelize.query(`SELECT * FROM p WHERE name LIKE '%${q}%'`);"
        self.assertIsNotNone(check(self.rule, code, "js"))

    def test_js_parameterized_clean(self):
        code = "pool.query('SELECT * FROM o WHERE customer = $1', [req.query.customer]);"
        self.assertIsNone(check(self.rule, code, "js"))

    def test_py_fstring(self):
        code = "acct = request.args.get('id')\nq = f\"SELECT * FROM t WHERE a = '{acct}'\"\ncursor.execute(q)"
        self.assertIsNotNone(check(self.rule, code, "py"))

    def test_py_parameterized_clean(self):
        code = 'cursor.execute("SELECT * FROM t WHERE a = ?", (acct,))'
        self.assertIsNone(check(self.rule, code, "py"))

    def test_nosql_operator(self):
        code = "db.users.findOne({ email: { $ne: null } })"
        self.assertIsNotNone(check(self.rule, code, "js"))

    def test_nosql_request_value(self):
        code = "db.users.findOne({ email: req.body.email })"
        self.assertIsNotNone(check(self.rule, code, "js"))

    def test_go_sprintf(self):
        code = 'sku := r.URL.Query().Get("sku")\nq := fmt.Sprintf("SELECT * FROM i WHERE sku = \'%s\'", sku)\nrows, err := db.Query(q)'
        self.assertIsNotNone(check(self.rule, code, "go"))


class TestXss(unittest.TestCase):
    rule = xss.RULE

    def test_php_echo_superglobal(self):
        self.assertIsNotNone(check(self.rule, "<?php echo $_GET['name']; ?>", "php"))

    def test_php_htmlspecialchars_clean(self):
        self.assertIsNone(check(self.rule, "<?php echo htmlspecialchars($_GET['name'], ENT_QUOTES); ?>", "php"))

    def test_js_innerhtml(self):
        self.assertIsNotNone(check(self.rule, "el.innerHTML = '<div>' + req.body.body + '</div>';", "js"))

    def test_js_textcontent_clean(self):
        self.assertIsNone(check(self.rule, "el.textContent = req.body.body;", "js"))

    def test_react_dangerous(self):
        self.assertIsNotNone(check(self.rule, "const h = req.body.d;\nreturn <div dangerouslySetInnerHTML={{ __html: h }} />;", "js"))

    def test_dompurify_clean(self):
        self.assertIsNone(check(self.rule, "el.innerHTML = DOMPurify.sanitize(req.body.d);", "js"))

    def test_angular_bypass(self):
        self.assertIsNotNone(check(
            self.rule,
            "this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(query.body.markup);",
            "js"))


class TestCmdi(unittest.TestCase):
    rule = cmdi.RULE

    def test_php_shell_exec(self):
        code = "<?php\n$t = $_REQUEST['ip'];\n$o = shell_exec('ping ' . $t);"
        self.assertIsNotNone(check(self.rule, code, "php"))

    def test_php_escapeshellarg_clean(self):
        code = "<?php\n$t = escapeshellarg($_REQUEST['ip']);\n$o = shell_exec('ping ' . $t);"
        self.assertIsNone(check(self.rule, code, "php"))

    def test_py_shell_true(self):
        code = "host = request.form['host']\nsubprocess.run(f'nslookup {host}', shell=True)"
        self.assertIsNotNone(check(self.rule, code, "py"))

    def test_py_list_form_clean(self):
        code = "host = request.form['host']\nsubprocess.run(['nslookup', host], capture_output=True)"
        self.assertIsNone(check(self.rule, code, "py"))

    def test_js_exec(self):
        code = "const { exec } = require('child_process');\nexec('tar -czf b.tgz ' + req.body.path);"
        self.assertIsNotNone(check(self.rule, code, "js"))

    def test_go_sh_c(self):
        code = 'name := r.FormValue("image")\nout, err := exec.Command("sh", "-c", "convert "+name).Output()'
        self.assertIsNotNone(check(self.rule, code, "go"))

    def test_go_arglist_clean(self):
        code = 'name := r.FormValue("image")\nout, err := exec.Command("convert", name).Output()'
        self.assertIsNone(check(self.rule, code, "go"))


class TestPath(unittest.TestCase):
    rule = path_traversal.RULE

    def test_php_include(self):
        code = "<?php\n$p = $_GET['page'];\ninclude($p);"
        self.assertIsNotNone(check(self.rule, code, "php"))

    def test_php_allowlisted_include_clean(self):
        code = ("<?php\n$p = $_GET['page'];\n"
                "$allowed = ['a.php', 'b.php'];\n"
                "if (in_array($p, $allowed, true)) { include($p); }")
        self.assertIsNone(check(self.rule, code, "php"))

    def test_js_sendfile(self):
        code = "app.get('/f/:f', (req, res) => { res.sendFile(path.join('docs/', req.params.f)); });"
        self.assertIsNotNone(check(self.rule, code, "js"))

    def test_js_basename_root_clean(self):
        code = ("app.get('/f/:f', (req, res) => {\n"
                "  const safe = path.basename(req.params.f);\n"
                "  res.sendFile(safe, { root: 'docs/' });\n});")
        self.assertIsNone(check(self.rule, code, "js"))

    def test_py_open(self):
        code = "note = request.args.get('note')\nwith open(f'static/{note}', 'rb') as fh:\n    data = fh.read()"
        self.assertIsNotNone(check(self.rule, code, "py"))


class TestDeserialization(unittest.TestCase):
    rule = deserialization.RULE

    def test_pickle(self):
        code = "blob = request.cookies.get('s')\nstate = pickle.loads(blob.encode('latin1'))"
        self.assertIsNotNone(check(self.rule, code, "py"))

    def test_yaml_load(self):
        self.assertIsNotNone(check(self.rule, "data = yaml.load(request.data)", "py"))

    def test_safe_yaml_clean(self):
        self.assertIsNone(check(self.rule, "data = yaml.safe_load(request.data)", "py"))

    def test_json_clean(self):
        self.assertIsNone(check(self.rule, "state = json.loads(request.data)", "py"))

    def test_php_unserialize(self):
        self.assertIsNotNone(check(self.rule, "<?php return unserialize($_COOKIE['p']);", "php"))

    def test_java_objectinputstream(self):
        code = ("@PostMapping(\"/d\")\n"
                "public R go(@RequestParam String token) throws Exception {\n"
                "  byte[] data = Base64.getDecoder().decode(token);\n"
                "  ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));\n"
                "}")
        self.assertIsNotNone(check(self.rule, code, "java"))


class TestSecrets(unittest.TestCase):
    rule = secrets.RULE

    def test_api_key_literal(self):
        code = 'const config = { apiKey: "AIzaSyD9tJq8Xy7WvN0aB1cD2eF3gH4" };'
        self.assertIsNotNone(check(self.rule, code, "js"))

    def test_env_lookup_clean(self):
        code = "const key = process.env.STRIPE_SECRET_KEY;"
        self.assertIsNone(check(self.rule, code, "js"))

    def test_placeholder_clean(self):
        code = 'const config = { apiKey: "<YOUR_API_KEY>" };'
        self.assertIsNone(check(self.rule, code, "js"))

    def test_comparison_is_not_a_secret(self):
        code = "if (req.body.password === 'admin123') { login(); }"
        self.assertIsNone(check(self.rule, code, "js"))

    def test_sql_text_is_not_a_secret(self):
        code = 'String q = "SELECT password FROM users WHERE name = \'dave\'";'
        self.assertIsNone(check(self.rule, code, "java"))

    def test_aws_shape(self):
        code = 'public static final String K = "AKIAIOSFODNN7DEMO123";'
        self.assertIsNotNone(check(self.rule, code, "java"))

    def test_pem_shape(self):
        code = "const k = `-----BEGIN RSA PRIVATE KEY-----\\nMIICXAIBAAKBgQC0exampleNOTAKEY0`;"
        self.assertIsNotNone(check(self.rule, code, "js"))


class TestSsrf(unittest.TestCase):
    rule = ssrf.RULE

    def test_js_fetch_user_url(self):
        code = "const url = req.body.imageUrl;\nconst r = await fetch(url);"
        self.assertIsNotNone(check(self.rule, code, "js"))

    def test_literal_url_clean(self):
        self.assertIsNone(check(self.rule, "const r = await fetch('https://api.example.com/gas');", "js"))

    def test_py_requests(self):
        code = "u = request.form['u']\nreturn requests.get(u, timeout=5).content"
        self.assertIsNotNone(check(self.rule, code, "py"))

    def test_allowlisted_clean(self):
        code = ("ALLOWED = ['images.internal']\n"
                "u = request.form['u']\n"
                "if u.split('/')[2] not in ALLOWED: raise ValueError\n"
                "return requests.get(u).content")
        self.assertIsNone(check(self.rule, code, "py"))

    def test_php_curl(self):
        code = "<?php\n$ch = curl_init($_GET['u']);\ncurl_exec($ch);"
        self.assertIsNotNone(check(self.rule, code, "php"))

    def test_java_url_openstream(self):
        code = ("@GetMapping(\"/proxy\")\n"
                "public String go(@RequestParam String target) throws Exception {\n"
                "    URL url = new URL(target);\n"
                "    try (InputStream in = url.openStream()) { return read(in); }\n"
                "}")
        self.assertIsNotNone(check(self.rule, code, "java"))


class TestRegistry(unittest.TestCase):
    def test_seven_rules_registered(self):
        self.assertEqual(7, len(ALL_RULES))

    def test_rule_ids_aligned_with_catalog(self):
        expected_prefixes = ("SENT-INJ-01", "SENT-INJ-02", "SENT-INJ-07",
                             "SENT-INJ-09", "SENT-INJ-10", "SENT-SECRET-01")
        for r in ALL_RULES:
            prefix = r.rule_id.split("/")[0]
            self.assertIn(prefix, expected_prefixes, r.rule_id)


if __name__ == "__main__":
    unittest.main()
