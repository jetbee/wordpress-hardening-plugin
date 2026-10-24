"""Static controls for the opt-in xmlrpc.php failed-login lockout."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "plugins/wordpress-hardening-ratelimit-xmlrpc.conf"
CONFIG = ROOT / "plugins/wordpress-hardening-config.conf"
GATES = ("TX:wphard.xmlrpc_rl", "TX:wphard.xmlrpc_auth_failed")

FAULT = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Incorrect username or password.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
"""
SUCCESS = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><array><data>
<value><struct><member><name>blogName</name><value><string>403</string></value>
</member></struct></value></data></array></value></param></params></methodResponse>
"""
MULTICALL = """<?xml version="1.0"?>
<methodCall><methodName>system.multicall</methodName><params><param><value>
<array><data><value><struct>
<member><name>methodName</name><value>%s</value></member>
<member><name>params</name><value><array><data>
<value><string>admin</string></value><value><string>guess</string></value>
</data></array></value></member>
</struct></value></data></array></value></param></params></methodCall>
"""


def directives(source):
    """Yield (head, actions) for each SecRule/SecAction, chains included."""
    text = re.sub(r"\\\n\s*", "", source)
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("SecRule "):
            match = re.match(r'SecRule (\S+) "((?:[^"\\]|\\.)*)" "(.*)"$', line)
            if match is None:
                raise AssertionError(f"unparsed rule: {line[:80]}")
            yield match.group(1), match.group(2), match.group(3)


def rule_operator(source, rule_id, target=None):
    rules = list(directives(source))
    for index, (_var, _op, actions) in enumerate(rules):
        if f"id:{rule_id}," in actions:
            chain = [rules[index]]
            while "chain" in re.split(r",\s*", chain[-1][2]):
                chain.append(rules[index + len(chain)])
            for var, op, _actions in chain:
                if target is None or var == target:
                    return op
    raise AssertionError(f"rule {rule_id} is missing")


def regex(operator):
    if not operator.startswith("@rx "):
        raise AssertionError(f"not a regex operator: {operator}")
    return re.compile(operator[4:].replace("\\\\", "\\"))


class XmlrpcLockoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = RULES.read_text(encoding="utf-8")
        cls.rules = list(directives(cls.source))

    def test_file_stays_outside_crs_loader_globs(self):
        self.assertFalse(re.search(r"-(?:config|before|after)\.conf$", RULES.name))

    def test_ids_stay_in_the_reserved_block(self):
        ids = [int(i) for i in re.findall(r"id:(\d+),", self.source)]
        self.assertEqual(len(ids), len(set(ids)))
        for rule_id in ids:
            with self.subTest(rule_id=rule_id):
                self.assertTrue(9522420 <= rule_id <= 9522439)
                self.assertNotIn(rule_id, (9522430, 9522431))
        for example in (9522430, 9522431):
            self.assertIn(f"id:{example},", CONFIG.read_text(encoding="utf-8"))

    def test_later_phases_are_gated_by_the_phase_one_flag(self):
        # skipAfter in phase 1 does not skip phase 2/4 rules, so each chain
        # starter in a later phase must test a flag only the gate sets.
        previous_chained = False
        checked = 0
        for var, _op, actions in self.rules:
            starter = not previous_chained
            previous_chained = "chain" in re.split(r",\s*", actions)
            phase = re.search(r"phase:(\d)", actions)
            if not starter or phase is None or phase.group(1) == "1":
                continue
            checked += 1
            with self.subTest(actions=actions[:30]):
                self.assertIn(var, GATES)
        self.assertEqual(6, checked)
        self.assertEqual(1, self.source.count("setvar:tx.wphard.xmlrpc_rl=1"))

    def test_fault_regex_matches_failed_login_only(self):
        pattern = regex(rule_operator(self.source, 9522429, "RESPONSE_BODY"))
        self.assertIsNotNone(pattern.search(FAULT))
        self.assertIsNotNone(pattern.search(FAULT.replace("<int>", "<i4>").replace("</int>", "</i4>")))
        self.assertIsNone(pattern.search(SUCCESS))
        self.assertIsNone(pattern.search(FAULT.replace("403", "405")))

    def test_multicall_regex_needs_authenticated_calls(self):
        source = self.source
        rules = [op for var, op, _a in self.rules if var == "REQUEST_BODY"]
        self.assertEqual(2, len(rules), source.count("REQUEST_BODY"))
        multicall, auth = (regex(op) for op in rules)
        for method in ("wp.getUsersBlogs", "<string>wp.getUsersBlogs</string>",
                       "metaWeblog.getRecentPosts", " blogger.getUsersBlogs", "mt.getCategoryList"):
            with self.subTest(method=method):
                body = MULTICALL % method
                self.assertIsNotNone(multicall.search(body))
                self.assertIsNotNone(auth.search(body))
        for method in ("pingback.ping", "system.listMethods", "<string>demo.sayHello</string>"):
            with self.subTest(method=method):
                self.assertIsNone(auth.search(MULTICALL % method))


if __name__ == "__main__":
    unittest.main()
