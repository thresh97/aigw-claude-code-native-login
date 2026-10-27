"""Tests for tools/release_check.py: the gate passes on this repository, and it fails on each kind of drift it exists to catch."""
import argparse
import datetime
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_check as rc  # noqa: E402


def parser_with(**commands):
    """An argparse parser with the given subcommands: parser_with(alpha=["--one", "--two"])."""
    ap = argparse.ArgumentParser(prog="x")
    sub = ap.add_subparsers(dest="cmd")
    for name, flags in commands.items():
        p = sub.add_parser(name)
        for f in flags:
            p.add_argument(f, action="store_true")
    return ap


CLIENT_REF = "## Client reference\n\n| Command | What it does |\n|---|---|\n{rows}\n\n**Config keys.**\n"


class RepositoryTests(unittest.TestCase):
    def test_the_repository_passes_the_gate(self):
        results, _ = rc.run_all()
        failing = {k: v for k, v in results.items() if v}
        self.assertEqual(failing, {}, "the release gate fails on this repository: run python3 tools/release_check.py")


class MarkdownTests(unittest.TestCase):
    def test_slugify_matches_githubs_anchors(self):
        for heading, slug in (("1.3 Client, per user", "13-client-per-user"), ("Sign-in method", "sign-in-method"),
                              ("What you need", "what-you-need"), ("`install` and **flags**", "install-and-flags"),
                              ("Without a JWT: gateway API keys", "without-a-jwt-gateway-api-keys"),
                              ("[Linked](x.md) heading", "linked-heading")):
            self.assertEqual(rc.slugify(heading), slug, heading)

    def test_duplicate_headings_get_numbered_anchors_and_code_fences_are_ignored(self):
        text = "# A\n## Same\n## Same\n```\n# not a heading\n```\n"
        self.assertEqual(rc.heading_anchors(text), {"a", "same", "same-1"})

    def test_table_rows_split_on_unescaped_pipes_only(self):
        rows = rc.table_rows("x\n| `a \\| b` | desc |\n|---|---|\n| `c` | d |\n", "x", "\n## ")
        self.assertEqual(rows, [["`a \\| b`", "desc"], ["`c`", "d"]])


class LinkTests(unittest.TestCase):
    def test_a_good_set_of_links_passes(self):
        files = {"README.md": "# Top\n## Sub heading\nSee [d](docs/a.md#part), [self](#sub-heading), [web](https://x.example/#nope) and [m](mailto:a@b.c).\n",
                 "docs/a.md": "# A\n## Part\nBack to [top](../README.md#top).\n"}
        self.assertEqual(rc.link_problems(files), [])

    def test_a_missing_file_a_missing_anchor_and_a_bad_in_page_anchor_are_caught(self):
        files = {"README.md": "# Top\n[a](docs/gone.md) [b](docs/a.md#nowhere) [c](#missing)\n", "docs/a.md": "# A\n"}
        problems = rc.link_problems(files)
        self.assertEqual(len(problems), 3, problems)
        self.assertTrue(any("gone.md" in p for p in problems))
        self.assertTrue(any("#nowhere" in p for p in problems))
        self.assertTrue(any("#missing" in p for p in problems))

    def test_links_inside_code_are_not_links(self):
        files = {"README.md": "# Top\n```\n[x](nowhere.md)\n```\nand `[y](nowhere.md)` inline\n"}
        self.assertEqual(rc.link_problems(files), [])


class CommandTests(unittest.TestCase):
    def test_in_step_passes(self):
        readme = CLIENT_REF.format(rows="| `alpha [--one] [--two]` | does alpha |\n| `beta` | does beta |")
        self.assertEqual(rc.command_problems(parser_with(alpha=["--one", "--two"], beta=[]), readme), [])

    def test_a_flag_the_readme_does_not_mention_is_caught(self):
        readme = CLIENT_REF.format(rows="| `alpha [--one]` | does alpha |\n| `beta` | does beta |")
        problems = rc.command_problems(parser_with(alpha=["--one", "--two"], beta=[]), readme)
        self.assertEqual(problems, ["alpha --two is in the argument parser but not in its README row"])

    def test_a_flag_that_only_the_readme_has_is_caught(self):
        readme = CLIENT_REF.format(rows="| `alpha [--one] [--gone]` | does alpha |")
        problems = rc.command_problems(parser_with(alpha=["--one"]), readme)
        self.assertEqual(problems, ["README documents alpha --gone, which the argument parser does not have"])

    def test_a_missing_and_an_unknown_command_are_caught(self):
        readme = CLIENT_REF.format(rows="| `alpha` | does alpha |\n| `ghost` | nothing |")
        problems = rc.command_problems(parser_with(alpha=[], beta=[]), readme)
        self.assertIn("command 'beta' is in the argument parser but not in the README client reference", problems)
        self.assertIn("command 'ghost' is in the README client reference but not in the argument parser", problems)

    def test_one_row_may_document_several_commands(self):
        readme = CLIENT_REF.format(rows="| `hook precheck`, `hook stop-failure` | the hooks |")
        self.assertEqual(rc.command_problems(parser_with(hook=[]), readme), [])


class ConfigTests(unittest.TestCase):
    def client(self, schema, defaults):
        return types.SimpleNamespace(SCHEMA=dict.fromkeys(schema), DEFAULTS=dict.fromkeys(defaults))

    def test_a_key_missing_from_the_readme_table_or_the_schema_is_caught(self):
        readme = "**Config keys.**\n\n| Key | Default | Meaning |\n|---|---|---|\n| `a` | | x |\n| `stale` | | y |\n\n## Next\n"
        with tempfile.TemporaryDirectory() as d:
            problems = rc.config_problems(self.client(["a", "b"], ["a", "b", "c"]), readme, d)
        self.assertIn("SCHEMA and DEFAULTS differ: ['c']", problems)
        self.assertIn("config key 'b' is in DEFAULTS but not in the README config table", problems)
        self.assertIn("config key 'stale' is in the README config table but not in DEFAULTS", problems)

    def test_an_example_config_with_an_unknown_key_is_caught(self):
        readme = "**Config keys.**\n\n| Key | Default | Meaning |\n|---|---|---|\n| `a` | | x |\n"
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "config.example.json").write_text(json.dumps({"a": 1, "typo": 2}))
            problems = rc.config_problems(self.client(["a"], ["a"]), readme, d)
        self.assertEqual(problems, ["config.example.json has keys the client does not know: ['typo']"])


class VersionAndMatrixTests(unittest.TestCase):
    def test_a_bad_version_and_a_hard_coded_packaging_title_are_caught(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "packaging").mkdir()
            (Path(d) / "packaging" / "README.md").write_text("# Fleet packaging (client 1.4.0)\n")
            problems = rc.version_problems(types.SimpleNamespace(VERSION="1.x"), Path(d))
        self.assertEqual(len(problems), 2, problems)

    def test_the_packages_must_carry_the_clients_version(self):
        with tempfile.TemporaryDirectory() as d:
            problems = rc.version_problems(types.SimpleNamespace(VERSION="1.9.0"), Path(d), types.SimpleNamespace(package_version=lambda: "1.4.0"))
        self.assertEqual(len(problems), 1)
        self.assertIn("1.4.0", problems[0])

    def test_the_support_matrix_needs_a_row_for_the_current_version_and_a_real_date(self):
        client = types.SimpleNamespace(VERSION="1.9.0")
        good = "Last reviewed: 2026-10-26\n| `1.9.x` (current) | ok |\n"
        self.assertEqual(rc.matrix_problems(client, good, today=datetime.date(2026, 10, 27)), [])
        self.assertIn("is missing", rc.matrix_problems(client, None)[0])
        self.assertTrue(any("no 'Last reviewed" in p for p in rc.matrix_problems(client, "| `1.9.x` |\n")))
        self.assertTrue(any("in the future" in p for p in rc.matrix_problems(client, good, today=datetime.date(2026, 10, 1))))
        self.assertTrue(any("no row for client 1.10.x" in p for p in rc.matrix_problems(types.SimpleNamespace(VERSION="1.10.0"), good, today=datetime.date(2026, 10, 27))))

    def test_help_must_explain_both_kinds_of_mode(self):
        self.assertEqual(len(rc.help_problems(argparse.ArgumentParser(prog="x"))), 5)


class EvidenceTests(unittest.TestCase):
    RECORD = ("### Finding {n}\n\n**T**\n\n- **Claim:** c\n- **Component and version:** v\n- **Environment:** e\n- **Method:** m\n"
              "- **Date:** 2026-10-26\n- **Status:** observed\n- **Rerun:** r\n")

    def doc(self, n=2):
        return "# Findings\n\n" + "\n".join(self.RECORD.format(n=i) for i in range(1, n + 1))

    def test_complete_records_pass(self):
        self.assertEqual(rc.evidence_problems(self.doc(3), "see finding 2 and findings 1 to 3"), [])

    def test_a_missing_field_a_bad_date_and_a_bad_status_are_caught(self):
        text = self.doc(2).replace("- **Environment:** e\n", "", 1).replace("2026-10-26", "Oct 26", 1).replace("observed", "probably", 1)
        problems = rc.evidence_problems(text)
        self.assertEqual(len(problems), 3, problems)

    def test_gaps_and_repeats_in_the_numbering_are_caught(self):
        text = self.doc(3).replace("### Finding 2", "### Finding 5")
        self.assertTrue(any("without gaps" in p for p in rc.evidence_problems(text)))

    def test_citing_a_finding_that_does_not_exist_is_caught(self):
        problems = rc.evidence_problems(self.doc(2), "as finding 7 shows")
        self.assertEqual(len(problems), 1)
        self.assertIn("finding 7", problems[0])

    def test_the_real_findings_have_all_22_records(self):
        text = (rc.ROOT / "docs" / "evidence" / "findings.md").read_text(encoding="utf-8")
        self.assertEqual(len(__import__("re").findall(r"(?m)^### Finding \d+$", text)), 22)


if __name__ == "__main__":
    unittest.main()
