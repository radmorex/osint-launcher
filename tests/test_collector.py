"""Offline tests: normalisation, de-duplication, pivot rules, parsers, export.

Run: python3 -m unittest discover -s tests
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.engine import Engine, combine  # noqa: E402
from collector.export import build_tree, to_csv  # noqa: E402
from collector.modules.base import Module, Result  # noqa: E402
from collector.modules.tools import (parse_harvester, parse_holehe, parse_maigret,  # noqa: E402
                                     parse_phoneinfoga, parse_sherlock, parse_subfinder)
from collector.normalize import canonical_url, guess_type, normalize, registered_domain  # noqa: E402
from collector.store import Store  # noqa: E402


class NormalizeTest(unittest.TestCase):
    def test_gmail_aliases_share_a_key(self):
        a = normalize("email", "Ivan.Petrenko+shop@GMAIL.com")
        b = normalize("email", "ivanpetrenko@googlemail.com")
        self.assertEqual(a.key, b.key)
        self.assertEqual(a.value, "ivan.petrenko+shop@gmail.com")   # display keeps the original
        self.assertIn("freemail", a.flags)

    def test_plus_tag_kept_for_unknown_providers(self):
        self.assertNotEqual(normalize("email", "a+b@firma.ua").key, normalize("email", "a@firma.ua").key)

    def test_email_flags(self):
        self.assertIn("disposable", normalize("email", "x@mailinator.com").flags)
        self.assertIn("role", normalize("email", "info@firma.ua").flags)
        self.assertIsNone(normalize("email", "not-an-email"))
        self.assertIsNone(normalize("email", "a..b@x.com"))

    def test_phone_e164(self):
        self.assertEqual(normalize("phone", "+38 (067) 123-45-67").value, "+380671234567")
        self.assertEqual(normalize("phone", "0671234567").value, "+380671234567")
        self.assertEqual(normalize("phone", "00380671234567").key, "phone:+380671234567")
        self.assertIsNone(normalize("phone", "12345"))

    def test_domain(self):
        self.assertEqual(normalize("domain", "https://WWW.Example.COM./path").value, "example.com")
        self.assertEqual(normalize("domain", "*.mail.firma.com.ua").value, "mail.firma.com.ua")
        self.assertEqual(normalize("domain", "приклад.укр").value, "xn--80aikifvh.xn--j1amh")
        self.assertIn("platform", normalize("domain", "gist.github.com").flags)
        self.assertIsNone(normalize("domain", "localhost"))
        self.assertEqual(registered_domain("a.b.shop.com.ua"), "shop.com.ua")

    def test_ip(self):
        self.assertIn("cdn", normalize("ip", "104.16.1.1").flags)
        self.assertIsNone(normalize("ip", "192.168.1.1"))      # private: never a finding
        self.assertEqual(normalize("ip", "2001:4860:4860:0:0:0:0:8888").value, "2001:4860:4860::8888")

    def test_url_canonical(self):
        self.assertEqual(canonical_url("HTTP://Example.com:443//a/b/?utm_source=x&b=2&a=1#frag"),
                         "https://example.com/a/b?a=1&b=2")
        self.assertEqual(normalize("account", "https://www.github.com/Octocat/").key,
                         normalize("account", "github.com/octocat").key)

    def test_profile_url_shapes_merge(self):
        self.assertEqual(normalize("account", "https://nightowl.deviantart.com/").key,
                         normalize("account", "https://www.deviantart.com/nightowl").key)

    def test_username(self):
        self.assertEqual(normalize("username", "@Night_Owl").key, "username:night_owl")
        self.assertIn("generic", normalize("username", "admin").flags)

    def test_guess(self):
        self.assertEqual(guess_type("a@b.com"), "email")
        self.assertEqual(guess_type("+380671234567"), "phone")
        self.assertEqual(guess_type("firma.com.ua"), "domain")
        self.assertEqual(guess_type("night_owl"), "username")
        self.assertEqual(guess_type("8.8.8.8"), "ip")


# ─── Fake modules for engine tests ────────────────────────────────────────────
class FakeAccounts(Module):
    """username → accounts; the same email shows up from two different modules."""
    name, consumes, reliability, cost = "fake_accounts", ("username",), 1.0, 1

    def run(self, entity, ctx):
        r = Result()
        r.add("account", "https://github.com/" + entity["value"], "has_account", 0.9)
        r.add("account", "https://GitHub.com/" + entity["value"] + "/?utm_source=x", "has_account", 0.9)
        r.add("email", "Owl.Night+x@gmail.com", "profile_email", 0.5)
        r.add("username", "admin", "linked_username", 0.9)       # generic → must not expand
        r.add("email", "broken@", "profile_email", 0.9)          # invalid → dropped
        return r


class FakeEmail(Module):
    name, consumes, reliability, cost = "fake_email", ("email",), 1.0, 1

    def run(self, entity, ctx):
        r = Result(attrs={"checked": True})
        r.add("username", "owl_second", "local_part", 0.9)
        return r


class FakeConfirm(Module):
    """Second, independent source for the same email."""
    name, consumes, reliability, cost = "fake_confirm", ("username",), 0.8, 1

    def run(self, entity, ctx):
        r = Result()
        r.add("email", "owlnight@gmail.com", "profile_email", 0.5)
        return r


class Boom(Module):
    name, consumes, reliability, cost = "boom", ("username",), 1.0, 1

    def run(self, entity, ctx):
        raise RuntimeError("module crashed")


def make_engine(modules, **settings):
    tmp = tempfile.mkdtemp()
    store = Store(Path(tmp) / "t.db")
    eng = Engine(store, Path(tmp), registry={m.name: m for m in modules}, workers=4)
    case = store.create_case("test", "unit test", {"profile": "standard", **settings})
    return eng, store, case


for m in (FakeAccounts, FakeEmail, FakeConfirm, Boom):
    m.profiles = ("standard",)


class EngineTest(unittest.TestCase):
    def test_dedup_and_drop_invalid(self):
        eng, store, case = make_engine([FakeAccounts])
        eng.add_seed(case, "night_owl")
        eng.wait(case, poll=0.05, timeout=10)
        values = sorted(e["value"] for e in store.entities(case))
        self.assertEqual(values.count("https://github.com/night_owl"), 1)   # two spellings, one entity
        self.assertNotIn("broken@", " ".join(values))
        eng.shutdown()

    def test_corroboration_raises_confidence_and_unlocks_pivot(self):
        eng, store, case = make_engine([FakeAccounts, FakeConfirm, FakeEmail], auto_threshold=0.6)
        eng.add_seed(case, "night_owl")
        eng.wait(case, poll=0.05, timeout=10)
        email = store.entity_by_key(case, "email:owlnight@gmail.com")
        # 0.5 from one module + 0.4 from another → 1 − 0.5·0.6 = 0.7, above the threshold
        self.assertAlmostEqual(email["confidence"], 0.7, places=3)
        self.assertEqual(email["pivot"], "done")
        self.assertTrue(email["attrs"].get("checked"))
        eng.shutdown()

    def test_single_weak_source_is_only_suggested(self):
        eng, store, case = make_engine([FakeAccounts, FakeEmail])
        eng.add_seed(case, "night_owl")
        eng.wait(case, poll=0.05, timeout=10)
        email = store.entity_by_key(case, "email:owlnight@gmail.com")
        self.assertEqual(email["pivot"], "suggested")
        self.assertIsNone(store.entity_by_key(case, "username:owl_second"))
        eng.expand(email["id"])                        # analyst decides to dig
        eng.wait(case, poll=0.05, timeout=10)
        self.assertIsNotNone(store.entity_by_key(case, "username:owl_second"))
        eng.shutdown()

    def test_generic_and_depth_limits(self):
        eng, store, case = make_engine([FakeAccounts, FakeConfirm, FakeEmail], max_depth=1)
        eng.add_seed(case, "night_owl")
        eng.wait(case, poll=0.05, timeout=10)
        admin = store.entity_by_key(case, "username:admin")
        self.assertEqual(admin["pivot"], "blocked")
        email = store.entity_by_key(case, "email:owlnight@gmail.com")
        self.assertEqual(email["pivot"], "suggested")
        self.assertIn("глибина", email["pivot_reason"])
        eng.shutdown()

    def test_false_lead_is_not_resurrected(self):
        eng, store, case = make_engine([FakeAccounts, FakeEmail])
        eng.add_seed(case, "night_owl")
        eng.wait(case, poll=0.05, timeout=10)
        email = store.entity_by_key(case, "email:owlnight@gmail.com")
        eng.set_status(email["id"], "no")
        eng.expand(store.entity_by_key(case, "username:night_owl")["id"])
        eng.wait(case, poll=0.05, timeout=10)
        self.assertEqual(store.entity(email["id"])["status"], "no")
        tree = build_tree(store, case)
        self.assertNotIn("owl.night", json.dumps(tree))
        eng.shutdown()

    def test_module_crash_is_recorded_not_fatal(self):
        eng, store, case = make_engine([Boom, FakeAccounts])
        eng.add_seed(case, "night_owl")
        p = eng.wait(case, poll=0.05, timeout=10)
        self.assertEqual(p["error"], 1)
        self.assertGreater(p["done"], 0)
        eng.shutdown()

    def test_budget(self):
        eng, store, case = make_engine([FakeAccounts, FakeEmail], budget=1, auto_threshold=0.0)
        eng.add_seed(case, "night_owl")
        eng.wait(case, poll=0.05, timeout=10)
        email = store.entity_by_key(case, "email:owlnight@gmail.com")
        self.assertEqual(email["pivot"], "suggested")
        self.assertIn("бюджет", email["pivot_reason"])
        eng.shutdown()

    def test_offline_derivation_ignores_depth(self):
        from collector.modules.native import EmailParts
        eng, store, case = make_engine([FakeAccounts, EmailParts], max_depth=1, auto_threshold=0.0)
        eng.add_seed(case, "night_owl")
        eng.wait(case, poll=0.05, timeout=10)
        # The email sits at the depth limit, yet its free offline split still ran.
        self.assertIsNotNone(store.entity_by_key(case, "username:owl.night"))
        eng.shutdown()

    def test_delete_entity_takes_its_branch_but_keeps_corroborated(self):
        eng, store, case = make_engine([FakeAccounts, FakeConfirm])
        eng.add_seed(case, "night_owl")
        eng.add_seed(case, "other_owl")
        eng.wait(case, poll=0.05, timeout=10)
        seed = store.entity_by_key(case, "username:night_owl")
        gh = store.entity_by_key(case, "account:github.com/night_owl")
        shared = store.entity_by_key(case, "email:owlnight@gmail.com")   # found from both seeds
        r = eng.delete_entities(case, [seed["id"]])
        self.assertIsNone(store.entity(seed["id"]))
        self.assertIsNone(store.entity(gh["id"]))                   # only came from the deleted seed
        kept = store.entity(shared["id"])
        self.assertIsNotNone(kept)                                  # other_owl also points at it
        self.assertEqual(kept["parent_id"], store.entity_by_key(case, "username:other_owl")["id"])
        self.assertGreaterEqual(r["kept"], 1)
        eng.shutdown()

    def test_delete_file_seed_never_touches_disk(self):
        from collector.modules.files import FileFingerprint
        FileFingerprint.profiles = ("quick", "standard", "deep")
        d = Path(tempfile.mkdtemp())
        (d / "a.txt").write_text("hello world")
        eng, store, case = make_engine([FileFingerprint], profile="quick")
        e = eng.add_seed(case, str(d / "a.txt"), "file")
        eng.wait(case, poll=0.05, timeout=10)
        eng.delete_entities(case, [e["id"]])
        self.assertIsNone(store.entity(e["id"]))
        self.assertTrue((d / "a.txt").exists())
        eng.delete_case(case)
        self.assertIsNone(store.case(case))
        self.assertFalse((eng.data_dir / "cases" / str(case)).exists())
        eng.shutdown()

    def test_combine(self):
        self.assertEqual(combine({}), 0)
        self.assertAlmostEqual(combine({"a": 0.5, "b": 0.5}), 0.75)


class ExportTest(unittest.TestCase):
    def test_tree_is_valid_osint_graph(self):
        eng, store, case = make_engine([FakeAccounts, FakeConfirm, FakeEmail])
        eng.add_seed(case, "night_owl")
        eng.wait(case, poll=0.05, timeout=10)
        doc = build_tree(store, case)
        self.assertEqual(doc["format"], "osint-graph")
        ids = []

        def walk(n):
            for f in ("id", "name", "type", "url", "note", "status", "collapsed", "children"):
                self.assertIn(f, n)
            self.assertIn(n["status"], ("", "ok", "maybe", "no"))
            ids.append(n["id"])
            for c in n["children"]:
                walk(c)
        walk(doc["root"])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("type,value,status", to_csv(store, case))
        eng.shutdown()


class LocalModulesTest(unittest.TestCase):
    def test_loader_registers_local_modules(self):
        from collector.modules import load_local
        d = Path(tempfile.mkdtemp())
        (d / "mine.py").write_text(
            "from collector.modules.base import Module, Result\n"
            "class Mine(Module):\n"
            "    name, consumes, profiles = 'mine', ('username',), ('selfaudit',)\n"
            "    def run(self, entity, ctx):\n"
            "        return Result()\n"
            "MODULES = [Mine]\n")
        (d / "_skip.py").write_text("raise RuntimeError('must not be imported')\n")
        (d / "broken.py").write_text("this is not python\n")
        reg: dict = {}
        loaded = load_local(reg, [d])
        self.assertEqual(loaded, ["mine"])
        self.assertIn("mine", reg)

    def test_selfaudit_profile_includes_standard_and_opt_in(self):
        class OptIn(Module):
            name, consumes, profiles, cost = "opt_in", ("username",), ("selfaudit",), 1

            def run(self, entity, ctx):
                return Result()

        class DeepOnly(Module):
            name, consumes, profiles, cost = "deep_only", ("username",), ("deep",), 1

            def run(self, entity, ctx):
                return Result()

        eng, store, case = make_engine([FakeAccounts, OptIn, DeepOnly], profile="selfaudit")
        names = {m.name for m in eng._modules_for(eng.settings(case),
                                                  {"type": "username", "value": "x", "flags": []})}
        self.assertEqual(names, {"fake_accounts", "opt_in"})   # standard + opt-in, not deep-only
        eng.shutdown()

    def test_monitor_snapshot_stops_a_long_running_tool(self):
        path = Path(__file__).resolve().parents[1] / "collector" / "local" / "activity_monitors.py"
        if not path.exists():
            self.skipTest("local activity monitors not installed")
        import importlib.util
        import os
        import time
        spec = importlib.util.spec_from_file_location("am_test", path)
        am = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(am)
        am.SNAPSHOT_SECONDS = 2
        fake = Path(tempfile.mkdtemp()) / "fake_monitor.py"
        fake.write_text("import sys, time\n"
                        "print('Steam user ' + sys.argv[1] + ' status: online', flush=True)\n"
                        "print('Currently playing: Dota 2', flush=True)\n"
                        "print('Profile visibility: public', flush=True)\n"
                        "time.sleep(600)\n")
        os.environ["STEAM_MONITOR_BIN"] = str(fake)
        try:
            from collector.modules.base import Context
            t = time.time()
            r = am.SteamMonitor().run({"type": "username", "value": "owl", "flags": []},
                                      Context(fake.parent, env=dict(os.environ)))
            self.assertLess(time.time() - t, 15)             # did not hang on the endless tool
            acc = [f for f in r.findings if f.type == "account"]
            self.assertEqual(acc[0].value, "https://steamcommunity.com/id/owl")
            self.assertIn("видно стороннім", r.attrs["steam_monitor"])
            self.assertIn("Приватно", r.attrs["steam_monitor_cleanup"])
        finally:
            del os.environ["STEAM_MONITOR_BIN"]


class CompanyTest(unittest.TestCase):
    def test_email_pattern_and_names(self):
        from collector.modules.company import email_candidates, employees_result, parse_crosslinked
        self.assertEqual(email_candidates("Іван", "Петренко", "{first}.{last}@firma.ua"), "ivan.petrenko@firma.ua")
        self.assertEqual(email_candidates("Юлія", "Щербак", "{f}{last}@firma.ua"), "yshcherbak@firma.ua")
        self.assertEqual(email_candidates("Jürgen", "Müller", "{f}{last}@firma.de"), "jmuller@firma.de")
        rows = parse_crosslinked(
            '"t","google","Ivan Petrenko","CTO","https://ua.linkedin.com/in/ivanp","x",\n'
            '"t","bing","ivan petrenko","CTO","https://ua.linkedin.com/in/ivanp","x",\n'
            '"t","bing","LinkedIn","","",""\n')
        self.assertEqual(len(rows), 1)
        res = employees_result([*rows, {"firstname": "LinkedIn", "lastname": "Member"}],
                               "{first}.{last}@firma.ua", "LinkedIn")
        kinds = sorted((f.type, f.value) for f in res.findings)
        self.assertIn(("email", "ivan.petrenko@firma.ua"), kinds)
        self.assertIn(("person", "Ivan Petrenko"), kinds)
        self.assertEqual([f.confidence for f in res.findings if f.type == "email"], [0.3])  # triage only

    def test_company_page_is_an_org(self):
        n = normalize("org", "https://ua.linkedin.com/company/Acme/about/")
        self.assertEqual((n.type, n.value), ("org", "https://www.linkedin.com/company/Acme"))
        self.assertEqual(guess_type("https://www.xing.com/pages/acme"), "org")


class CompanyRunTest(unittest.TestCase):
    def _ctx(self, env=None):
        from collector.modules.base import Context
        d = Path(tempfile.mkdtemp())
        return Context(d, env={**os.environ, **(env or {})}), d

    def test_crosslinked_run_builds_args_and_parses(self):
        import os
        import stat
        from collector.modules.company import CrossLinked
        binp = Path(tempfile.mkdtemp())
        fake = binp / "crosslinked"
        fake.write_text("#!/usr/bin/env python3\n"
                        "import sys\n"
                        "o = sys.argv[sys.argv.index('-o')+1]\n"
                        "open(o+'.csv','w').write('\"t\",\"google\",\"Ivan Petrenko\",\"CTO\","
                        "\"https://ua.linkedin.com/in/ivanp\",\"x\",\\n')\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        ctx, _ = self._ctx({"PATH": str(binp) + os.pathsep + os.environ["PATH"],
                            "COLLECTOR_EMAIL_FORMAT": "{first}.{last}@firma.ua"})
        res = CrossLinked().run({"type": "org", "value": "Firma"}, ctx)
        vals = {(f.type, f.value) for f in res.findings}
        self.assertIn(("person", "Ivan Petrenko"), vals)
        self.assertIn(("email", "ivan.petrenko@firma.ua"), vals)
        self.assertTrue(res.raw)

    def test_dumper_run_builds_args_and_parses(self):
        import collector.modules.company as company
        from collector.modules.company import LinkedInDumper
        tools = Path(tempfile.mkdtemp())
        repo = tools / "LinkedInDumper"
        (repo / ".venv" / "bin").mkdir(parents=True)
        (repo / ".venv" / "bin" / "python").symlink_to(sys.executable)
        (repo / "linkedindumper.py").write_text(
            "import sys, json\n"
            "a = sys.argv\n"
            "assert '--url' in a and '--cookie' in a and '--jitter' in a and '--quiet' in a, a\n"
            "assert a[a.index('--url')+1] == 'https://www.linkedin.com/company/acme', a\n"
            "out = a[a.index('--output-json')+1]\n"
            "json.dump({'employees':["
            "  {'firstname':'Ivan','lastname':'Petrenko','position':'CTO','profile':'https://linkedin.com/in/ip'},"
            "  {'firstname':'Olena','lastname':'Koval','business_email':'olena@acme.io'}]}, open(out,'w'))\n")
        old = company.TOOLS_DIR
        company.TOOLS_DIR = tools
        try:
            self.assertTrue(LinkedInDumper._entry())
            ctx, _ = self._ctx({"LINKEDIN_LI_AT": "cookie123", "COLLECTOR_EMAIL_FORMAT": "{first}.{last}@acme.io"})
            res = LinkedInDumper().run(
                {"type": "org", "value": "https://www.linkedin.com/company/acme"}, ctx)
        finally:
            company.TOOLS_DIR = old
        emails = sorted(f.value for f in res.findings if f.type == "email")
        self.assertEqual(emails, ["ivan.petrenko@acme.io", "olena@acme.io"])  # generated + tool-provided
        self.assertEqual(res.attrs["employees_found"], 2)

    def test_dumper_without_cookie_reports_clearly(self):
        from collector.modules.company import XingDumper
        ok, why = XingDumper.available()
        self.assertFalse(ok)
        self.assertTrue("XING" in why or "XING_LOGIN_COOKIE" in why)


class FingerprintTest(unittest.TestCase):
    def test_metadata_fingerprints(self):
        from collector.modules.files import fingerprints
        r = fingerprints({"Make": "Canon", "Model": "Canon EOS 80D", "SerialNumber": "0123456",
                          "Artist": "Ivan Petrenko", "Author": "Windows User", "Company": "Firma LLC",
                          "DocumentID": "xmp.did:abc-1", "GPSLatitude": 50.4501, "GPSLongitude": 30.5234,
                          "Software": "Adobe Photoshop 25.1 (Macintosh)"})
        got = {(f.type, f.value) for f in r.findings}
        self.assertIn(("fingerprint", "камера Canon EOS 80D · серійний 0123456"), got)
        self.assertIn(("person", "Ivan Petrenko"), got)
        self.assertNotIn(("person", "Windows User"), got)          # generic author dropped
        self.assertIn(("org", "Firma LLC"), got)
        self.assertIn(("fingerprint", "XMP-документ abc-1"), got)
        self.assertIn(("location", "50.45010, 30.52340"), got)
        self.assertFalse(any(f.value.startswith("програма") and f.confidence > 0.5 for f in r.findings))

    def test_two_photos_from_one_camera_are_linked(self):
        import base64
        import shutil
        import subprocess
        if not shutil.which("exiftool"):
            self.skipTest("exiftool not installed")
        from collector.analysis import link_case
        from collector.modules.files import FileFingerprint
        d = Path(tempfile.mkdtemp())
        jpeg = base64.b64decode("/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////"
                                "////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAA"
                                "AAAAAAAAAAAAAP/aAAgBAQABPxA=")
        for name, comment in (("a.jpg", "one"), ("b.jpg", "two"), ("c.jpg", "three")):
            (d / name).write_bytes(jpeg)
            serial = "SN-777" if name != "c.jpg" else "SN-999"
            p = subprocess.run(["exiftool", "-q", "-overwrite_original", f"-SerialNumber={serial}", "-Make=Canon",
                                "-Model=Canon EOS 80D", f"-Comment={comment}", str(d / name)], capture_output=True)
            if p.returncode != 0:
                self.skipTest("exiftool could not write test metadata")
        FileFingerprint.profiles = ("quick", "standard", "deep")
        eng, store, case = make_engine([FileFingerprint], profile="quick")
        seed = eng.add_seed(case, str(d))
        self.assertEqual(seed["count"], 3)
        eng.wait(case, poll=0.05, timeout=30)
        rep = link_case(store, case)
        shared = [r for r in rep["shared"] if "SN-777" in r["what"]]
        self.assertEqual(shared[0]["files"], ["a.jpg", "b.jpg"])
        self.assertFalse(any("SN-999" in r["what"] for r in rep["shared"]))  # one file: no link
        eng.shutdown()


def _texts():
    """Two synthetic authors with different vocabulary and typing habits."""
    import random
    a_sent = ["ну ось я знову тут — і що далі…", "ось так воно і буває — нічого не поробиш…",
              "ну я ж казав — так і вийде…", "коротко кажучи — все погано…", "ось чому я і мовчу — бо сенсу нема…",
              "ну добре — подивимось завтра…", "мені це вже набридло — серйозно…", "ось і все — крапка…"]
    b_sent = ["Однак, якщо розглянути ситуацію ширше, то стає зрозуміло, що причини значно глибші, ніж здається на "
              "перший погляд...", "Проте варто зазначити, що подібні рішення ухвалюються, як правило, без "
              "належного обговорення, і це викликає занепокоєння...", "Втім, на мою думку, головна проблема полягає "
              "в тому, що відповідальність розмита між багатьма учасниками процесу...",
              "Зрештою, саме тому необхідно, щоб кожен крок був ретельно обґрунтований, задокументований і "
              "перевірений незалежними експертами..."]
    out = {}
    for author, pool in (("A", a_sent), ("B", b_sent)):
        for k in range(3):
            rnd = random.Random(f"{author}{k}")
            out[f"{author}{k}.txt"] = "\n".join(rnd.choice(pool) for _ in range(60 if author == "A" else 18))
    return out


class StylometryTest(unittest.TestCase):
    def test_same_author_scores_higher(self):
        from collector.analysis import profile, style_matrix
        m = style_matrix({k: profile(v) for k, v in _texts().items()})
        same = [s["score"] for (a, b), s in m.items() if a[0] == b[0]]
        cross = [s["score"] for (a, b), s in m.items() if a[0] != b[0]]
        self.assertGreater(min(same), max(cross))

    def test_link_case_finds_style_and_skips_short(self):
        from collector.analysis import link_case
        from collector.modules.files import FileFingerprint
        d = Path(tempfile.mkdtemp())
        for name, text in _texts().items():
            (d / name).write_text(text)
        (d / "short.txt").write_text("лише кілька слів тут")
        FileFingerprint.profiles = ("quick", "standard", "deep")
        eng, store, case = make_engine([FileFingerprint], profile="quick")
        eng.add_seed(case, str(d))
        eng.wait(case, poll=0.05, timeout=30)
        rep = link_case(store, case)
        self.assertEqual(rep["texts"], 6)
        self.assertIn("short.txt", rep["too_short"])
        pairs = {tuple(sorted((r["a"][0], r["b"][0]))) for r in rep["style"]}
        self.assertTrue(pairs)
        self.assertEqual(pairs, {("A", "A"), ("B", "B")})    # never links A with B
        eng.shutdown()


class MonitorDecisionTest(unittest.TestCase):
    def test_paths_do_not_count_as_private_and_unknown_is_reported(self):
        path = Path(__file__).resolve().parents[1] / "collector" / "local" / "activity_monitors.py"
        if not path.exists():
            self.skipTest("local activity monitors not installed")
        import importlib.util
        spec = importlib.util.spec_from_file_location("am_dec", path)
        am = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(am)
        am.SNAPSHOT_SECONDS = 2
        from collector.modules.base import Context
        fake = Path(tempfile.mkdtemp()) / "fake_monitor.py"
        fake.write_text("print('* Output directory: /private/var/folders/x', flush=True)\n"
                        "print('- loading profile from username...', flush=True)\n")
        os.environ["STEAM_MONITOR_BIN"] = str(fake)
        try:
            r = am.SteamMonitor().run({"type": "username", "value": "owl", "flags": []},
                                      Context(fake.parent, env=dict(os.environ)))
        finally:
            del os.environ["STEAM_MONITOR_BIN"]
        self.assertIn("не показав", r.attrs["steam_monitor"])
        self.assertEqual(r.findings, [])


class ServerTest(unittest.TestCase):
    def test_api_and_cross_origin_guard(self):
        import threading
        import urllib.error
        import urllib.request
        from http.server import ThreadingHTTPServer

        from collector.server import App, make_handler
        eng, store, case = make_engine([FakeAccounts])
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(App(store, eng)))
        except OSError as e:
            self.skipTest(f"local sockets unavailable: {e}")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_port}"

        def call(path, data=None, origin=None):
            req = urllib.request.Request(base + path, data=json.dumps(data).encode() if data is not None else None,
                                         headers={"Content-Type": "application/json",
                                                  **({"Origin": origin} if origin else {})})
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())
        try:
            self.assertEqual(call("/api/cases", {"name": "x"}, origin="https://evil.example")[0], 403)
            self.assertEqual(call(f"/api/cases/{case}/seeds", {"value": "night_owl"}, origin=base)[0], 201)
            eng.wait(case, poll=0.05, timeout=10)
            status, view = call(f"/api/cases/{case}")
            self.assertEqual(status, 200)
            self.assertTrue(any(e["type"] == "account" for e in view["entities"]))
            self.assertEqual(call(f"/api/cases/{case}/seeds", {"value": "!!"})[0], 400)
            self.assertEqual(call(f"/api/cases/{case}/link", {})[0], 200)   # link endpoint works
            acc = next(e for e in call(f"/api/cases/{case}")[1]["entities"] if e["type"] == "account")
            req = urllib.request.Request(f"{base}/api/entities/{acc['id']}", method="DELETE", headers={"Origin": base})
            with urllib.request.urlopen(req) as r:
                self.assertGreaterEqual(json.loads(r.read())["deleted"], 1)
            self.assertEqual(call(f"/api/cases/{case}/delete-entities", {"ids": []})[0], 200)
        finally:
            httpd.shutdown()
            eng.shutdown()


class ParserTest(unittest.TestCase):
    def test_maigret(self):
        report = {
            "GitHub": {"url_user": "https://github.com/owl", "is_similar": False, "rank": 30,
                       "status": {"status": "Claimed", "url": "https://github.com/owl",
                                  "ids": {"fullname": "Night Owl", "location": "Lviv"}, "tags": ["coding"]}},
            "Fuzzy": {"url_user": "https://fuzzy.example/owl", "is_similar": True,
                      "status": {"status": "Claimed", "url": "https://fuzzy.example/owl", "ids": {}}},
            "Absent": {"status": {"status": "Available", "url": "https://x.example/owl"}},
        }
        r = parse_maigret(report)
        acc = {f.value: f.confidence for f in r.findings if f.type == "account"}
        self.assertEqual(len(acc), 2)
        self.assertLess(acc["https://fuzzy.example/owl"], acc["https://github.com/owl"])
        self.assertTrue(any(f.type == "person" and f.value == "Night Owl" for f in r.findings))

    def test_sherlock(self):
        r = parse_sherlock("[+] GitHub: https://github.com/owl\nhttps://www.reddit.com/user/owl\n"
                           "Total Websites Username Detected On : 2\n")
        self.assertEqual([f.value for f in r.findings],
                         ["https://github.com/owl", "https://www.reddit.com/user/owl"])

    def test_holehe(self):
        text = ("name,domain,method,frequent_rate_limit,rateLimit,exists,emailrecovery,phoneNumber,others\n"
                "spotify,spotify.com,register,False,False,True,None,None,None\n"
                "twitter,twitter.com,other,False,False,False,None,None,None\n"
                "adobe,adobe.com,password recovery,False,False,True,ow****@gmail.com,None,None\n")
        r = parse_holehe(text, "owl@gmail.com")
        self.assertEqual(len(r.findings), 2)
        self.assertEqual(r.findings[1].attrs["recovery_hint"], "ow****@gmail.com")

    def test_subfinder(self):
        text = ('{"host":"a.firma.ua","sources":["crtsh","alienvault"]}\n'
                '{"host":"b.firma.ua","source":"crtsh"}\n{"host":"evil.com","source":"x"}\nnot json\n')
        r = parse_subfinder(text, "firma.ua")
        self.assertEqual([f.value for f in r.findings], ["a.firma.ua", "b.firma.ua"])
        self.assertGreater(r.findings[0].confidence, r.findings[1].confidence)

    def test_user_scanner(self):
        from collector.modules.tools import parse_user_scanner
        email_rows = [{"status": "Registered", "site_name": "Instagram", "url": "https://instagram.com", "extra": {}},
                      {"status": "Not Registered", "site_name": "Spotify", "url": "https://spotify.com"},
                      {"status": "Skipped", "site_name": "Payhip", "url": ""},
                      {"status": "Error", "site_name": "Patreon", "url": ""}]
        r = parse_user_scanner(email_rows, "email", "a@b.ua")
        self.assertEqual([f.value for f in r.findings], ["instagram.com · a@b.ua"])
        self.assertIn("пропущено 1", r.attrs["user_scanner"])
        user_rows = [{"status": "Found", "site_name": "Twitch", "url": "https://twitch.tv/owl", "extra": {"followers": 2}}]
        r = parse_user_scanner(user_rows, "username", "owl")
        self.assertEqual(r.findings[0].value, "https://twitch.tv/owl")
        from collector.modules.base import ModuleError
        with self.assertRaises(ModuleError):
            parse_user_scanner([{"status": "Error"}] * 7 + [{"status": "Not Found"}] * 3, "username", "owl")

    def test_maigret_canary_drops_sites_that_claim_anything(self):
        from collector.modules.tools import drop_false_positives, parse_maigret
        claimed = lambda url: {"status": {"status": "Claimed", "url": url, "ids": {}}}
        report = {"GitHub": claimed("https://github.com/owl"), "Upwork": claimed("https://upwork.com/fl/owl")}
        kept, bad = drop_false_positives(report, {"Upwork": claimed("https://upwork.com/fl/zqcanary")})
        self.assertEqual(bad, ["Upwork"])
        self.assertEqual([f.value for f in parse_maigret(kept).findings], ["https://github.com/owl"])

    def test_sherlock_canary(self):
        import os
        import stat
        from collector.modules.base import Context
        from collector.modules.tools import Sherlock
        binp = Path(tempfile.mkdtemp())
        fake = binp / "sherlock"
        fake.write_text("#!/usr/bin/env python3\n"
                        "import sys\n"
                        "for u in sys.argv[1:3]:\n"
                        "    print('[*] Checking username '+u+' on:')\n"
                        "    print('[+] Houzz: https://houzz.com/user/'+u)\n"
                        "    if not u.startswith('zq'): print('[+] GitHub: https://github.com/'+u)\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        env = {**os.environ, "PATH": str(binp) + os.pathsep + os.environ["PATH"]}
        old = os.environ["PATH"]
        os.environ["PATH"] = env["PATH"]
        try:
            r = Sherlock().run({"type": "username", "value": "owl", "flags": []},
                               Context(Path(tempfile.mkdtemp()), env=env))
        finally:
            os.environ["PATH"] = old
        self.assertEqual([f.value for f in r.findings], ["https://github.com/owl"])
        self.assertIn("houzz.com", r.attrs["sherlock_відкинуто"])

    def test_false_positive_memory(self):
        from collector.modules.base import Context
        from collector.modules.tools import FalsePositives, drop_false_positives
        d = Path(tempfile.mkdtemp())
        ctx = Context(d, env={"COLLECTOR_DATA": str(d)})
        FalsePositives(ctx, "maigret").add({"Upwork"})
        remembered = FalsePositives(ctx, "maigret").load()
        self.assertEqual(remembered, {"Upwork"})
        kept, bad = drop_false_positives({"Upwork": {}, "GitHub": {}}, {}, remembered)  # canary missed it this time
        self.assertEqual((list(kept), bad), (["GitHub"], ["Upwork"]))

    def test_holehe_all_rate_limited_is_an_error_not_a_clean_result(self):
        from collector.modules.base import ModuleError
        text = "name,domain,method,frequent_rate_limit,rateLimit,exists\n" + \
               "\n".join(f"s{i},s{i}.com,register,False,True,False" for i in range(10)) + "\n"
        with self.assertRaises(ModuleError):
            parse_holehe(text, "a@b.ua")

    def test_socid_profile_and_email_hash_link(self):
        import hashlib
        from collector.modules.enrich import parse_socid
        h = hashlib.sha256(b"owl@gmail.com").hexdigest()
        blocks = [{"url": "https://gitlab.com/owl", "info": {"uid": "1", "_extractor": "Gitlab"}},
                  {"url": "api", "info": {"fullname": "Night Owl", "country": "Ukraine", "created_at": "2025-06-12",
                                          "image": f"https://secure.gravatar.com/avatar/{h}?s=80",
                                          "website": "https://gitlab.com/owl"}}]
        r = parse_socid(blocks, "https://gitlab.com/owl", "owl")
        got = {(f.type, f.value) for f in r.findings}
        self.assertIn(("person", "Night Owl"), got)
        self.assertIn(("location", "Ukraine"), got)
        self.assertIn(("fingerprint", f"email-хеш sha256:{h}"), got)
        self.assertNotIn(("url", "https://gitlab.com/owl"), got)        # its own URL is not a new link
        self.assertEqual(r.attrs["created_at"], "2025-06-12")
        self.assertEqual(parse_socid([{"info": {"fullname": "D"}}], "u").findings, [])  # 1-letter names skipped

    def test_engine_joins_email_and_profile_by_hash(self):
        import hashlib
        h = hashlib.sha256(b"owl@gmail.com").hexdigest()

        class FakeProfile(Module):
            name, consumes, reliability, cost, profiles = "fake_profile", ("username",), 1.0, 1, ("standard",)

            def run(self, entity, ctx):
                r = Result()
                r.add("fingerprint", f"email-хеш sha256:{h}", "avatar_email_hash", 0.95)
                return r
        eng, store, case = make_engine([FakeProfile])
        eng.add_seed(case, "owl@gmail.com")
        eng.add_seed(case, "night_owl")
        eng.wait(case, poll=0.05, timeout=10)
        fp = store.entity_by_key(case, f"fingerprint:email-хеш sha256:{h}")
        self.assertEqual(fp["attrs"]["збіг_з_поштою"], "owl@gmail.com")
        eng.shutdown()

    def test_ignorant(self):
        from collector.modules.tools import parse_ignorant, split_cc
        self.assertEqual(split_cc("+380000000000"), ("380", "000000000"))
        self.assertEqual(split_cc("+14155550100"), ("1", "4155550100"))
        self.assertEqual(split_cc("+447700900123"), ("44", "7700900123"))
        r = parse_ignorant("\x1b[32m[+] instagram.com\x1b[0m\n[+] Phone number used, [-] Phone number not used\n"
                           "[-] snapchat.com\n", "+380000000000")
        self.assertEqual([f.value for f in r.findings], ["instagram.com · +380000000000"])

    def test_phoneinfoga_and_harvester(self):
        attrs = parse_phoneinfoga("Results for local\nLocal: 067 123 4567\nCountry: UA\nCarrier: \n")
        self.assertEqual(attrs["country"], "UA")
        self.assertNotIn("carrier", attrs)
        r = parse_harvester({"emails": ["a@firma.ua"], "hosts": ["mail.firma.ua:1.2.3.4", "x.other.com"]},
                            "firma.ua")
        self.assertEqual(sorted(f.value for f in r.findings), ["a@firma.ua", "mail.firma.ua"])


if __name__ == "__main__":
    unittest.main()
