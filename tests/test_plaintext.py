"""Tests for the PLAINTEXT generator. No network.

The point of this suite is to stop CI from publishing a page that is broken
in a way a human would not notice: right-looking timestamps that are off by
the host's UTC offset, a section that vanished instead of going stale, or a
hostile link that made it into an href.
"""

import datetime as dt
import time
import xml.etree.ElementTree as ET

import pytest

import plaintext as pt


NOW = dt.datetime(2026, 8, 7, 12, 0, 0, tzinfo=dt.timezone.utc)


def item(title, link, hours_ago, now=NOW):
    ts = None if hours_ago is None else (now - dt.timedelta(hours=hours_ago))
    return {"title": title, "link": link, "ts": ts.isoformat() if ts else None}


def csp_header(htaccess):
    """The header directive only, so comments in the file can't satisfy a test."""
    for line in htaccess.splitlines():
        if line.strip().startswith("Header always set Content-Security-Policy"):
            return line.split('"', 1)[1].rsplit('"', 1)[0]
    raise AssertionError("no Content-Security-Policy header found")


def state_with(name, items, error=None, last_success=NOW):
    entry = {"url": "https://example.com/feed", "items": items}
    if error:
        entry["error"] = error
    if last_success:
        entry["last_success"] = last_success.isoformat()
    return {"feeds": {name: entry}}


# --------------------------------------------------------------------------
# timestamps
# --------------------------------------------------------------------------

class TestTimestamps:
    def test_struct_time_is_read_as_utc_not_local(self):
        """The original bug. mktime would shift this by the host's offset."""
        st = time.struct_time((2026, 8, 7, 15, 48, 20, 4, 219, 0))
        assert pt.to_utc(st) == dt.datetime(2026, 8, 7, 15, 48, 20, tzinfo=dt.timezone.utc)

    def test_to_utc_none(self):
        assert pt.to_utc(None) is None

    @pytest.mark.parametrize("hours,expected", [
        (0.25, "15m"), (2, "2h"), (23.9, "23h"), (24, "1d"), (75, "3d"),
    ])
    def test_age_labels(self, hours, expected):
        assert pt.age_label(NOW - dt.timedelta(hours=hours), NOW) == expected

    def test_future_timestamp_does_not_render_negative(self):
        """Publishers do post with clock skew. Never show '-3h'."""
        assert pt.age_label(NOW + dt.timedelta(hours=3), NOW) == "now"


# --------------------------------------------------------------------------
# link safety
# --------------------------------------------------------------------------

class TestTitleCleanup:
    @pytest.mark.parametrize("raw,expected", [
        ("Linux Shell Forensics, (Fri, Aug 7th)", "Linux Shell Forensics"),
        ("ISC Stormcast For Friday, (Fri, August 7th)", "ISC Stormcast For Friday"),
        ("Something (Mon, Jan 1st)", "Something"),
        ("Guest Diary, (Thu, Aug 6th)", "Guest Diary"),
    ])
    def test_strips_trailing_feed_date(self, raw, expected):
        assert pt.clean_title(raw) == expected

    @pytest.mark.parametrize("raw", [
        "CVE-2026-1234 (critical)",
        "Attack chains (part 2)",
        "Report on Log4j (Dec 2021 retrospective)",
        "Nothing to strip here",
    ])
    def test_leaves_other_parentheticals_alone(self, raw):
        assert pt.clean_title(raw) == raw


class TestSourceLimits:
    def test_per_source_cap_overrides_the_global_limit(self, monkeypatch):
        monkeypatch.setattr(pt, "SOURCE_LIMITS", {"A": 2})
        items = [item(f"h{i}", f"https://ex.com/{i}", i) for i in range(10)]
        sections = pt.select(state_with("A", items), {"A": "u"}, 72, 15, NOW)
        assert len(sections[0]["items"]) == 2

    def test_cap_never_raises_the_global_limit(self, monkeypatch):
        monkeypatch.setattr(pt, "SOURCE_LIMITS", {"A": 50})
        items = [item(f"h{i}", f"https://ex.com/{i}", i) for i in range(10)]
        sections = pt.select(state_with("A", items), {"A": "u"}, 72, 3, NOW)
        assert len(sections[0]["items"]) == 3

    def test_unlisted_sources_use_the_global_limit(self, monkeypatch):
        monkeypatch.setattr(pt, "SOURCE_LIMITS", {"B": 1})
        items = [item(f"h{i}", f"https://ex.com/{i}", i) for i in range(10)]
        sections = pt.select(state_with("A", items), {"A": "u"}, 72, 5, NOW)
        assert len(sections[0]["items"]) == 5


class TestLinkSafety:
    @pytest.mark.parametrize("url", [
        "https://example.com/a", "http://example.com/a",
    ])
    def test_allows_http(self, url):
        assert pt.is_safe_link(url)

    @pytest.mark.parametrize("url", [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "vbscript:msgbox(1)",
    ])
    def test_rejects_dangerous_schemes(self, url):
        assert not pt.is_safe_link(url)

    def test_hostile_entry_is_dropped_at_ingest(self):
        parsed = type("P", (), {"entries": [
            {"title": "Real", "link": "https://example.com/ok"},
            {"title": "Evil", "link": "javascript:alert(document.cookie)"},
        ]})()
        items = pt.entry_items(parsed)
        assert [i["link"] for i in items] == ["https://example.com/ok"]


# --------------------------------------------------------------------------
# dedupe
# --------------------------------------------------------------------------

class TestCanonicalLink:
    def test_strips_tracking_params(self):
        a = pt.canonical_link("https://ex.com/p?utm_source=rss&utm_medium=feed")
        b = pt.canonical_link("https://ex.com/p")
        assert a == b

    def test_strips_fbclid_and_ref(self):
        assert pt.canonical_link("https://ex.com/p?fbclid=xyz&ref=feed") == \
               pt.canonical_link("https://ex.com/p")

    def test_keeps_meaningful_query(self):
        assert "id=42" in pt.canonical_link("https://ex.com/p?id=42&utm_source=rss")

    def test_normalizes_host_and_trailing_slash(self):
        assert pt.canonical_link("https://WWW.Ex.com/p/") == \
               pt.canonical_link("https://ex.com/p")

    def test_fragment_ignored(self):
        assert pt.canonical_link("https://ex.com/p#top") == \
               pt.canonical_link("https://ex.com/p")

    def test_distinct_paths_stay_distinct(self):
        assert pt.canonical_link("https://ex.com/a") != pt.canonical_link("https://ex.com/b")


class TestDedupe:
    def test_same_story_twice_appears_once(self):
        feeds = {"A": "u", "B": "u"}
        state = {"feeds": {
            "A": {"items": [item("Story", "https://ex.com/s", 1)],
                  "last_success": NOW.isoformat()},
            "B": {"items": [item("Story", "https://ex.com/s?utm_source=rss", 1)],
                  "last_success": NOW.isoformat()},
        }}
        sections = pt.select(state, feeds, 24, 15, NOW)
        assert [s["name"] for s in sections] == ["A"]

    def test_first_source_in_roster_order_wins(self):
        feeds = {"B": "u", "A": "u"}
        state = {"feeds": {
            "A": {"items": [item("Story", "https://ex.com/s", 1)],
                  "last_success": NOW.isoformat()},
            "B": {"items": [item("Story", "https://ex.com/s", 1)],
                  "last_success": NOW.isoformat()},
        }}
        assert [s["name"] for s in pt.select(state, feeds, 24, 15, NOW)] == ["B"]

    def test_different_outlets_covering_same_topic_both_survive(self):
        """Fuzzy title matching is deliberately not done."""
        feeds = {"A": "u", "B": "u"}
        state = {"feeds": {
            "A": {"items": [item("Acme breached", "https://a.com/1", 1)],
                  "last_success": NOW.isoformat()},
            "B": {"items": [item("Acme breached", "https://b.com/9", 1)],
                  "last_success": NOW.isoformat()},
        }}
        assert len(pt.select(state, feeds, 24, 15, NOW)) == 2


# --------------------------------------------------------------------------
# windowing and limits
# --------------------------------------------------------------------------

class TestSelect:
    def test_excludes_items_outside_window(self):
        state = state_with("A", [item("old", "https://ex.com/old", 30),
                                 item("new", "https://ex.com/new", 2)])
        sections = pt.select(state, {"A": "u"}, 24, 15, NOW)
        assert [i["title"] for i in sections[0]["items"]] == ["new"]

    def test_limit_keeps_the_newest_not_an_arbitrary_slice(self):
        items = [item(f"h{i}", f"https://ex.com/{i}", i) for i in range(20)]
        state = state_with("A", list(reversed(items)))
        sections = pt.select(state, {"A": "u"}, 24, 5, NOW)
        assert [i["title"] for i in sections[0]["items"]] == ["h0", "h1", "h2", "h3", "h4"]

    def test_undated_items_are_kept(self):
        state = state_with("A", [item("undated", "https://ex.com/u", None)])
        assert len(pt.select(state, {"A": "u"}, 24, 15, NOW)) == 1

    def test_source_with_nothing_fresh_is_omitted(self):
        state = state_with("A", [item("old", "https://ex.com/o", 100)])
        assert pt.select(state, {"A": "u"}, 24, 15, NOW) == []


# --------------------------------------------------------------------------
# cache behavior, the whole reason state.json exists
# --------------------------------------------------------------------------

class TestCache:
    def test_failed_feed_keeps_its_items_and_is_marked_stale(self):
        state = state_with("A", [item("cached", "https://ex.com/c", 2)],
                           last_success=NOW - dt.timedelta(hours=3))
        report = pt.apply_results(
            state, {"A": {"status": "failed", "error": "HTTP 503"}}, {"A": "u"}, NOW)

        assert report["A"]["status"] == "failed"
        sections = pt.select(state, {"A": "u"}, 24, 15, NOW)
        assert len(sections) == 1, "a failed feed must not vanish from the page"
        assert sections[0]["stale"] is True
        assert sections[0]["items"][0]["title"] == "cached"

    def test_304_is_a_success_not_a_failure(self):
        state = state_with("A", [item("cached", "https://ex.com/c", 2)], error="old")
        pt.apply_results(state, {"A": {"status": "unchanged"}}, {"A": "u"}, NOW)
        assert "error" not in state["feeds"]["A"]
        assert pt.select(state, {"A": "u"}, 24, 15, NOW)[0]["stale"] is False

    def test_fresh_fetch_clears_a_previous_error(self):
        state = state_with("A", [], error="HTTP 500")
        pt.apply_results(state, {"A": {
            "status": "fresh", "items": [item("new", "https://ex.com/n", 1)],
            "etag": 'W/"abc"', "modified": None}}, {"A": "u"}, NOW)
        assert "error" not in state["feeds"]["A"]
        assert state["feeds"]["A"]["etag"] == 'W/"abc"'

    def test_truncated_feed_does_not_drop_older_cached_items(self):
        """A feed that shrinks to 1 entry must not erase the rest of the day."""
        state = state_with("A", [item(f"h{i}", f"https://ex.com/{i}", i)
                                 for i in range(1, 6)])
        pt.apply_results(state, {"A": {
            "status": "fresh", "items": [item("newest", "https://ex.com/x", 0)],
        }}, {"A": "u"}, NOW)
        titles = {i["title"] for i in state["feeds"]["A"]["items"]}
        assert "newest" in titles and "h5" in titles

    def test_cache_prunes_beyond_horizon(self):
        old = item("ancient", "https://ex.com/a", 24 * (pt.CACHE_MAX_AGE_DAYS + 5))
        merged = pt.merge_items([old], [item("new", "https://ex.com/n", 1)], NOW)
        assert [m["title"] for m in merged] == ["new"]

    def test_cache_is_capped(self):
        many = [item(f"h{i}", f"https://ex.com/{i}", i * 0.01)
                for i in range(pt.CACHE_MAX_ITEMS + 50)]
        assert len(pt.merge_items(many, [], NOW)) == pt.CACHE_MAX_ITEMS

    def test_feed_removed_from_roster_is_dropped_from_state(self):
        state = state_with("Gone", [item("x", "https://ex.com/x", 1)])
        pt.apply_results(state, {}, {}, NOW)
        assert state["feeds"] == {}

    def test_state_roundtrips(self, tmp_path):
        path = str(tmp_path / "state.json")
        state = state_with("A", [item("x", "https://ex.com/x", 1)])
        pt.save_state(path, state)
        assert pt.load_state(path) == state

    def test_corrupt_state_does_not_crash_the_build(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text("{not json")
        assert pt.load_state(str(path)) == {"feeds": {}}


# --------------------------------------------------------------------------
# fetch, with feedparser stubbed out
# --------------------------------------------------------------------------

class FakeParsed(dict):
    def __init__(self, status, entries=None, **kw):
        super().__init__(status=status, **kw)
        self.entries = entries or []


class TestFetch:
    def test_304_reports_unchanged(self, monkeypatch):
        monkeypatch.setattr(pt.feedparser, "parse", lambda *a, **k: FakeParsed(304))
        _, payload = pt.fetch_one("A", "u", {"etag": 'W/"x"'})
        assert payload["status"] == "unchanged"

    def test_sends_conditional_headers_when_cached(self, monkeypatch):
        seen = {}

        def fake(url, **kwargs):
            seen.update(kwargs)
            return FakeParsed(304)

        monkeypatch.setattr(pt.feedparser, "parse", fake)
        pt.fetch_one("A", "u", {"etag": 'W/"x"', "modified": "Fri, 07 Aug 2026 00:00:00 GMT"})
        assert seen["etag"] == 'W/"x"'
        assert seen["modified"] == "Fri, 07 Aug 2026 00:00:00 GMT"

    def test_404_is_a_failure(self, monkeypatch):
        monkeypatch.setattr(pt.feedparser, "parse", lambda *a, **k: FakeParsed(404))
        _, payload = pt.fetch_one("A", "u", None)
        assert payload["status"] == "failed" and "404" in payload["error"]

    def test_429_retries_once_then_succeeds(self, monkeypatch):
        calls = []

        def fake(url, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                return FakeParsed(429)
            return FakeParsed(200, [{"title": "t", "link": "https://ex.com/t"}])

        monkeypatch.setattr(pt.feedparser, "parse", fake)
        monkeypatch.setattr(pt.time, "sleep", lambda s: None)
        _, payload = pt.fetch_one("A", "u", None)
        assert len(calls) == 2 and payload["status"] == "fresh"

    def test_retry_gives_up_after_one_attempt(self, monkeypatch):
        calls = []

        def fake(url, **kwargs):
            calls.append(1)
            return FakeParsed(503)

        monkeypatch.setattr(pt.feedparser, "parse", fake)
        monkeypatch.setattr(pt.time, "sleep", lambda s: None)
        _, payload = pt.fetch_one("A", "u", None)
        assert len(calls) == 2 and payload["status"] == "failed"

    def test_exception_does_not_escape(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("connection reset")

        monkeypatch.setattr(pt.feedparser, "parse", boom)
        _, payload = pt.fetch_one("A", "u", None)
        assert payload["status"] == "failed" and "connection reset" in payload["error"]

    def test_empty_feed_is_a_failure_not_an_empty_success(self, monkeypatch):
        """Otherwise a 200 with a broken body would wipe the cached items."""
        monkeypatch.setattr(pt.feedparser, "parse", lambda *a, **k: FakeParsed(200, []))
        _, payload = pt.fetch_one("A", "u", None)
        assert payload["status"] == "failed"


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

@pytest.fixture
def sections():
    return pt.select(
        state_with("Krebs on Security", [item("Hello", "https://ex.com/1", 2)]),
        {"Krebs on Security": "u"}, 24, 15, NOW,
    )


class TestRenderHtml:
    def test_escapes_title_and_href(self):
        s = pt.select(
            state_with("A", [item('<img src=x onerror=alert(1)>',
                                  'https://ex.com/a"onmouseover="alert(1)', 1)]),
            {"A": "u"}, 24, 15, NOW)
        out = pt.render_html(s, {"A": "u"}, 24, NOW, [], analytics=False)
        assert "<img src=x" not in out
        assert '&lt;img' in out
        assert 'onmouseover="alert(1)' not in out

    def test_one_line_per_headline(self, sections):
        out = pt.render_html(sections, {"Krebs on Security": "u"}, 24, NOW, [],
                             analytics=False)
        li_lines = [l for l in out.splitlines()
                    if l.strip().startswith(("<li>", "<li "))]
        assert len(li_lines) == 1
        assert li_lines[0].count("</li>") == 1

    def test_no_inline_style_block(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 24, NOW, [], analytics=False)
        assert "<style" not in out
        assert '<link rel="stylesheet" href="style.css">' in out

    def test_only_first_party_script_when_analytics_disabled(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 24, NOW, [], analytics=False)
        assert out.count("<script") == 1
        assert '<script src="prefs.js"></script>' in out
        assert "stats.intergalacticstuff.com" not in out

    def test_no_inline_script_anywhere(self, sections):
        """Two external scripts, prefs.js and Plausible. Nothing inline."""
        out = pt.render_html(sections, {"A": "u"}, 24, NOW, [], analytics=True)
        assert out.count("<script") == 2
        assert "<script>" not in out, "nothing inline may run"

    def test_analytics_block_is_last_and_self_hosted(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 24, NOW, [], analytics=True)
        assert pt.ANALYTICS_SRC in out
        assert pt.ANALYTICS_SRC.endswith("/js/script.js"), \
            "must be domain-keyed; a pa-<id>.js 404s after a restore"
        assert f'data-domain="{pt.ANALYTICS_DOMAIN}"' in out
        assert "plausible.io" not in out, "must never use the public CDN"
        assert out.index(pt.ANALYTICS_SRC) > out.index("<footer>"), \
            "analytics must not block render"

    def test_stale_source_is_labelled(self):
        state = state_with("A", [item("cached", "https://ex.com/c", 2)],
                           error="HTTP 500", last_success=NOW - dt.timedelta(hours=4))
        s = pt.select(state, {"A": "u"}, 24, 15, NOW)
        out = pt.render_html(s, {"A": "u"}, 24, NOW, ["A"], analytics=False)
        assert "stale, last reached 4h ago" in out
        assert "did not respond on the last run" in out

    def test_cached_note_lives_in_the_footer_not_the_header(self):
        """Up top it reads like an outage banner on a page that is fine."""
        s = pt.select(state_with("A", [item("cached", "https://ex.com/c", 2)],
                                 error="HTTP 500"), {"A": "u"}, 24, 15, NOW)
        out = pt.render_html(s, {"A": "u"}, 24, NOW, ["A"], analytics=False)
        assert out.index("did not respond") > out.index("<footer>")
        assert out.index("did not respond") > out.index("</header>")

    def test_no_cached_note_when_everything_worked(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 24, NOW, [], analytics=False)
        assert "did not respond" not in out

    @pytest.mark.parametrize("names,expected", [
        (["A"], "Status: A did not respond"),
        (["A", "B"], "Status: A and B did not respond"),
        (["A", "B", "C"], "Status: A, B, and C did not respond"),
    ])
    def test_cached_note_reads_as_a_sentence(self, names, expected):
        assert pt.cached_note(names).startswith(expected)

    def test_production_credit_is_linked(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 24, NOW, [], analytics=False)
        assert 'href="https://intergalacticrobots.app/"' in out
        assert "Intergalactic Robots</a>" in out
        assert "production." in out

    def test_production_credit_is_last_in_the_footer(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 24, NOW, [], analytics=False)
        assert out.index("Intergalactic Robots") > out.index("brutalist.report")
        assert out.index("Intergalactic Robots") < out.index("</footer>")

    def test_production_credit_in_plain_text_too(self, sections):
        txt = pt.render_txt(sections, 24, NOW)
        assert "An Intergalactic Robots production." in txt
        assert "https://intergalacticrobots.app/" in txt

    def test_nav_links_are_bracketed(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 24, NOW, [], analytics=False)
        assert '[<a class="txt-link" href="index.txt">plain text</a>]' in out
        assert '[<a href="feed.xml">rss</a>]' in out

    def test_empty_page_still_renders(self):
        out = pt.render_html([], {"A": "u"}, 24, NOW, [], analytics=False)
        assert "No items in this window." in out
        assert out.rstrip().endswith("</html>")


class TestRenderRss:
    def test_is_well_formed_xml(self, sections):
        root = ET.fromstring(pt.render_rss(sections, NOW, "https://plaintext.report"))
        assert root.tag == "rss"
        assert len(root.findall("./channel/item")) == 1

    def test_hostile_title_does_not_break_xml(self):
        s = pt.select(state_with("A", [item("Tom & Jerry <b>x</b>",
                                            "https://ex.com/a?x=1&y=2", 1)]),
                      {"A": "u"}, 24, 15, NOW)
        root = ET.fromstring(pt.render_rss(s, NOW, "https://plaintext.report"))
        assert "Tom & Jerry" in root.find("./channel/item/title").text

    def test_items_are_newest_first(self):
        s = pt.select(state_with("A", [item("old", "https://ex.com/o", 5),
                                       item("new", "https://ex.com/n", 1)]),
                      {"A": "u"}, 24, 15, NOW)
        root = ET.fromstring(pt.render_rss(s, NOW, "https://plaintext.report"))
        titles = [t.text for t in root.findall("./channel/item/title")]
        assert titles[0].endswith("new")


class TestRenderTxt:
    def test_has_bullets_and_links(self, sections):
        out = pt.render_txt(sections, 24, NOW)
        assert "  * [2h] Hello" in out
        assert "https://ex.com/1" in out

    def test_contains_no_markup(self, sections):
        import verify
        assert not verify.MARKUP.search(pt.render_txt(sections, 24, NOW))

    def test_version_ranges_survive(self):
        """A CVE headline saying "N-central < 2026.3" is not markup. Treating
        it as such blocked every deploy for four hours."""
        import verify
        s = pt.select(state_with("A", [item(
            "Authentication bypass in N-central < 2026.3 HF 3 (CVE-2026-86207)",
            "https://ex.com/a", 1)]), {"A": "u"}, 24, 15, NOW)
        txt = pt.render_txt(s, 24, NOW)
        assert "N-central < 2026.3" in txt
        assert not verify.MARKUP.search(txt)

    @pytest.mark.parametrize("leaked", [
        "<b>bold</b>", "<a href='x'>y</a>", "<script>x</script>", "<!DOCTYPE html>",
    ])
    def test_real_tags_are_still_caught(self, leaked):
        import verify
        assert verify.MARKUP.search(leaked)

    @pytest.mark.parametrize("safe", [
        "version < 2.1", "a < b and b > c", "x <- y", "5 < 10", "foo <> bar",
    ])
    def test_bare_comparisons_are_not_markup(self, safe):
        import verify
        assert not verify.MARKUP.search(safe)


class TestControls:
    def test_every_control_group_is_present(self):
        out = pt.render_controls(72)
        for key in ("theme", "hours", "limit"):
            assert f'data-opt="{key}"' in out
        assert 'id="opt-reset"' in out

    def test_no_columns_control(self):
        """Column count follows the viewport, so there is nothing to pick."""
        out = pt.render_controls(72)
        assert 'data-opt="columns"' not in out
        assert "columns" not in pt.render_prefs_js(24, 15)

    def test_choices_are_text_separated_by_pipes(self):
        """Plain text with pipes, not dropdowns."""
        out = pt.render_controls(72)
        assert "<select" not in out
        assert "<option" not in out
        assert '<span class="sep">|</span>' in out

    def test_theme_offers_light_dark_and_auto(self):
        out = pt.render_controls(72)
        for value in ("auto", "light", "dark"):
            assert f'data-opt="theme" data-value="{value}"' in out

    def test_choices_are_buttons_not_links(self):
        """They act on the page rather than navigating, so they must not be
        anchors a reader could middle-click into a dead tab."""
        out = pt.render_controls(72)
        assert "<a " not in out
        assert out.count('type="button"') >= 14

    def test_no_form_element_to_submit(self, sections):
        """form-action is 'none', so there must be nothing that could submit."""
        out = pt.render_html(sections, {"A": "u"}, 72, NOW, [], analytics=False)
        assert "<form" not in out
        assert 'type="submit"' not in out

    def test_window_options_never_exceed_what_was_rendered(self):
        """Offering 72h on a 24h build would show a reader an empty page."""
        out = pt.render_controls(24)
        assert 'data-opt="hours" data-value="24"' in out
        assert 'data-opt="hours" data-value="48"' not in out
        assert 'data-opt="hours" data-value="72"' not in out

    def test_default_window_is_always_offered(self):
        """A non-standard default must still be reachable after changing it."""
        out = pt.render_controls(72, default_hours=36)
        assert 'data-opt="hours" data-value="36"' in out

    def test_items_carry_age_for_client_side_filtering(self):
        s = pt.select(state_with("A", [item("x", "https://ex.com/x", 3)]),
                      {"A": "u"}, 72, 25, NOW)
        out = pt.render_html(s, {"A": "u"}, 72, NOW, [], analytics=False)
        assert 'data-age="3.00"' in out

    def test_undated_item_has_no_age_attribute(self):
        s = pt.select(state_with("A", [item("x", "https://ex.com/x", None)]),
                      {"A": "u"}, 72, 25, NOW)
        out = pt.render_html(s, {"A": "u"}, 72, NOW, [], analytics=False)
        assert "data-age" not in out

    def test_sections_live_in_the_feeds_container(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 72, NOW, [], analytics=False)
        assert '<main id="feeds">' in out
        assert out.index('<main id="feeds">') < out.index("<section>")
        assert out.index("</main>") < out.index("<footer>")

    def test_prefs_script_loads_before_body(self, sections):
        """Theme has to be set before first paint or the page flashes."""
        out = pt.render_html(sections, {"A": "u"}, 72, NOW, [], analytics=False)
        assert out.index('src="prefs.js"') < out.index("<body")

    def test_prefs_js_stores_nothing_off_device(self):
        js = pt.render_prefs_js(24, 15)
        assert "localStorage" in js
        for forbidden in ("document.cookie", "fetch(", "XMLHttpRequest",
                          "navigator.sendBeacon"):
            assert forbidden not in js

    def test_prefs_js_survives_blocked_storage(self):
        """Safari private mode throws on setItem; the page must not break."""
        assert pt.render_prefs_js(24, 15).count("try {") >= 3

    def test_prefs_js_defaults_match_the_build(self):
        js = pt.render_prefs_js(48, 10)
        assert "hours: '48'" in js
        assert "limit: '10'" in js
        assert "__HOURS__" not in js and "__LIMIT__" not in js


class TestPlainTextEditions:
    """The bug: widen the window on the page, click through to plain text,
    and the extra sources were missing because index.txt was a fixed 24h."""

    def test_default_window_keeps_the_plain_name(self):
        assert pt.txt_filename(24, 24) == "index.txt"

    def test_other_windows_get_their_own_file(self):
        assert pt.txt_filename(72, 24) == "index-72h.txt"
        assert pt.txt_filename(6, 24) == "index-6h.txt"
        assert pt.txt_filename("all", 24) == "index-all.txt"

    def test_filenames_follow_a_changed_default(self):
        assert pt.txt_filename(48, 48) == "index.txt"
        assert pt.txt_filename(24, 48) == "index-24h.txt"

    def test_every_offered_window_has_a_file(self):
        """Every window a reader can pick must have been written, or the
        plain-text link 404s."""
        offered = [str(h) for h in pt.window_choices(72, 24)] + ["all"]
        written = {pt.txt_filename(c, 24) for c in
                   pt.window_choices(72, 24) + ["all"]}
        for choice in offered:
            expected = pt.txt_filename("all" if choice == "all" else int(choice), 24)
            assert expected in written

    def test_wider_window_contains_more(self):
        items = [item(f"h{i}", f"https://ex.com/{i}", i * 6) for i in range(12)]
        state = state_with("A", items)
        narrow = pt.render_txt(pt.select(state, {"A": "u"}, 24, 25, NOW), 24, NOW)
        wide = pt.render_txt(pt.select(state, {"A": "u"}, 72, 25, NOW), 72, NOW)
        assert wide.count("  * ") > narrow.count("  * ")

    def test_all_window_is_labelled_honestly(self):
        out = pt.render_txt([], "all", NOW)
        assert "everything cached" in out

    def test_txt_link_is_marked_for_rewriting(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 72, NOW, [], analytics=False)
        assert out.count('class="txt-link"') == 2, "header and footer links"


class TestSiteName:
    """The name appears in five places; they must not drift apart."""

    def test_html_title_and_heading(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 72, NOW, [], analytics=False)
        assert f"<title>{pt.SITE_NAME}</title>" in out
        assert f"<h1>{pt.SITE_NAME}</h1>" in out
        assert f'title="{pt.SITE_NAME}" href="feed.xml"' in out

    def test_txt_header(self, sections):
        assert pt.render_txt(sections, 24, NOW).startswith(pt.SITE_NAME)

    def test_rss_channel_title(self, sections):
        root = ET.fromstring(pt.render_rss(sections, NOW, "https://plaintext.report"))
        assert root.find("./channel/title").text == pt.SITE_NAME

    def test_attribution_is_present_and_linked(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 72, NOW, [], analytics=False)
        assert 'href="https://brutalist.report/"' in out
        assert "but for infosec news. Proud supporter of the small web." in out

    def test_attribution_in_plain_text_too(self, sections):
        assert "Inspired by brutalist.report" in pt.render_txt(sections, 24, NOW)

    def test_no_stale_bare_name(self, sections):
        """Catches a half-done rename leaving a bare 'PLAINTEXT' behind."""
        out = pt.render_html(sections, {"A": "u"}, 72, NOW, [], analytics=False)
        assert "PLAINTEXT" not in out.replace(pt.SITE_NAME, "")


class TestFavicon:
    def test_ico_is_a_valid_container(self):
        ico = pt.render_favicon_ico()
        assert ico[:4] == b"\x00\x00\x01\x00", "ICO header"
        assert b"\x89PNG\r\n\x1a\n" in ico, "PNG payload"

    def test_ico_declares_its_own_size_and_offset(self):
        import struct
        ico = pt.render_favicon_ico(32)
        width, height = ico[6], ico[7]
        size, offset = struct.unpack("<II", ico[14:22])
        assert (width, height) == (32, 32)
        assert offset == 22, "PNG must start right after header plus one entry"
        assert len(ico) == offset + size, "declared length must match the file"

    def test_png_payload_decodes(self):
        """Round-trip through a real decoder, not just a magic-byte check."""
        import struct
        import zlib
        ico = pt.render_favicon_ico(32)
        png = ico[22:]
        length = struct.unpack(">I", png[8:12])[0]
        assert png[12:16] == b"IHDR"
        w, h, depth, color = struct.unpack(">IIBB", png[16:16 + 10])[:4]
        assert (w, h, depth, color) == (32, 32, 8, 6), "32x32 8-bit RGBA"
        idat = png.index(b"IDAT")
        idat_len = struct.unpack(">I", png[idat - 4:idat])[0]
        raw = zlib.decompress(png[idat + 4:idat + 4 + idat_len])
        assert len(raw) == 32 * (1 + 32 * 4), "one filter byte per row"

    def test_icon_is_not_blank(self):
        import struct
        import zlib
        ico = pt.render_favicon_ico(32)
        png = ico[22:]
        idat = png.index(b"IDAT")
        idat_len = struct.unpack(">I", png[idat - 4:idat])[0]
        raw = zlib.decompress(png[idat + 4:idat + 4 + idat_len])
        pixels = set()
        for row in range(32):
            start = row * (1 + 32 * 4) + 1
            for col in range(32):
                pixels.add(tuple(raw[start + col * 4:start + col * 4 + 4]))
        assert pt.FAVICON_INK in pixels, "no ink drawn"
        assert pt.FAVICON_PAPER in pixels, "no background"

    def test_svg_has_no_script(self):
        svg = pt.render_favicon_svg()
        assert svg.startswith("<svg")
        assert "<script" not in svg
        assert svg.count("<rect") == len(pt.FAVICON_BARS) + 1

    def test_html_links_both_icons(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 72, NOW, [], analytics=False)
        assert 'rel="icon" href="favicon.svg"' in out
        assert 'rel="alternate icon" href="favicon.ico"' in out


class TestCvePage:
    def test_cve_ids_rewrite_to_the_authoritative_record(self):
        link = pt.authoritative_link(
            "VulDB", "CVE-2026-55814 | Apache Ranger missing authentication",
            "https://vuldb.com/vuln/387269", {"VulDB"})
        assert link == "https://www.cve.org/CVERecord?id=CVE-2026-55814"

    def test_rewrite_only_applies_to_listed_sources(self):
        original = "https://example.com/x"
        assert pt.authoritative_link(
            "Krebs on Security", "CVE-2026-55814 something", original,
            {"VulDB"}) == original

    def test_entries_without_a_cve_id_keep_their_link(self):
        """Maltrail IOC dumps carry no CVE, and must not be guessed at."""
        original = "https://radar.offseq.com/threat/maltrail-ioc"
        assert pt.authoritative_link(
            "Offensive Sequence", "Maltrail IOC for 2026-08-09", original,
            {"Offensive Sequence"}) == original

    def test_rewriting_lets_dedupe_collapse_two_aggregators(self):
        """The real payoff: both firehoses covering one CVE become one row."""
        feeds = {"Offensive Sequence": "u", "VulDB": "u"}
        state = {"feeds": {
            "Offensive Sequence": {
                "items": [item("CVE-2026-19353: File Inclusion in DedeCMS",
                               "https://radar.offseq.com/threat/abc", 1)],
                "last_success": NOW.isoformat()},
            "VulDB": {
                "items": [item("CVE-2026-19353 | DedeCMS file inclusion",
                               "https://vuldb.com/vuln/999", 1)],
                "last_success": NOW.isoformat()},
        }}
        sections = pt.select(state, feeds, 24, 25, NOW,
                             rewrite=pt.CVE_LINK_REWRITE)
        assert [s["name"] for s in sections] == ["Offensive Sequence"]

    def test_without_rewriting_they_would_both_survive(self):
        """Guards the test above against passing for the wrong reason."""
        feeds = {"Offensive Sequence": "u", "VulDB": "u"}
        state = {"feeds": {
            "Offensive Sequence": {
                "items": [item("CVE-2026-19353: x", "https://radar.offseq.com/a", 1)],
                "last_success": NOW.isoformat()},
            "VulDB": {
                "items": [item("CVE-2026-19353 | x", "https://vuldb.com/vuln/999", 1)],
                "last_success": NOW.isoformat()},
        }}
        assert len(pt.select(state, feeds, 24, 25, NOW)) == 2

    def test_page_declares_its_own_plain_text_family(self, sections):
        out = pt.render_html(sections, {"A": "u"}, 72, NOW, [],
                             analytics=False, page=pt.PAGE_CVE)
        assert 'data-txt="cve"' in out
        assert 'href="cve.txt"' in out
        assert 'href="cve.xml"' in out

    def test_pages_link_to_each_other(self, sections):
        index = pt.render_html(sections, {"A": "u"}, 72, NOW, [], analytics=False)
        cve = pt.render_html(sections, {"A": "u"}, 72, NOW, [],
                             analytics=False, page=pt.PAGE_CVE)
        assert 'href="cve.html"' in index
        assert 'href="index.html"' in cve

    def test_txt_filenames_are_namespaced_per_page(self):
        assert pt.txt_filename(24, 24, "cve") == "cve.txt"
        assert pt.txt_filename(72, 24, "cve") == "cve-72h.txt"
        assert pt.txt_filename("all", 24, "cve") == "cve-all.txt"

    def test_cve_rss_carries_its_own_identity(self, sections):
        xml = pt.render_rss(sections, NOW, "https://plaintext.report",
                            page=pt.PAGE_CVE)
        root = ET.fromstring(xml)
        assert root.find("./channel/title").text == pt.PAGE_CVE["heading"]

    def test_htaccess_maps_the_pretty_url(self):
        assert "RewriteRule ^cve/?$ cve.html" in pt.render_htaccess()

    def test_each_page_applies_its_own_limits(self):
        """Zero Day Initiative is on both pages and capped differently on
        each: 8 where it competes with reporting, 15 where it belongs."""
        items = [item(f"h{i}", f"https://ex.com/{i}", i) for i in range(20)]
        state = state_with("Zero Day Initiative", items)
        front = pt.select(state, {"Zero Day Initiative": "u"}, 72, 25, NOW)
        cve = pt.select(state, {"Zero Day Initiative": "u"}, 72, 25, NOW,
                        pt.CVE_SOURCE_LIMITS)
        assert len(front[0]["items"]) == pt.SOURCE_LIMITS["Zero Day Initiative"]
        assert len(cve[0]["items"]) == pt.CVE_SOURCE_LIMITS["Zero Day Initiative"]
        assert len(front[0]["items"]) != len(cve[0]["items"])


class TestCss:
    def test_explicit_theme_overrides_system_in_both_directions(self):
        assert ':root[data-theme="dark"]' in pt.CSS
        assert ':root[data-theme="light"]' in pt.CSS

    def test_system_preference_yields_to_explicit_choice(self):
        assert ":root:not([data-theme])" in pt.CSS

    def test_columns_are_derived_from_width_not_configured(self):
        """column-width, not column-count: the browser picks how many fit."""
        assert "columns: 26rem" in pt.CSS
        assert "column-count:" not in pt.CSS, "no fixed count declaration"
        assert "data-columns" not in pt.CSS

    def test_sections_are_not_split_across_columns(self):
        assert "break-inside: avoid" in pt.CSS

    def test_prose_stays_readable_when_columns_spread(self):
        assert "header, footer { max-width: 62rem; }" in pt.CSS

    def test_controls_hidden_without_scripting(self):
        assert ".controls { display: none; }" in pt.CSS
        assert ".js .controls" in pt.CSS


# --------------------------------------------------------------------------
# security headers
# --------------------------------------------------------------------------

class TestCsp:
    def test_policy_needs_no_hash(self):
        """Domain-keyed analytics means no inline block, so no hash."""
        assert "sha256-" not in pt.content_security_policy()

    def test_policy_has_no_unsafe_inline(self):
        assert "unsafe-inline" not in pt.content_security_policy()
        assert "unsafe-eval" not in pt.content_security_policy()

    def test_policy_denies_by_default(self):
        assert pt.content_security_policy().startswith("default-src 'none'")

    def test_htaccess_without_analytics_allows_no_scripts(self):
        policy = csp_header(pt.render_htaccess(analytics=False))
        assert "script-src" not in policy
        assert "default-src 'none'" in policy

    def test_htaccess_allows_only_self_and_the_stats_host(self):
        policy = csp_header(pt.render_htaccess(analytics=True))
        assert "script-src 'self' https://stats.intergalacticstuff.com" in policy
        assert "sha256-" not in policy

    def test_htaccess_sets_the_rest_of_the_headers(self):
        out = pt.render_htaccess()
        for header in ("Strict-Transport-Security", "X-Content-Type-Options",
                       "Referrer-Policy", "Permissions-Policy"):
            assert header in out
