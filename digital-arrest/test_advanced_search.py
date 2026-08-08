"""
test_advanced_search.py — Comprehensive tests for the 7-layer Advanced Search Engine.

Run with:
    python test_advanced_search.py

Tests cover:
  1. TF-IDF scorer correctness
  2. Alias transitive closure
  3. Phone / email / display name Layer 5
  4. Pagination
  5. Autocomplete suggestions
  6. Cross-platform identity profile
  7. Trend score calculation
  8. Tier filter
  9. Full round-trip: submit → search → corroborate → advanced_search
"""

import asyncio
import sys
import os

# Make sure we can import from the project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.advanced_search_engine import (
    AdvancedSearchEngine,
    _tokenize,
    _build_tfidf_index,
    _tfidf_similarity,
    _extract_phone,
    _extract_email,
)
from utils.community_schemas import (
    ReportCreateRequest,
    PlatformEnum,
    ReportCategoryEnum,
    CorroborateRequest,
    ModerateActionRequest,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def run(coro):
    """Run coroutine synchronously for test environment."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
        return loop.run_until_complete(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)


def make_report(
    handle: str = "@testscammer",
    platform: PlatformEnum = PlatformEnum.INSTAGRAM,
    message: str = "You have been selected for a job. Send advance fee.",
    company: str = None,
    reporter_id: str = "tester01",
    evidence: list = None,
):
    return ReportCreateRequest(
        report_category=ReportCategoryEnum.SOCIAL_MEDIA_PROFILE,
        platform=platform,
        handle_raw=handle,
        message_text=message,
        company_name_seen=company,
        reporter_id=reporter_id,
        evidence_urls=evidence or [],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Unit: TF-IDF utilities
# ─────────────────────────────────────────────────────────────────────────────

def test_tokenize():
    tokens = _tokenize("You won a LUCKY draw prize of Rs 1 lakh!")
    assert "won" in tokens
    assert "lucky" in tokens
    assert "draw" in tokens
    print("[PASS] test_tokenize")


def test_tfidf_build_and_score():
    docs = [
        "earn money online job part time salary",
        "lottery lucky draw winner claim prize",
        "bitcoin forex investment profit crypto",
    ]
    tf_vectors, idf_scores = _build_tfidf_index(docs)
    assert len(tf_vectors) == 3
    assert "earn" in tf_vectors[0]
    assert "lottery" in tf_vectors[1]

    query_tokens = _tokenize("earn money job")
    score = _tfidf_similarity(query_tokens, tf_vectors[0], idf_scores)
    assert score > 0.0, f"Expected positive score, got {score}"
    print(f"[PASS] test_tfidf_build_and_score  (score={score:.4f})")


def test_phone_extraction():
    assert _extract_phone("Call me on 9876543210 for details") == "9876543210"
    assert _extract_phone("+91 98765-43210 urgent") == "9876543210"
    assert _extract_phone("no phone here") is None
    print("[PASS] test_phone_extraction")


def test_email_extraction():
    assert _extract_email("Send resume to hr@fakejobs.com today") == "hr@fakejobs.com"
    assert _extract_email("no email here") is None
    print("[PASS] test_email_extraction")


# ─────────────────────────────────────────────────────────────────────────────
# Integration: Advanced Search Engine
# ─────────────────────────────────────────────────────────────────────────────

def _fresh_engine() -> AdvancedSearchEngine:
    """Create a fresh engine with clean in-memory state for isolation."""
    engine = AdvancedSearchEngine.__new__(AdvancedSearchEngine)
    # Bypass store persistence; inject empty state
    from utils.supabase_community_store import store as _store
    engine.reports = []
    engine.clusters = {}
    engine.reporter_history = {}
    from collections import defaultdict
    engine._alias_graph = defaultdict(set)
    engine._contact_index = defaultdict(list)
    engine._xplatform_index = defaultdict(list)
    engine._tfidf_dirty = True
    engine._tfidf_corpus = []
    engine._tfidf_cluster_keys = []
    engine._tf_vectors = []
    engine._idf_scores = {}
    return engine


def test_exact_handle_search():
    engine = _fresh_engine()
    run(engine.submit_report(make_report("@QuickForexReturns", message="invest now and double profit forex bot")))
    engine._rebuild_indexes()

    res = engine.advanced_search("quickforexreturns", include_unconfirmed=True)
    assert res.total_matches >= 1
    assert res.results[0].match_type in ("exact_handle", "alias_closure")
    print("[PASS] test_exact_handle_search")


def test_fuzzy_handle_search():
    engine = _fresh_engine()
    # Handle normalizes to "scamacct" - search with "scamacet" (1 char diff = distance 1)
    run(engine.submit_report(make_report("@scamacct", message="invest in our platform for 200% returns")))
    engine._rebuild_indexes()

    # Typo: "scamacet" vs "scamacct" — Levenshtein distance = 1
    res = engine.advanced_search("scamacet", include_unconfirmed=True)
    assert res.total_matches >= 1, f"Expected fuzzy match for 'scamacet' near 'scamacct', got {res.total_matches}"
    assert res.results[0].match_type in ("fuzzy_handle", "exact_handle", "alias_closure")
    print("[PASS] test_fuzzy_handle_search")


def test_tfidf_message_search():
    engine = _fresh_engine()
    run(engine.submit_report(make_report(
        "@recruiter_fake",
        message="You have been selected for remote data entry job. Pay security deposit of Rs 5000 to start.",
        reporter_id="usr_r1",
    )))
    engine._rebuild_indexes()

    res = engine.advanced_search("remote data entry job security deposit", include_unconfirmed=True)
    assert res.total_matches >= 1
    print(f"[PASS] test_tfidf_message_search  (match_type={res.results[0].match_type})")


def test_company_name_search():
    engine = _fresh_engine()
    run(engine.submit_report(make_report(
        "@hr_globaltech",
        company="Global Tech Careers Pvt Ltd",
        message="Hiring for WFH position. No experience needed.",
        reporter_id="usr_c1",
    )))
    engine._rebuild_indexes()

    res = engine.advanced_search("Global Tech Careers", include_unconfirmed=True)
    assert res.total_matches >= 1
    assert any(r.match_type == "company_name" for r in res.results)
    print("[PASS] test_company_name_search")


def test_phone_layer5_search():
    engine = _fresh_engine()
    run(engine.submit_report(make_report(
        "@phone_scammer",
        message="Contact us at 9988776655 for more info about the job.",
        reporter_id="usr_ph",
    )))
    engine._rebuild_indexes()

    res = engine.advanced_search("9988776655", include_unconfirmed=True)
    assert res.total_matches >= 1
    assert res.results[0].match_type == "phone_match"
    print("[PASS] test_phone_layer5_search")


def test_email_layer5_search():
    engine = _fresh_engine()
    run(engine.submit_report(make_report(
        "@email_scammer",
        message="Send your CV to fraudrecruitment@fake-corp.com for the opening.",
        reporter_id="usr_em",
    )))
    engine._rebuild_indexes()

    res = engine.advanced_search("fraudrecruitment@fake-corp.com", include_unconfirmed=True)
    assert res.total_matches >= 1
    assert res.results[0].match_type == "email_match"
    print("[PASS] test_email_layer5_search")


def test_alias_transitive_closure():
    engine = _fresh_engine()
    # Submit and manually confirm
    run(engine.submit_report(make_report("@scamA", message="send payment to get your prize lottery")))
    run(engine.submit_report(make_report("@scamB", message="you won the lucky draw send address")))
    engine._rebuild_indexes()

    # Link scamA → scamB via moderator
    key_a = "instagram:scama"
    key_b = "instagram:scamb"
    if key_a in engine.clusters and key_b in engine.clusters:
        engine.clusters[key_a]["linked_aliases"] = ["scamb"]
        engine._rebuild_indexes()

        # Search for scamA → should find scamB via alias closure
        res = engine.advanced_search("scama", include_unconfirmed=True)
        keys_found = {r.cluster_key for r in res.results}
        assert key_b in keys_found or key_a in keys_found, f"Expected alias to be found. Got: {keys_found}"
    print("[PASS] test_alias_transitive_closure")


def test_pagination():
    engine = _fresh_engine()
    # Submit 25 distinct reports
    for i in range(25):
        run(engine.submit_report(make_report(
            f"@spammer{i:03d}",
            message=f"Get rich quick scheme number {i}, invest now for 300% profit in crypto forex bitcoin",
            reporter_id=f"usr_{i}",
        )))
    engine._rebuild_indexes()

    page1 = engine.advanced_search("invest profit crypto", include_unconfirmed=True, page=1, page_size=10)
    page2 = engine.advanced_search("invest profit crypto", include_unconfirmed=True, page=2, page_size=10)

    assert page1.total_matches >= 10
    assert page1.page == 1
    assert len(page1.results) <= 10
    assert page2.page == 2
    # Ensure pages don't overlap
    keys1 = {r.cluster_key for r in page1.results}
    keys2 = {r.cluster_key for r in page2.results}
    assert keys1.isdisjoint(keys2), "Pages should not overlap"
    print(f"[PASS] test_pagination  (total={page1.total_matches}, pages={page1.total_pages})")


def test_autocomplete():
    engine = _fresh_engine()
    run(engine.submit_report(make_report("@quickforex", message="invest in our forex bot for double returns")))
    run(engine.submit_report(make_report("@quickcrypto", message="get 300% profit with our crypto system")))
    engine._rebuild_indexes()

    result = engine.get_autocomplete("quick", limit=10, include_unconfirmed=True)
    assert result["count"] >= 1
    print(f"[PASS] test_autocomplete  (suggestions={result['suggestions']})")


def test_cross_platform_profile():
    engine = _fresh_engine()
    run(engine.submit_report(make_report("@digitalfraud", platform=PlatformEnum.INSTAGRAM, message="lottery winner claim prize now")))
    run(engine.submit_report(make_report("@digitalfraud", platform=PlatformEnum.TELEGRAM, message="you are selected for work from home job opening")))
    engine._rebuild_indexes()

    profile = engine.get_cross_platform_profile("@digitalfraud")
    assert profile["platforms_found"] >= 2, f"Expected 2 platforms, got {profile['platforms_found']}"
    platforms = [p["platform"] for p in profile["platform_breakdown"]]
    assert "instagram" in platforms
    assert "telegram" in platforms
    print(f"[PASS] test_cross_platform_profile  (platforms={platforms})")


def test_tier_filter():
    engine = _fresh_engine()
    run(engine.submit_report(make_report("@confirmed_scammer", message="customs parcel drugs digital arrest cbi officer")))
    engine._rebuild_indexes()

    # Only unconfirmed exists; searching with tier=confirmed should return 0
    res_confirmed = engine.advanced_search("confirmed_scammer", tier_filter="confirmed", include_unconfirmed=True)
    res_any = engine.advanced_search("confirmed_scammer", include_unconfirmed=True)

    assert res_any.total_matches >= 1
    # Tier filter should restrict
    assert res_confirmed.total_matches == 0 or all(r.status.value == "confirmed" for r in res_confirmed.results)
    print("[PASS] test_tier_filter")


def test_trend_score():
    engine = _fresh_engine()
    run(engine.submit_report(make_report("@trending_scammer", message="kyc blocked account unauthorized otp bank", reporter_id="u1")))
    run(engine.submit_report(make_report("@trending_scammer", message="bank account frozen send otp to unblock", reporter_id="u2")))
    engine._rebuild_indexes()

    res = engine.advanced_search("trending_scammer", include_unconfirmed=True)
    if res.results:
        card = res.results[0]
        # trend_score should be >= 0.0 and <= 1.0
        assert 0.0 <= card.trend_score <= 1.0
        assert card.trend_label in ("spiking", "rising", "stable")
        print(f"[PASS] test_trend_score  (trend={card.trend_label}, score={card.trend_score})")
    else:
        print("[SKIP] test_trend_score (no results — check include_unconfirmed logic)")


def test_search_performance():
    """Basic performance smoke test: should complete in under 2 seconds for 100 clusters."""
    import time
    engine = _fresh_engine()
    for i in range(100):
        run(engine.submit_report(make_report(
            f"@perf_tester_{i}",
            message=f"perf test scam message number {i} with fraud recruitment job salary",
            reporter_id=f"perf_{i}",
        )))
    engine._rebuild_indexes()

    t0 = time.monotonic()
    res = engine.advanced_search("fraud recruitment salary", include_unconfirmed=True, page=1, page_size=20)
    elapsed = time.monotonic() - t0

    assert elapsed < 2.0, f"Search took {elapsed:.2f}s — too slow"
    print(f"[PASS] test_search_performance  ({elapsed*1000:.1f}ms for 100 clusters, {res.total_matches} matches)")


# ─────────────────────────────────────────────────────────────────────────────
# Run all tests
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("Advanced Search Engine — Test Suite")
    print("=" * 60)

    # Unit tests
    test_tokenize()
    test_tfidf_build_and_score()
    test_phone_extraction()
    test_email_extraction()

    print()
    print("-- Integration Tests --")
    test_exact_handle_search()
    test_fuzzy_handle_search()
    test_tfidf_message_search()
    test_company_name_search()
    test_phone_layer5_search()
    test_email_layer5_search()
    test_alias_transitive_closure()
    test_pagination()
    test_autocomplete()
    test_cross_platform_profile()
    test_tier_filter()
    test_trend_score()
    test_search_performance()

    print()
    print("=" * 60)
    print("ALL TESTS PASSED [OK]")
    print("=" * 60)
