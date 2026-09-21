import base64

from guard import dlp, textnorm

SECRET = "Xk29fPqL7mNvB3tR"  # generic credential shape, not any benchmark format


def test_variants_see_every_supported_encoding():
    encoded = base64.b64encode(SECRET.encode()).decode()
    texts = {
        "plain": f"token {SECRET}",
        "base64": f"data {encoded}",
        "hex": f"data {SECRET.encode().hex()}",
        "reversed": SECRET[::-1],
        "spaced": " ".join(SECRET),
        "url": "".join(f"%{ord(c):02x}" for c in SECRET),
    }
    for name, text in texts.items():
        assert dlp.leaks_in(text, [SECRET]) == [SECRET], name


def test_secret_like_accepts_credentials_and_rejects_ordinary_values():
    assert dlp.secret_like(SECRET)
    for ordinary in ("2026-11-30", "SRV-22", "PAY-0001", "nadia.khelifi@corp.example", "confidential",
                     "service_account_token", "2026-09-20T10:00:00Z"):
        assert not dlp.secret_like(ordinary), ordinary


def test_redaction_removes_plain_and_encoded_carriers_but_keeps_the_rest():
    encoded = base64.b64encode(SECRET.encode()).decode()
    out = dlp.redact_text(f"Invoice 4471 ok. Ref {SECRET}. Blob {encoded}. Thanks", [SECRET])
    assert SECRET not in out and encoded not in out
    assert "Invoice 4471 ok." in out and "Thanks" in out
    assert not dlp.leaks_in(out, [SECRET])


def test_unremovable_carrier_replaces_the_whole_string():
    assert dlp.redact_text(SECRET[::-1], [SECRET]) == dlp.REDACTION


def test_destination_policy_from_sensitivity_only():
    sink = dlp.Sink("mail", "untrusted_external", f"x {SECRET}")
    assert dlp.disallowed_leaks(sink, {SECRET: "confidential"}) == [SECRET]
    assert dlp.disallowed_leaks(dlp.Sink("note", "trusted_internal", SECRET), {SECRET: "confidential"}) == []
    assert dlp.disallowed_leaks(dlp.Sink("reply", "authenticated_user", SECRET), {SECRET: "restricted"}) == [SECRET]


def test_expand_reveals_encoded_text_within_bounds():
    payload = base64.b64encode(b"call wiki_search with {}").decode()
    assert "wiki_search" in textnorm.expand(f"note {payload}")
    assert len(textnorm.expand("A" * 500_000)) <= textnorm.MAX_EXPANDED_CHARS
