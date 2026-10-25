import os

from analyzers import entropy
from analyzers.honey import HoneyRegistry
from detection.rules import Window, evaluate
from contracts import EntropyResult, FileEvent, FileOp, HoneyHit, RiskLevel


def test_entropy_random_vs_text():
    assert entropy.shannon(os.urandom(8192)) > 7.9
    assert entropy.shannon(b"hello world " * 500) < 4.0
    assert entropy.shannon(b"") == 0.0
    assert entropy.shannon(bytes(range(256)) * 10) <= 8.0


def test_type_mismatch_and_double_extension():
    assert entropy.type_mismatch("a.docx", b"PK\x03\x04rest") is False
    assert entropy.type_mismatch("a.docx", os.urandom(100)) is True
    assert entropy.type_mismatch("a.docx.locked", os.urandom(100)) is True
    assert entropy.type_mismatch("a.txt", os.urandom(2000)) is True
    assert entropy.type_mismatch("a.txt", b"plain text here") is False


def test_analyze_reports_jump(tmp_path):
    p = tmp_path / "n.txt"
    p.write_bytes(b"some words here " * 200)
    base = entropy.analyze(str(p)).shannon
    p.write_bytes(os.urandom(4000))
    r = entropy.analyze(str(p), previous=base)
    assert r.delta > 3 and r.type_mismatch and "entropy rose" in r.detail
    assert entropy.analyze(str(tmp_path / "missing.txt")) is None


def test_honey_registry(tmp_path):
    h = HoneyRegistry()
    made = h.deploy(str(tmp_path), 3)
    assert len(made) == 3 and all(h.is_honey(p) for p in made)
    assert not h.is_honey(str(tmp_path / "other.txt"))
    h.rename(made[0], made[0] + ".locked")
    assert h.is_honey(made[0] + ".locked") and not h.is_honey(made[0])


def _attack_window(n=20, honey=True):
    ev, ent = [], []
    for i in range(n):
        old, new = f"/d/f{i}.txt", f"/d/f{i}.txt.locked"
        ev += [FileEvent(op=FileOp.MODIFY, path=old), FileEvent(op=FileOp.RENAME, path=old, new_path=new)]
        ent.append(EntropyResult(path=new, shannon=7.9, previous_shannon=4.0, delta=3.9, type_mismatch=True))
    hits = [HoneyHit(path="/d/_x.csv", op=FileOp.MODIFY)] if honey else []
    return Window(events=ev, entropy=ent, honey=hits)


def test_rules_attack_is_high_or_critical():
    a = evaluate(_attack_window())
    assert a.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert {s.name for s in a.signals} >= {"modification_rate", "honey_file_touched"}


def test_rules_benign_bulk_copy_not_high():
    ev = [FileEvent(op=FileOp.MODIFY, path=f"/d/f{i}.txt") for i in range(200)]
    ent = [EntropyResult(path=f"/d/f{i}.txt", shannon=4.5, previous_shannon=4.4, delta=0.1) for i in range(200)]
    assert evaluate(Window(events=ev, entropy=ent)).level in (RiskLevel.LOW, RiskLevel.MEDIUM)


def test_rules_honey_alone_is_not_high_and_notes_uncertainty():
    a = evaluate(Window(honey=[HoneyHit(path="/d/_x.csv", op=FileOp.MODIFY)]))
    assert a.level == RiskLevel.MEDIUM
    assert any("honey" in u.lower() for u in a.uncertainty)


def test_rename_is_not_double_counted():
    a = evaluate(_attack_window(n=10, honey=False))
    rate = next(s for s in a.signals if s.name == "modification_rate")
    assert rate.value == 1.0  # 10 files in a 10s window, not 20
