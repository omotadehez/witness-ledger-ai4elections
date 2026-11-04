"""
Distributed Witness Ledger - prototype v0.4 (adds sealed submissions)
#AI4Elections Hackathon | Track: Electoral Cybersecurity and Resilience

SYNTHETIC DATA ONLY. Never point this at a live electoral system.

Layers:
  1. Integrity ledger : Merkle tree over result hashes, publicly verifiable
  2. Witness quorum   : k-of-n independent witnesses must agree, drawn from at
                        least `min_groups` different groups (parties, observers)
                        Late submissions catch up round by round (offline-first)
  3. Insider monitor  : flags suspicious staff access
  4. NEW adversarial tests:
       A. colluding witnesses (sweep) - plain k-of-n vs k-of-n + group diversity
       B. regional outage + tampering - does it fail safe?
       C. forged signature / stolen key
  6. NEW sealed submissions: witnesses commit their hash BEFORE INEC publishes,
     so there is nothing to copy; attackers must pre-plan every alteration
  5. AI layer: a novelty-detection model (robust Mahalanobis) learns normal
     witness behaviour from a trusted rehearsal, flags copy-like witnesses, and the
     ledger revokes them, so a silent quorum breach becomes a human-review case

Witnesses hash the TRANSCRIBED FIGURES from their own signed copy, not photo
bytes (two photos of one sheet never hash the same).

Run in Colab: paste into a cell and press play. To change settings, put this at
the top of the cell:
  import sys; sys.argv = ["x", "--pus", "1000", "--witnesses", "9", "--k", "5"]
"""
import argparse
import copy
import hashlib
import hmac
import json
import random
import statistics
from collections import Counter

try:  # AI layer; preinstalled on Colab
    from sklearn.covariance import EllipticEnvelope
    HAVE_SK = True
except ImportError:
    HAVE_SK = False

try:  # real signatures if available (preinstalled on Colab)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_ED = True
except ImportError:  # fallback keeps the demo runnable anywhere
    HAVE_ED = False

PARTIES = ["P1", "P2", "P3", "P4"]
GROUPS = ["PartyA", "PartyB", "Observers", "Universities", "CivilSociety"]


# ---------- helpers ----------
def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(pu_id, scores):
    """Canonical text of a result sheet's figures. This is what gets hashed."""
    return "|".join([pu_id] + [f"{p}:{scores[p]}" for p in PARTIES])


class Signer:
    """One independent witness (or INEC) holding its own key."""

    def __init__(self, name, rng, group="-"):
        self.name, self.group = name, group
        if HAVE_ED:
            self._sk = Ed25519PrivateKey.generate()
            self._pk = self._sk.public_key()
        else:
            self._secret = rng.randbytes(32)

    def sign(self, msg: bytes) -> bytes:
        if HAVE_ED:
            return self._sk.sign(msg)
        return hmac.new(self._secret, msg, "sha256").digest()

    def verify(self, msg: bytes, sig: bytes) -> bool:
        if HAVE_ED:
            try:
                self._pk.verify(sig, msg)
                return True
            except Exception:
                return False
        return hmac.compare_digest(hmac.new(self._secret, msg, "sha256").digest(), sig)


# ---------- Merkle tree ----------
def _next_level(level):
    if len(level) % 2:
        level = level + [level[-1]]
    return [hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)]


def merkle_root(leaves):
    level = [bytes.fromhex(x) for x in leaves] or [hashlib.sha256(b"").digest()]
    while len(level) > 1:
        level = _next_level(level)
    return level[0].hex()


def merkle_proof(leaves, idx):
    level = [bytes.fromhex(x) for x in leaves]
    proof = []
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        sib = idx ^ 1
        proof.append((level[sib].hex(), sib > idx))
        level = _next_level(level)
        idx //= 2
    return proof


def verify_proof(leaf, proof, root):
    h = bytes.fromhex(leaf)
    for sib, sib_is_right in proof:
        s = bytes.fromhex(sib)
        h = hashlib.sha256(h + s if sib_is_right else s + h).digest()
    return h.hex() == root


# ---------- simulator ----------
def make_polling_units(n, rng):
    units = []
    for i in range(n):
        reg = rng.randint(300, 900)
        turnout = int(reg * rng.uniform(0.35, 0.75))
        w = [rng.random() for _ in PARTIES]
        total = sum(w)
        scores = {p: int(turnout * x / total) for p, x in zip(PARTIES, w)}
        units.append((f"PU-{i:04d}", scores))
    return units


def simulate(units, witnesses, inec, a, rng, colluders=frozenset(),
             region=None, offline=frozenset(), mimic=False, sealed=False, plan_cover=0.0):
    """Build ledger entries with tampering, witness typos, outages and attackers.

    colluders : witness names that attest to INEC's (possibly tampered) figures
    region    : set of PU ids hit by a regional outage
    offline   : witness names that cannot reach the ledger inside `region`
    Random draws are made in a fixed order so runs stay comparable.
    """
    entries, truth = [], set()
    never = a.rounds + 1  # a delay beyond the last round = never arrives
    for pu_id, scores in units:
        t = rng.random() < a.tamper
        t_party, t_amt = rng.choice(PARTIES), rng.randint(20, 120)
        t_inec = 60 + rng.gauss(0, 20)  # minutes after close when INEC publishes
        planned = rng.random() < plan_cover  # attacker pre-agreed this alteration
        inec_scores = dict(scores)
        if t:  # INEC-side change AFTER capture
            inec_scores[t_party] += t_amt
            truth.add(pu_id)
        inec_hash = sha(canonical(pu_id, inec_scores).encode())

        subs = []
        for w in witnesses:
            typo = rng.random() < a.typo
            ty_party, ty_amt = rng.choice(PARTIES), rng.choice([-10, -1, 1, 10])
            late = rng.random() < a.outage
            late_by = rng.randint(1, a.rounds)
            jit, copy_lag = rng.gauss(0, 40), rng.uniform(1, 5)
            ts = t_inec + jit                    # honest: independent, wide timing
            # sealed: a colluder committed before INEC published, so it can only match
            # INEC's tampered figures if the alteration was pre-agreed
            is_col = w.name in colluders and not (sealed and not planned)
            if is_col:
                w_scores = dict(inec_scores)     # attests to whatever INEC says
                if mimic:                        # smart attacker imitates honest noise
                    if typo:
                        w_scores[ty_party] += ty_amt
                else:                            # naive attacker copies right after INEC
                    ts = t_inec + copy_lag
            else:
                w_scores = dict(scores)          # honest: own copy of the sheet
                if typo:
                    w_scores[ty_party] += ty_amt
            h = sha(canonical(pu_id, w_scores).encode())
            delay = late_by if late else 0
            if region and pu_id in region and w.name in offline:
                delay = never
            sig = w.sign(f"{pu_id}|{h}".encode())
            subs.append({"witness": w.name, "group": w.group, "hash": h,
                         "delay": delay, "t": ts,
                         "valid": w.verify(f"{pu_id}|{h}".encode(), sig)})
        entries.append({"pu_id": pu_id, "inec_hash": inec_hash, "subs": subs,
                        "t_inec": t_inec})
    return entries, truth


def run_case(args, witnesses, inec, colluders=frozenset(), region=None,
             offline=frozenset(), tamper=None, mimic=False, salt=0,
             sealed=False, plan_cover=0.0):
    units = make_polling_units(args.pus, random.Random(args.seed + salt))
    a = copy.copy(args)
    if tamper is not None:
        a.tamper = tamper
    return simulate(units, witnesses, inec, a, random.Random(args.seed + 1 + salt),
                    colluders, region, offline, mimic, sealed, plan_cover)


# ---------- quorum logic ----------
def status(entry, k, n, round_no, min_groups=1, exclude=frozenset()):
    arrived = [s for s in entry["subs"] if s["delay"] <= round_no and s["valid"]
               and s["witness"] not in exclude]
    missing = n - len(arrived)
    by_hash = {}
    for s in arrived:
        by_hash.setdefault(s["hash"], []).append(s)
    mine = by_hash.get(entry["inec_hash"], [])
    matching, groups = len(mine), len({s["group"] for s in mine})
    rival = max((len(v) for h, v in by_hash.items() if h != entry["inec_hash"]),
                default=0)
    if matching >= k and groups >= min_groups:
        return "DISPUTED" if rival >= k else "VERIFIED"
    if rival >= k:
        return "TAMPER_SUSPECTED"
    can_verify = matching + missing >= k and groups + missing >= min_groups
    if can_verify or rival + missing >= k:
        return "PENDING"
    return "DISPUTED"  # no quorum possible: send to human review


def evaluate(entries, truth, args, min_groups, exclude=frozenset()):
    final = {e["pu_id"]: status(e, args.k, args.witnesses, args.rounds, min_groups, exclude)
             for e in entries}
    hidden = sum(final[p] == "VERIFIED" for p in truth)  # tampering marked VERIFIED
    caught = sum(final[p] in ("TAMPER_SUSPECTED", "DISPUTED") for p in truth)
    verified = sum(s == "VERIFIED" for s in final.values())
    return final, hidden, caught, verified


# ---------- insider monitor ----------
def make_access_logs(rng, n_events=600, n_bad=12):
    events = []
    for i in range(n_events):
        bad = i < n_bad
        events.append({
            "staff": f"S{rng.randint(1, 40):02d}" if not bad else f"S{rng.randint(90, 92)}",
            "hour": rng.randint(1, 4) if bad else int(min(23, max(0, rng.gauss(12, 3)))),
            "edits": rng.randint(25, 60) if bad else rng.randint(0, 4),
            "in_scope": False if bad else rng.random() > 0.03,
            "label_bad": bad,
        })
    rng.shuffle(events)
    return events


def detect_insiders(events):
    mu = statistics.mean(e["edits"] for e in events)
    sd = statistics.pstdev(e["edits"] for e in events) or 1
    flagged = []
    for e in events:
        score = (e["hour"] < 6 or e["hour"] > 21) + (not e["in_scope"]) \
                + ((e["edits"] - mu) / sd > 3)
        if score >= 2:  # two independent signals needed: limits false alarms
            flagged.append(e)
    return flagged


# ---------- AI layer: witness behaviour model ----------
class ZNovelty:
    """Dependency-free fallback if scikit-learn is missing."""

    def fit(self, X):
        cols = list(zip(*X))
        self.mu = [statistics.mean(c) for c in cols]
        self.sd = [statistics.pstdev(c) or 1.0 for c in cols]
        return self

    def predict(self, X):
        return [-1 if any(abs((v - m) / s) > 4 for v, m, s in zip(x, self.mu, self.sd))
                else 1 for x in X]


def window_features(entries, witnesses, win=25):
    """One row per (witness, window of `win` units):
    [spread of upload lag vs INEC, size of mean lag, mismatch rate vs INEC]."""
    rows = []
    for start in range(0, len(entries) - win + 1, win):
        chunk = entries[start:start + win]
        for idx, w in enumerate(witnesses):
            lags = [e["subs"][idx]["t"] - e["t_inec"] for e in chunk]
            miss = sum(e["subs"][idx]["hash"] != e["inec_hash"] for e in chunk) / win
            rows.append((w.name, [statistics.pstdev(lags), abs(statistics.mean(lags)), miss]))
    return rows


def fit_behaviour_model(rows):
    X = [r[1] for r in rows]
    if HAVE_SK:
        return EllipticEnvelope(contamination=0.01, random_state=0).fit(X)
    return ZNovelty().fit(X)


def flag_witnesses(model, rows, share=0.5):
    """Flag a witness when more than `share` of its windows look novel."""
    preds = model.predict([r[1] for r in rows])
    seen, bad = Counter(), Counter()
    for (name, _), p in zip(rows, preds):
        seen[name] += 1
        bad[name] += p == -1
    return {nm for nm in seen if bad[nm] / seen[nm] > share}


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pus", type=int, default=500)
    ap.add_argument("--witnesses", type=int, default=7)
    ap.add_argument("--k", type=int, default=4)
    ap.add_argument("--groups", type=int, default=3)
    ap.add_argument("--min-groups", dest="min_groups", type=int, default=3)
    ap.add_argument("--tamper", type=float, default=0.02)
    ap.add_argument("--typo", type=float, default=0.02)
    ap.add_argument("--outage", type=float, default=0.15)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_known_args()[0]  # known_args so it also runs in Colab/Jupyter
    if args.k * 2 <= args.witnesses:
        print("WARNING: k should be more than half of n, or two rival quorums can exist.\n")

    keyrng = random.Random(args.seed + 99)
    witnesses = [Signer(f"W{i + 1}", keyrng, GROUPS[i % args.groups])
                 for i in range(args.witnesses)]
    inec = Signer("INEC", keyrng)
    n, k, m = args.witnesses, args.k, args.min_groups
    print(f"Signatures: {'Ed25519' if HAVE_ED else 'HMAC fallback (demo only)'}")
    print(f"{args.pus} polling units | {n} witnesses in {args.groups} groups | "
          f"quorum {k}-of-{n}, needs {m} groups\n")

    # ===== baseline: honest witnesses =====
    entries, truth = run_case(args, witnesses, inec)
    print("BASELINE - status by sync round (late witnesses catch up)")
    for r in range(args.rounds + 1):
        c = Counter(status(e, k, n, r, m) for e in entries)
        print(f"  round {r}: " + ", ".join(f"{s}={c.get(s, 0)}" for s in
              ["VERIFIED", "PENDING", "TAMPER_SUSPECTED", "DISPUTED"]))
    _, hid, cau, ver = evaluate(entries, truth, args, m)
    print(f"  tampering: true={len(truth)}, caught={cau}, hidden={hid}")

    leaves = [sha(f"{e['pu_id']}|{e['inec_hash']}".encode()) for e in entries]
    root = merkle_root(leaves)
    i = len(entries) // 2
    ok = verify_proof(leaves[i], merkle_proof(leaves, i), root)
    print(f"  Merkle root {root[:24]}... | public proof for {entries[i]['pu_id']}: "
          f"{'VALID' if ok else 'INVALID'}")

    logs = make_access_logs(random.Random(args.seed + 5))
    hits = detect_insiders(logs)
    tp = sum(e["label_bad"] for e in hits)
    print(f"  insider monitor: flagged={len(hits)}, true positives={tp}/"
          f"{sum(e['label_bad'] for e in logs)}, false positives={len(hits) - tp}")

    # ===== A. collusion sweep =====
    print("\nA. COLLUDING WITNESSES (attacker tampers INEC's figures AND bribes c witnesses)")
    print("   Worst case for diversity: colluders come from as few groups as possible.")
    order = [w.name for w in sorted(witnesses, key=lambda w: w.group)]
    print("   c | plain k-of-n: hidden/caught | + group rule: hidden/caught | units marked VERIFIED (plain vs group)")
    for c in range(0, n + 1):
        ent, tr = run_case(args, witnesses, inec, colluders=frozenset(order[:c]))
        _, h1, c1, v1 = evaluate(ent, tr, args, 1)
        _, h2, c2, v2 = evaluate(ent, tr, args, m)
        print(f"   {c} | {h1:>3}/{c1:<3} {'<- BREACH' if h1 else '':9} | "
              f"{h2:>3}/{c2:<3} {'<- BREACH' if h2 else '':9} | {v1} vs {v2}")
    print(f"   Rule of thumb: plain rule breaks when colluders >= k ({k}). The group rule "
          f"also needs colluders to span >= {m} groups.")
    print("   Cost: the group rule leaves more honest units unverified when witnesses are offline.")

    # ===== B. regional outage + tampering =====
    print("\nB. REGIONAL OUTAGE + TAMPERING (20% of units; too many witnesses offline for quorum)")
    region = {u[0] for u in make_polling_units(args.pus, random.Random(args.seed))[:args.pus // 5]}
    offline = frozenset(w.name for w in witnesses[:n - k + 1])
    ent, tr = run_case(args, witnesses, inec, region=region, offline=offline, tamper=0.10)
    final, hid, cau, ver = evaluate(ent, tr, args, m)
    in_reg = [e["pu_id"] for e in ent if e["pu_id"] in region]
    stuck = sum(final[p] == "PENDING" for p in in_reg)
    tam_in = [p for p in tr if p in region]
    print(f"   units in region={len(in_reg)}, still PENDING after last round={stuck}, "
          f"tampered in region={len(tam_in)}")
    print(f"   tampered units wrongly marked VERIFIED (anywhere)={hid}  <- must be 0 (fails safe)")
    print("   Pending units escalate to manual collation. The attack buys delay, not a fake pass.")

    # ===== C. forged signature / stolen key =====
    print("\nC. FORGERY AND STOLEN KEYS")
    fake = witnesses[0].verify(b"PU-0001|deadbeef", b"\x00" * 64)
    print(f"   forged signature without the key accepted? {fake}  <- must be False")
    ent, tr = run_case(args, witnesses, inec, colluders=frozenset([witnesses[0].name]))
    _, h1, _, _ = evaluate(ent, tr, args, 1)
    print(f"   one stolen key (acts as 1 colluder): hidden tampering={h1}")
    print("   An attacker needs k stolen keys, so key hygiene and revocation matter per witness.")

    # ===== D. AI layer =====
    print("\nD. AI LAYER - witness behaviour model (plain 4-of-7 rule, no group rule)")
    print("   Trained on an honest rehearsal (e.g. a mock election), then scores live windows.")
    base, _ = run_case(args, witnesses, inec, salt=1000)
    model = fit_behaviour_model(window_features(base, witnesses))
    print(f"   model: {'EllipticEnvelope (robust Mahalanobis distance)' if HAVE_SK else 'z-score fallback'}")
    print("   c | attacker | flagged right/wrong | hidden tampering before -> after | units VERIFIED after")
    for c in (0, 2, 4, 6):
        for mimic in (False, True):
            if c == 0 and mimic:
                continue
            col = frozenset(order[:c])
            ent, tr = run_case(args, witnesses, inec, colluders=col, mimic=mimic)
            fl = flag_witnesses(model, window_features(ent, witnesses))
            _, h0, _, _ = evaluate(ent, tr, args, 1)
            _, h1, _, v1 = evaluate(ent, tr, args, 1, fl)
            who = "none" if c == 0 else ("mimic" if mimic else "naive")
            print(f"   {c} | {who:<8} | {len(fl & col)}/{c} right, {len(fl - col)} wrong | "
                  f"{h0:>3} -> {h1:<3} | {v1}")
    print("   Naive copiers are caught and revoked. Attackers who imitate honest timing and")
    print("   typo noise are NOT caught: their units stay falsely verified.")
    print("   Defence against mimics: sealed submissions (section E) plus richer behaviour")
    print("   data from a real rehearsal.")
    print("   After revocation, units go to human review instead of VERIFIED. That is the point.")

    # ===== E. sealed submissions =====
    print("\nE. SEALED SUBMISSIONS (commit before INEC publishes; plain 4-of-7, no AI layer)")
    print("   Attacker must pre-agree each alteration with colluders before the commit deadline.")
    print("   c | alterations pre-planned | hidden tampering: open vs sealed | caught (sealed)")
    for c in (4, 6):
        col = frozenset(order[:c])
        ent, tr = run_case(args, witnesses, inec, colluders=col)
        _, ho, _, _ = evaluate(ent, tr, args, 1)
        for pc in (0.0, 0.25, 0.5, 1.0):
            ent, tr = run_case(args, witnesses, inec, colluders=col, sealed=True, plan_cover=pc)
            _, hs, cs, _ = evaluate(ent, tr, args, 1)
            print(f"   {c} | {pc:>4.0%} | {ho:>3} vs {hs:<3} | {cs}/{len(tr)}")
    print("   Sealing removes copy-after-publication. What is left is an attacker who plans every")
    print("   alteration with colluders in advance: more people must know, and it leaves a trail.")
    print("   Sealing does NOT help if the sheet itself is falsified at the polling unit.")

    with open("ledger_export.json", "w") as f:
        json.dump({"merkle_root": root}, f, indent=1)
    print("\nWrote ledger_export.json")


if __name__ == "__main__":
    main()
