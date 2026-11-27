"""Traceroute history analytics."""
import statistics
from collections import defaultdict
from database import db_connect
MAX_ROUTE_COLUMNS=12
def get_hop_report_summary(target, limit=10000):
    """Return per-hop statistics from the latest stored traceroute samples."""
    with db_connect() as db:
        rows = db.execute(
            "SELECT hop,address,latency,timestamp FROM hop_samples "
            "WHERE target=? ORDER BY timestamp DESC,id DESC LIMIT ?",
            (target, int(limit)),
        ).fetchall()
    grouped = defaultdict(list)
    for hop, address, latency, stamp in reversed(rows):
        grouped[int(hop)].append((address or "—", latency, stamp))

    result = []
    for hop in sorted(grouped):
        samples = grouped[hop]
        valid = [float(item[1]) for item in samples if item[1] is not None]
        diffs = [
            abs(float(samples[i][1]) - float(samples[i - 1][1]))
            for i in range(1, len(samples))
            if samples[i][1] is not None and samples[i - 1][1] is not None
        ]
        addresses = [item[0] for item in samples if item[0] not in ("", "—", "*")]
        latest_address = addresses[-1] if addresses else (samples[-1][0] if samples else "—")
        address_changes = sum(addresses[i] != addresses[i - 1] for i in range(1, len(addresses)))
        losses = sum(item[1] is None for item in samples)
        result.append({
            "hop": hop,
            "address": latest_address,
            "current": samples[-1][1],
            "average": statistics.mean(valid) if valid else None,
            "minimum": min(valid) if valid else None,
            "maximum": max(valid) if valid else None,
            "jitter": statistics.mean(diffs) if diffs else None,
            "loss_pct": 100.0 * losses / len(samples) if samples else 0.0,
            "losses": losses,
            "samples": len(samples),
            "address_changes": address_changes,
            "last_seen": samples[-1][2],
        })
    return result


def load_route_snapshots(target, limit=MAX_ROUTE_COLUMNS):
    """Restore the most recent complete traceroute scans for a target from SQLite."""
    with db_connect() as db:
        stamps = [row[0] for row in db.execute(
            "SELECT DISTINCT timestamp FROM hop_samples WHERE target=? "
            "ORDER BY timestamp DESC LIMIT ?", (target, int(limit))
        ).fetchall()]
        if not stamps:
            return []
        placeholders = ",".join("?" for _ in stamps)
        rows = db.execute(
            f"SELECT timestamp,hop,address,latency FROM hop_samples "
            f"WHERE target=? AND timestamp IN ({placeholders}) ORDER BY timestamp,hop,id",
            (target, *stamps)
        ).fetchall()
    by_stamp = {}
    for stamp, hop, address, latency in rows:
        by_stamp.setdefault(stamp, {})[int(hop)] = (address or "—", latency)
    return [by_stamp[stamp] for stamp in sorted(by_stamp)][-int(limit):]


def route_diagnosis_flags(snapshots):
    """Return conservative per-hop flags for visual highlighting in the route heatmap."""
    if not snapshots:
        return {}
    recent = snapshots[-5:]
    latest = recent[-1]
    flags = {}
    placeholder = ("", "—", "*", None)

    if len(recent) >= 2:
        previous = recent[-2]
        for hop, observation in latest.items():
            old = previous.get(hop)
            new_addr = observation[0] if observation else None
            old_addr = old[0] if old else None
            if old_addr not in placeholder and new_addr not in placeholder and old_addr != new_addr:
                flags[hop] = ("ROUTE CHANGE", "route")

    hops = sorted(latest)
    for hop in hops[:-1]:
        observations = [snap.get(hop) for snap in recent]
        losses = sum(obs is None or obs[1] is None for obs in observations)
        downstream = sum(
            any((obs := snap.get(later)) is not None and obs[1] is not None
                for later in hops if later > hop) for snap in recent
        )
        if losses >= max(2, (len(recent) + 1) // 2) and downstream >= max(1, (len(recent) * 2 + 2) // 3):
            flags.setdefault(hop, ("ICMP FILTER / RATE LIMIT", "caution"))

    medians = {}
    for hop in hops:
        vals = [float(obs[1]) for snap in recent
                if (obs := snap.get(hop)) is not None and obs[1] is not None]
        if len(vals) >= min(3, len(recent)):
            medians[hop] = statistics.median(vals)
    for left, right in zip(hops, hops[1:]):
        if left in medians and right in medians:
            delta = medians[right] - medians[left]
            if delta >= max(35.0, medians[left] * 0.75):
                flags.setdefault(right, (f"RTT +{delta:.0f} ms", "latency"))

    for hop in hops:
        vals = [float(obs[1]) for snap in recent
                if (obs := snap.get(hop)) is not None and obs[1] is not None]
        if len(vals) >= 4:
            jitter = statistics.mean(abs(vals[i] - vals[i-1]) for i in range(1, len(vals)))
            if jitter >= 25:
                flags.setdefault(hop, (f"HIGH JITTER {jitter:.0f} ms", "caution"))

    if hops:
        final_hop = hops[-1]
        final = [snap.get(final_hop) for snap in recent]
        losses = sum(obs is None or obs[1] is None for obs in final)
        if len(recent) >= 3 and losses >= max(2, (len(recent)+1)//2):
            flags.setdefault(final_hop, ("FINAL HOP NOT REPLYING", "latency"))
    return flags


def analyze_route_snapshots(snapshots):
    """Conservative, evidence-based interpretation of recent traceroute snapshots."""
    if not snapshots:
        return "Route diagnosis: waiting for traceroute samples."

    recent = snapshots[-5:]
    latest = recent[-1]
    if not latest:
        return "Route diagnosis: the latest scan returned no hop data."

    notes = []
    placeholders = ("", "—", "*", None)

    # Detect address changes between the two most recent successful scans.
    if len(recent) >= 2:
        previous = recent[-2]
        changes = []
        for hop, observation in latest.items():
            old = previous.get(hop)
            new_address = observation[0] if observation else None
            old_address = old[0] if old else None
            if (old_address not in placeholders and new_address not in placeholders
                    and old_address != new_address):
                changes.append(f"hop {hop}: {old_address} → {new_address}")
        if changes:
            notes.append("Route changed (" + "; ".join(changes[:3]) + ").")

    hops = sorted(latest)
    # A hop that times out while later hops keep replying is usually filtering
    # or ICMP rate limiting, not proof of forwarding loss.
    for hop in hops[:-1]:
        observations = [snap.get(hop) for snap in recent]
        count = len(observations)
        losses = sum(obs is None or obs[1] is None for obs in observations)
        downstream_replies = sum(
            1 for snap in recent
            if any((obs := snap.get(later)) is not None and obs[1] is not None
                   for later in hops if later > hop)
        )
        threshold = max(2, (count + 1) // 2)
        if losses >= threshold and downstream_replies >= max(1, (count * 2 + 2) // 3):
            notes.append(
                f"Hop {hop} misses replies while later hops respond; likely ICMP "
                "rate limiting/deprioritization rather than confirmed packet loss."
            )
            break

    # If the final observed hop repeatedly fails to answer, report it as a
    # possible endpoint/route issue, not a definitive outage (the route may
    # simply be capped by the max-hop setting).
    final_hop = hops[-1]
    final_obs = [snap.get(final_hop) for snap in recent]
    final_losses = sum(obs is None or obs[1] is None for obs in final_obs)
    if len(recent) >= 3 and final_losses >= max(2, (len(recent) + 1) // 2):
        notes.append(
            f"Last observed hop {final_hop} is not replying consistently; "
            "destination filtering, an outage, or the traceroute hop limit may be involved."
        )

    # Detect a large, repeated RTT step between adjacent hops. This is a
    # diagnostic hint only: hop RTTs are round-trip measurements and are not
    # additive link-delay measurements.
    medians = {}
    for hop in hops:
        vals = [
            float(obs[1]) for snap in recent
            if (obs := snap.get(hop)) is not None and obs[1] is not None
        ]
        if len(vals) >= min(3, len(recent)):
            medians[hop] = statistics.median(vals)
    for left, right in zip(hops, hops[1:]):
        if left in medians and right in medians:
            delta = medians[right] - medians[left]
            if delta >= max(35.0, medians[left] * 0.75):
                notes.append(
                    f"Large RTT increase between hops {left} and {right} "
                    f"(about +{delta:.1f} ms median); investigate this segment."
                )
                break

    # High variation at a hop can indicate an unstable path, but only report
    # it when enough valid samples exist.
    for hop in hops:
        vals = [
            float(obs[1]) for snap in recent
            if (obs := snap.get(hop)) is not None and obs[1] is not None
        ]
        if len(vals) >= 4:
            jitter = statistics.mean(abs(vals[i] - vals[i - 1]) for i in range(1, len(vals)))
            if jitter >= 25:
                notes.append(f"Hop {hop} has elevated RTT variation (about {jitter:.1f} ms).")
                break

    if not notes:
        return "Route diagnosis: no persistent route anomaly detected in the recent scans."
    return "Route diagnosis: " + " ".join(notes) + (
        " Interpret intermediate-hop loss cautiously; routers may limit diagnostic replies."
    )


