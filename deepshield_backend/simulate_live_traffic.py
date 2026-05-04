import argparse
import random
import signal
import sys
import time
from datetime import datetime

import requests


RUNNING = True


def _handle_sigint(_sig, _frame):
    global RUNNING
    RUNNING = False


signal.signal(signal.SIGINT, _handle_sigint)


ATTACK_POOL_MIXED = [
    ("Benign", 0.58, (0.50, 0.72)),
    ("Bot", 0.05, (0.72, 0.93)),
    ("DDoS", 0.06, (0.75, 0.96)),
    ("DoS GoldenEye", 0.04, (0.72, 0.94)),
    ("DoS Hulk", 0.06, (0.75, 0.96)),
    ("DoS Slowhttptest", 0.03, (0.68, 0.90)),
    ("DoS slowloris", 0.03, (0.68, 0.90)),
    ("FTP-Patator", 0.03, (0.66, 0.89)),
    ("Heartbleed", 0.01, (0.70, 0.92)),
    ("Infiltration", 0.02, (0.70, 0.93)),
    ("PortScan", 0.05, (0.72, 0.94)),
    ("SSH-Patator", 0.02, (0.66, 0.90)),
    ("Web Attack - Brute Force", 0.01, (0.65, 0.89)),
    ("Web Attack - Sql Injection", 0.005, (0.70, 0.95)),
    ("Web Attack - XSS", 0.015, (0.66, 0.90)),
]

ATTACK_POOL_BENIGN = [
    ("Benign", 0.96, (0.52, 0.72)),
    ("Normal", 0.04, (0.50, 0.70)),
]

ATTACK_CONFIDENCE_DEFAULTS = {
    "bot": (0.72, 0.93),
    "ddos": (0.75, 0.96),
    "dos goldeneye": (0.72, 0.94),
    "dos hulk": (0.75, 0.96),
    "dos slowhttptest": (0.68, 0.90),
    "dos slowloris": (0.68, 0.90),
    "ftp-patator": (0.66, 0.89),
    "heartbleed": (0.70, 0.92),
    "infiltration": (0.70, 0.93),
    "portscan": (0.72, 0.94),
    "ssh-patator": (0.66, 0.90),
    "web attack - brute force": (0.65, 0.89),
    "web attack - sql injection": (0.70, 0.95),
    "web attack - xss": (0.66, 0.90),
    "unknown zero-day exploit chain": (0.94, 0.99),
}

SOURCES = [
    "edge-gw-01",
    "branch-fw-02",
    "vpn-gateway-01",
    "internet-sensor-a",
    "dmz-probe-node",
    "sim-lab-agent",
]

TARGETS = [
    "api-node-1",
    "auth-service-1",
    "db-primary-1",
    "fileserver-2",
    "payment-gateway",
    "k8s-worker-3",
]

COMMON_PORTS = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9200]

# Fixed path for --mode attack so all burst events share one incident signature (one auto-email, not dozens).
ATTACK_BURST_SOURCE = "attack-simulator"
ATTACK_BURST_TARGET = "demo-victim-primary"

# Order matches launch_simulator_menu.bat. Benign is a baseline class, not listed here.
SIMULATOR_ATTACK_MENU: list[str] = [
    "DoS Hulk",
    "DDoS",
    "PortScan",
    "FTP-Patator",
    "SSH-Patator",
    "Infiltration",
    "Heartbleed",
    "DoS GoldenEye",
    "DoS Slowhttptest",
    "DoS slowloris",
    "Bot",
    "Web Attack - Brute Force",
    "Web Attack - Sql Injection",
    "Web Attack - XSS",
    "Unknown Zero-Day Exploit Chain",
]


def print_attack_menu() -> None:
    """Print attack choices with severity + justification (same rules as PredictorService / ingest)."""
    from pathlib import Path

    services_dir = Path(__file__).resolve().parent / "app" / "services"
    if str(services_dir) not in sys.path:
        sys.path.insert(0, str(services_dir))
    from severity_rules import severity_and_explanation

    def console_safe(value: str) -> str:
        replacements = {
            "≥": ">=",
            "≤": "<=",
            "→": "->",
            "—": "-",
            "–": "-",
        }
        for old, new in replacements.items():
            value = value.replace(old, new)
        return value.encode("ascii", "replace").decode("ascii")

    print("Choose attack to trigger:")
    print("(Severity uses midpoint of simulator confidence range -> same engine as /ingest.)")
    print("")
    for idx, name in enumerate(SIMULATOR_ATTACK_MENU, start=1):
        lo, hi = ATTACK_CONFIDENCE_DEFAULTS.get(name.strip().lower(), (0.72, 0.94))
        ref_p = round((lo + hi) / 2, 4)
        sev, why = severity_and_explanation(name, ref_p)
        tag = sev.upper()
        pad = " " if idx < 10 else ""
        print(f"  {pad}{idx}) {name:<30} [{tag}]  ref p={ref_p:.2f}")
        print(f"       -> {console_safe(why)}")
        print("")
    print("  S) Settings / presets")
    print("  Q) Quit")
    print("")
    print("Model also predicts: Benign (baseline) - not in this attack list.")


def pick_event(pool: list[tuple[str, float, tuple[float, float]]]) -> tuple[str, float]:
    roll = random.random()
    running_weight = 0.0
    for attack_type, weight, conf_range in pool:
        running_weight += weight
        if roll <= running_weight:
            return attack_type, round(random.uniform(*conf_range), 4)
    attack_type, _, conf_range = pool[-1]
    return attack_type, round(random.uniform(*conf_range), 4)


def send_event(base_url: str, timeout: int, pool: list[tuple[str, float, tuple[float, float]]]) -> bool:
    attack_type, confidence = pick_event(pool)
    payload = {
        "attack_type": attack_type,
        "confidence": confidence,
        "source": random.choice(SOURCES),
        "target": random.choice(TARGETS),
        "protocol": random.choice(["TCP", "TCP", "TCP", "UDP"]),
        "dst_port": random.choice(COMMON_PORTS),
    }

    res = requests.post(f"{base_url}/ingest/traffic-event", json=payload, timeout=timeout)
    res.raise_for_status()

    print(
        f"[{datetime.utcnow().isoformat()}Z] sent attack_type={attack_type:<6} conf={confidence:.2f} "
        f"source={payload['source']} target={payload['target']} status={res.status_code}"
    )
    return attack_type.strip().lower() not in {"benign", "normal", "normal traffic"}


def send_attack_event(base_url: str, timeout: int, attack_type: str) -> bool:
    conf_low, conf_high = ATTACK_CONFIDENCE_DEFAULTS.get(attack_type.strip().lower(), (0.72, 0.94))
    confidence = round(random.uniform(conf_low, conf_high), 4)
    payload = {
        "attack_type": attack_type,
        "confidence": confidence,
        # Same source->target for every packet in the burst so backend one-mail / dedupe policies apply.
        "source": ATTACK_BURST_SOURCE,
        "target": ATTACK_BURST_TARGET,
        "protocol": random.choice(["TCP", "TCP", "TCP", "UDP"]),
        "dst_port": random.choice(COMMON_PORTS),
    }

    res = requests.post(f"{base_url}/ingest/traffic-event", json=payload, timeout=timeout)
    res.raise_for_status()
    response_payload = {}
    try:
        response_payload = res.json()
    except ValueError:
        response_payload = {}

    automation = response_payload.get("automation") if isinstance(response_payload, dict) else None
    escalation_reason = response_payload.get("escalation_reason") if isinstance(response_payload, dict) else None
    automation_status = "none"
    if isinstance(automation, dict):
        automation_status = str(automation.get("status") or "unknown")
        if automation.get("run_id"):
            automation_status = f"{automation_status} run_id={automation.get('run_id')}"
        if automation.get("reason"):
            automation_status = f"{automation_status} reason={automation.get('reason')}"

    print(
        f"[{datetime.utcnow().isoformat()}Z] injected attack_type={attack_type:<24} conf={confidence:.2f} "
        f"source={payload['source']} target={payload['target']} status={res.status_code} "
        f"escalation={escalation_reason or 'none'} automation={automation_status}"
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="DeepShield live traffic simulator")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000", help="DeepShield backend base URL")
    parser.add_argument(
        "--mode",
        choices=["benign", "mixed", "attack"],
        default="benign",
        help="Traffic mode: benign baseline, mixed traffic, or fixed attack injection",
    )
    parser.add_argument(
        "--attack-type",
        default="DoS Hulk",
        help="Attack class to inject when --mode attack is selected",
    )
    parser.add_argument("--interval", type=float, default=1.5, help="Seconds between bursts")
    parser.add_argument("--burst-size", type=int, default=8, help="Events per burst")
    parser.add_argument("--cycles", type=int, default=0, help="Number of burst cycles before exit (0 = run forever)")
    parser.add_argument("--timeout", type=int, default=8, help="HTTP request timeout seconds")
    parser.add_argument(
        "--print-attack-menu",
        action="store_true",
        help="Print attack menu with engine-derived severity + justification, then exit.",
    )
    args = parser.parse_args()

    if args.print_attack_menu:
        print_attack_menu()
        return 0

    print("DeepShield simulator started. Press Ctrl+C to stop.")
    print(f"Target backend: {args.base_url}")
    print(f"Mode: {args.mode}")
    if args.mode == "attack":
        print(f"Attack injection class: {args.attack_type}")

    total_sent = 0
    total_alert_like = 0
    completed_cycles = 0
    pool = ATTACK_POOL_BENIGN if args.mode == "benign" else ATTACK_POOL_MIXED

    while RUNNING:
        for _ in range(args.burst_size):
            if not RUNNING:
                break
            try:
                if args.mode == "attack":
                    is_alert_like = send_attack_event(args.base_url, args.timeout, args.attack_type)
                else:
                    is_alert_like = send_event(args.base_url, args.timeout, pool)
                total_sent += 1
                total_alert_like += 1 if is_alert_like else 0
            except requests.RequestException as exc:
                print(f"[warn] Failed to send event: {exc}")
            time.sleep(0.08)

        if not RUNNING:
            break

        print(f"[stats] total_sent={total_sent} alert_like={total_alert_like}")
        completed_cycles += 1
        if args.cycles > 0 and completed_cycles >= args.cycles:
            break
        time.sleep(max(args.interval, 0.2))

    print("\nDeepShield simulator stopped.")
    print(f"Final stats: total_sent={total_sent}, alert_like={total_alert_like}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
