import os
import secrets
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from collections import defaultdict
import threading
from urllib.parse import unquote, urlsplit

import click
import joblib
import numpy as np
import pandas as pd

from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify
)

from flask_login import (
    UserMixin,
    current_user,
    login_user,
    logout_user,
    login_required
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from extensions import db, login_manager, csrf
from ml.inference import (
    analyze_uploaded_csv,
    load_detection_model
)

try:
    from scapy.all import AsyncSniffer, conf, get_if_list, IP, IPv6, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    AsyncSniffer = None
    conf = None
    get_if_list = None
    SCAPY_AVAILABLE = False


# --------------------------------------------------
# PROJECT CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MODEL_PATH = BASE_DIR / "models" / "cybershield_model.joblib"

UPLOAD_MAX_SIZE = 100 * 1024 * 1024
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()


def resolve_secret_key(environment, configured_key):
    """Require a persistent production secret; generate one for local use."""
    placeholder_keys = {
        "",
        "replace-with-a-random-secret",
        "development-only-change-this-key",
        "change-me",
        "changeme",
        "secret"
    }
    configured_key = (configured_key or "").strip()
    is_placeholder = configured_key.casefold() in placeholder_keys

    if environment == "production" and (
        is_placeholder or len(configured_key) < 32
    ):
        raise RuntimeError(
            "Set a unique SECRET_KEY of at least 32 characters "
            "before running in production."
        )

    return (
        configured_key
        if not is_placeholder
        else secrets.token_hex(32)
    )

# --------------------------------------------------
# LIVE MONITOR - PHASE 3
# Real-time packet capture + flow aggregation + ML inference.
# Diagnostic counters expose the live inference path for validation.
# --------------------------------------------------

LIVE_MONITOR_STATE = {}
LIVE_MONITOR_RUNTIME = {}
LIVE_MONITOR_FLOWS = {}
LIVE_MONITOR_LOCK = threading.RLock()
LIVE_FLOW_TIMEOUT_SECONDS = 60
LIVE_FLOW_PREDICT_PACKET_INTERVAL = 10
LIVE_FLOW_MAX_EVENTS = 25
LIVE_FLOW_MAX_ACTIVE = 500
LIVE_FLOW_MAX_PACKET_SAMPLES = 256
LIVE_MONITOR_MODEL_CACHE = None


def get_live_monitor_state(user_id):
    """Return the current live monitor state for one user."""
    state = LIVE_MONITOR_STATE.get(user_id)

    if state is None:
        state = {
            "running": False,
            "started_at": None,
            "packet_count": 0,
            "byte_count": 0,
            "events": [],
            "packet_activity": [],
            "threat_count": 0,
            "flows_observed": 0,
            "flows_analyzed": 0,
            "benign_predictions": 0,
            "attack_predictions": 0,
            "alerts_created": 0,
            "inference_errors": 0,
            "model_features": 0,
            "last_prediction": "Not analyzed yet",
            "interface": "Not selected",
            "message": "Monitor is ready to start."
        }
        LIVE_MONITOR_STATE[user_id] = state

    return state


def get_capture_interfaces():
    """Return the interfaces Scapy can use for packet capture."""
    if not SCAPY_AVAILABLE or get_if_list is None or conf is None:
        return []

    available = set(get_if_list())
    interfaces = []

    for interface in conf.ifaces.values():
        name = getattr(interface, "name", None)
        network_name = getattr(interface, "network_name", None)
        capture_name = (
            network_name if network_name in available
            else name if name in available
            else None
        )

        if capture_name is None:
            continue

        description = getattr(interface, "description", "")
        address = getattr(interface, "ip", "")
        label = name or description or capture_name

        if description and description != label:
            label += f" — {description}"
        if address:
            label += f" ({address})"

        interfaces.append({
            "value": capture_name,
            "label": label
        })

    return interfaces


def get_default_capture_interface():
    """Return the Scapy default interface name."""
    if not SCAPY_AVAILABLE or conf is None:
        return "Unavailable"

    configured_interface = os.getenv("CYBERSHIELD_MONITOR_INTERFACE", "").strip()
    if configured_interface:
        return configured_interface

    default_interface = conf.iface
    available = {
        interface["value"]
        for interface in get_capture_interfaces()
    }

    for capture_name in (
        getattr(default_interface, "network_name", None),
        getattr(default_interface, "name", None)
    ):
        if capture_name in available:
            return capture_name

    return "Default interface"


def get_capture_backend_error():
    """Return a clear error when Windows packet capture is unavailable."""
    if (
        SCAPY_AVAILABLE
        and os.name == "nt"
        and getattr(conf.L2listen, "__name__", None) == "_NotAvailableSocket"
    ):
        return (
            "Npcap is missing or unavailable (Scapy cannot load wpcap.dll). "
            "Install Npcap with WinPcap API-compatible Mode, then restart the app."
        )

    return None


def concise_error_message(error, limit=240):
    message = " ".join(str(error).split())
    return message if len(message) <= limit else message[:limit - 3] + "..."


def get_live_flow_store(user_id):
    """Return the bidirectional flow store for one monitored user."""
    return LIVE_MONITOR_FLOWS.setdefault(user_id, {})


def _packet_network_fields(packet):
    """Extract network/transport fields without retaining Scapy objects."""
    src = dst = "-"
    src_port = dst_port = 0
    ip_version = 0
    protocol = "OTHER"

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst = str(ip.src), str(ip.dst)
        ip_version = 4
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        src, dst = str(ip.src), str(ip.dst)
        ip_version = 6

    return src, dst, src_port, dst_port, ip_version, protocol


def _flow_key(src, dst, src_port, dst_port, protocol):
    """Create a canonical bidirectional flow key."""
    left = (src, int(src_port), dst, int(dst_port))
    right = (dst, int(dst_port), src, int(src_port))
    return (min(left, right), max(left, right), protocol)


def _new_flow(now, src, dst, src_port, dst_port, protocol):
    return {
        "first_seen": now,
        "last_seen": now,
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "fwd_lengths": [],
        "bwd_lengths": [],
        "fwd_times": [],
        "bwd_times": [],
        "fwd_packets": 0,
        "bwd_packets": 0,
        "fwd_bytes": 0,
        "bwd_bytes": 0,
        "fin": 0,
        "syn": 0,
        "rst": 0,
        "psh": 0,
        "ack": 0,
        "urg": 0,
        "ece": 0,
        "cwr": 0,
        "forward_direction": (src, src_port, dst, dst_port),
        "last_prediction_at": 0.0,
        "prediction_packet_count": 0,
        "alert_created": False,
    }


def _safe_mean(values):
    return float(np.mean(values)) if values else 0.0


def _safe_std(values):
    return float(np.std(values)) if values else 0.0


def _safe_var(values):
    return float(np.var(values)) if values else 0.0


def _safe_max(values):
    return float(max(values)) if values else 0.0


def _safe_min(values):
    return float(min(values)) if values else 0.0


def append_bounded_sample(samples, value):
    samples.append(value)
    if len(samples) > LIVE_FLOW_MAX_PACKET_SAMPLES:
        del samples[:-LIVE_FLOW_MAX_PACKET_SAMPLES]


def build_live_flow_features(flow, feature_columns):
    """Build CIC-IDS2017-style flow features from aggregated live packets.

    Only features that can be derived from the captured flow are populated.
    Remaining model columns are initialized to zero so the existing pipeline
    receives the exact column order saved with the trained model.
    """
    duration = max((flow["last_seen"] - flow["first_seen"]) * 1_000_000.0, 0.0)
    duration_seconds = duration / 1_000_000.0
    fwd = flow["fwd_lengths"]
    bwd = flow["bwd_lengths"]
    all_lengths = fwd + bwd
    total_packets = flow["fwd_packets"] + flow["bwd_packets"]
    total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

    values = {str(column): 0.0 for column in feature_columns}

    def setv(name, value):
        if name in values:
            values[name] = float(value)

    setv("Destination Port", flow["dst_port"])
    setv("Flow Duration", duration)
    setv("Total Fwd Packets", flow["fwd_packets"])
    setv("Total Backward Packets", flow["bwd_packets"])
    setv("Total Length of Fwd Packets", flow["fwd_bytes"])
    setv("Total Length of Bwd Packets", flow["bwd_bytes"])

    setv("Fwd Packet Length Max", _safe_max(fwd))
    setv("Fwd Packet Length Min", _safe_min(fwd))
    setv("Fwd Packet Length Mean", _safe_mean(fwd))
    setv("Fwd Packet Length Std", _safe_std(fwd))
    setv("Bwd Packet Length Max", _safe_max(bwd))
    setv("Bwd Packet Length Min", _safe_min(bwd))
    setv("Bwd Packet Length Mean", _safe_mean(bwd))
    setv("Bwd Packet Length Std", _safe_std(bwd))

    setv("Flow Bytes/s", total_bytes / duration_seconds if duration_seconds else 0.0)
    setv("Flow Packets/s", total_packets / duration_seconds if duration_seconds else 0.0)
    setv("Fwd Packets/s", flow["fwd_packets"] / duration_seconds if duration_seconds else 0.0)
    setv("Bwd Packets/s", flow["bwd_packets"] / duration_seconds if duration_seconds else 0.0)

    setv("Min Packet Length", _safe_min(all_lengths))
    setv("Max Packet Length", _safe_max(all_lengths))
    setv("Packet Length Mean", _safe_mean(all_lengths))
    setv("Packet Length Std", _safe_std(all_lengths))
    setv("Packet Length Variance", _safe_var(all_lengths))

    setv("FIN Flag Count", flow["fin"])
    setv("SYN Flag Count", flow["syn"])
    setv("RST Flag Count", flow["rst"])
    setv("PSH Flag Count", flow["psh"])
    setv("ACK Flag Count", flow["ack"])
    setv("URG Flag Count", flow["urg"])
    setv("CWE Flag Count", flow["cwr"])
    setv("ECE Flag Count", flow["ece"])

    setv("Down/Up Ratio", flow["bwd_packets"] / flow["fwd_packets"] if flow["fwd_packets"] else 0.0)
    setv("Average Packet Size", total_bytes / total_packets if total_packets else 0.0)
    setv("Avg Fwd Segment Size", _safe_mean(fwd))
    setv("Avg Bwd Segment Size", _safe_mean(bwd))

    # Header length cannot be reconstructed exactly for every capture layer;
    # use the common IP/TCP/UDP header estimate from packet counts.
    fwd_header = flow.get("fwd_header_bytes", 0)
    bwd_header = flow.get("bwd_header_bytes", 0)
    setv("Fwd Header Length", fwd_header)
    setv("Bwd Header Length", bwd_header)

    setv("Subflow Fwd Packets", flow["fwd_packets"])
    setv("Subflow Bwd Packets", flow["bwd_packets"])
    setv("Subflow Fwd Bytes", flow["fwd_bytes"])
    setv("Subflow Bwd Bytes", flow["bwd_bytes"])
    setv("act_data_pkt_fwd", sum(1 for x in fwd if x > 0))

    # These are left at zero unless the packet capture provides reliable
    # TCP window/segment information for the flow.
    if flow.get("init_win_fwd") is not None:
        setv("Init_Win_bytes_forward", flow["init_win_fwd"])
    if flow.get("init_win_bwd") is not None:
        setv("Init_Win_bytes_backward", flow["init_win_bwd"])

    setv("min_seg_size_forward", _safe_min(fwd))

    # CIC-IDS2017 active/idle timing features.
    intervals = []
    timestamps = sorted(flow["fwd_times"] + flow["bwd_times"])
    for a, b in zip(timestamps, timestamps[1:]):
        intervals.append(max(b - a, 0.0) * 1_000_000.0)

    if intervals:
        active = [x for x in intervals if x <= 1_000_000.0]
        idle = [x for x in intervals if x > 1_000_000.0]
    else:
        active, idle = [], []

    setv("Active Mean", _safe_mean(active))
    setv("Active Std", _safe_std(active))
    setv("Active Max", _safe_max(active))
    setv("Active Min", _safe_min(active))
    setv("Idle Mean", _safe_mean(idle))
    setv("Idle Std", _safe_std(idle))
    setv("Idle Max", _safe_max(idle))
    setv("Idle Min", _safe_min(idle))

    return pd.DataFrame([values], columns=feature_columns)


def update_live_flow(user_id, packet):
    """Aggregate one packet into a bidirectional flow and optionally score it."""
    if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
        return

    src, dst, src_port, dst_port, ip_version, protocol = _packet_network_fields(packet)
    if protocol not in {"TCP", "UDP"}:
        return

    now = datetime.now(timezone.utc).timestamp()
    key = _flow_key(src, dst, src_port, dst_port, protocol)

    with LIVE_MONITOR_LOCK:
        flows = get_live_flow_store(user_id)

        # Expire stale flows before adding the current packet.
        stale_keys = [
            k for k, v in flows.items()
            if now - v["last_seen"] > LIVE_FLOW_TIMEOUT_SECONDS
        ]
        for stale_key in stale_keys:
            flows.pop(stale_key, None)

        if key not in flows:
            if len(flows) >= LIVE_FLOW_MAX_ACTIVE:
                oldest_key = min(
                    flows,
                    key=lambda flow_key: flows[flow_key]["last_seen"]
                )
                flows.pop(oldest_key)

            flows[key] = _new_flow(
                now, src, dst, src_port, dst_port, protocol
            )
            state = get_live_monitor_state(user_id)
            state["flows_observed"] += 1

        flow = flows[key]
        packet_len = int(len(packet))

        if (src, src_port, dst, dst_port) == flow["forward_direction"]:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += packet_len
            append_bounded_sample(flow["fwd_lengths"], packet_len)
            append_bounded_sample(flow["fwd_times"], now)
            direction = "fwd"
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += packet_len
            append_bounded_sample(flow["bwd_lengths"], packet_len)
            append_bounded_sample(flow["bwd_times"], now)
            direction = "bwd"

        flow["last_seen"] = now

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            flow["fin"] += int(bool(flags.F))
            flow["syn"] += int(bool(flags.S))
            flow["rst"] += int(bool(flags.R))
            flow["psh"] += int(bool(flags.P))
            flow["ack"] += int(bool(flags.A))
            flow["urg"] += int(bool(flags.U))
            flow["ece"] += int(bool(flags.E))
            flow["cwr"] += int(bool(flags.C))

            header_bytes = int(packet[TCP].dataofs or 5) * 4
            if direction == "fwd":
                flow["fwd_header_bytes"] = flow.get("fwd_header_bytes", 0) + header_bytes
                if flow.get("init_win_fwd") is None:
                    flow["init_win_fwd"] = int(packet[TCP].window)
            else:
                flow["bwd_header_bytes"] = flow.get("bwd_header_bytes", 0) + header_bytes
                if flow.get("init_win_bwd") is None:
                    flow["init_win_bwd"] = int(packet[TCP].window)

        flow["prediction_packet_count"] += 1

        if flow["prediction_packet_count"] < LIVE_FLOW_PREDICT_PACKET_INTERVAL:
            return

        flow["prediction_packet_count"] = 0

        # Copy the flow while holding the lock so the background Scapy
        # callback can continue updating the live flow safely during inference.
        flow_snapshot = dict(flow)
        flow_snapshot["fwd_lengths"] = list(flow["fwd_lengths"])
        flow_snapshot["bwd_lengths"] = list(flow["bwd_lengths"])
        flow_snapshot["fwd_times"] = list(flow["fwd_times"])
        flow_snapshot["bwd_times"] = list(flow["bwd_times"])

    # Do model work outside the packet-state lock.
    try:
        model, feature_columns, target_mapping = load_live_detection_model()
        features = build_live_flow_features(flow_snapshot, feature_columns)
        prediction = model.predict(features)[0]
        probabilities = model.predict_proba(features)[0]
        confidence = float(np.max(probabilities) * 100.0)
        mapped = target_mapping.get(str(prediction), target_mapping.get(prediction, prediction))
        mapped = str(mapped)

        state = get_live_monitor_state(user_id)
        with LIVE_MONITOR_LOCK:
            state["flows_analyzed"] += 1
            state["model_features"] = len(feature_columns)
            state["last_prediction"] = (
                f"{mapped} ({confidence:.1f}% raw model score; uncalibrated)"
            )

            if mapped.upper() == "BENIGN":
                state["benign_predictions"] += 1
            else:
                state["attack_predictions"] += 1

        if mapped.upper() != "BENIGN":
            should_create_alert = False

            state = get_live_monitor_state(user_id)
            with LIVE_MONITOR_LOCK:
                state["threat_count"] += 1

                # Create one persistent alert for the first ATTACK prediction
                # of this flow. Subsequent predictions update the live monitor
                # but do not spam the Alerts table.
                live_flow = LIVE_MONITOR_FLOWS.get(user_id, {}).get(key)
                if live_flow is not None and not live_flow.get("alert_created", False):
                    live_flow["alert_created"] = True
                    should_create_alert = True

                event = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "time": datetime.now(IST).strftime("%I:%M:%S %p"),
                    "protocol": protocol,
                    "src": src,
                    "dst": dst,
                    "summary": (
                        f"{mapped} model prediction | "
                        f"{confidence:.1f}% raw score | "
                        f"{src}:{src_port} → {dst}:{dst_port}"
                    ),
                    "length": int(len(packet)),
                    "threat": True,
                    "attack_type": mapped,
                    "confidence": round(confidence, 2),
                    "severity": (
                        "Critical" if confidence >= 95
                        else "High" if confidence >= 85
                        else "Medium"
                    )
                }
                state["events"].append(event)
                state["events"] = state["events"][-LIVE_FLOW_MAX_EVENTS:]
                state["message"] = (
                    f"Model classified this flow as {mapped} "
                    f"({confidence:.1f}% raw score; uncalibrated)."
                )

            if should_create_alert:
                alert_created = create_live_attack_alert(
                    user_id=user_id,
                    attack_type=mapped,
                    confidence=confidence,
                    flow=flow_snapshot,
                    packet_length=len(packet)
                )

                with LIVE_MONITOR_LOCK:
                    state = get_live_monitor_state(user_id)
                    if alert_created:
                        state["alerts_created"] = state.get("alerts_created", 0) + 1
                    else:
                        # Allow a later ATTACK prediction to retry if the DB
                        # insert failed.
                        live_flow = LIVE_MONITOR_FLOWS.get(user_id, {}).get(key)
                        if live_flow is not None:
                            live_flow["alert_created"] = False

    except Exception as error:
        # Packet capture must continue even if the model cannot score a flow.
        state = get_live_monitor_state(user_id)
        with LIVE_MONITOR_LOCK:
            state["inference_errors"] += 1
            state["last_prediction"] = (
                f"Inference error: {concise_error_message(error)}"
            )
        app.logger.warning("Live flow prediction skipped: %s", error)


def create_live_attack_alert(user_id, attack_type, confidence, flow, packet_length):
    """Create one database alert for a live attack flow.

    Alerts are created only once per flow so repeated ML predictions for the
    same active flow do not flood the Alerts page.
    """
    severity = (
        "critical" if confidence >= 95
        else "high" if confidence >= 85
        else "medium"
    )

    timestamp = datetime.now(timezone.utc)

    description = "\n".join([
        "A live network flow was classified as an attack by the CyberShield AI model.",
        "",
        f"Attack type: {attack_type}",
        f"Raw model score (uncalibrated): {confidence:.2f}%",
        f"Source IP: {flow.get('src', 'N/A')}",
        f"Destination IP: {flow.get('dst', 'N/A')}",
        f"Source Port: {flow.get('src_port', 'N/A')}",
        f"Destination Port: {flow.get('dst_port', 'N/A')}",
        f"Protocol: {flow.get('protocol', 'N/A')}",
        f"Flow packets: {flow.get('fwd_packets', 0) + flow.get('bwd_packets', 0):,}",
        f"Flow bytes: {flow.get('fwd_bytes', 0) + flow.get('bwd_bytes', 0):,}",
        f"Trigger packet size: {packet_length:,} bytes",
        f"Detected at: {timestamp.astimezone(IST).strftime('%d %b %Y, %I:%M:%S %p IST')}",
    ])

    try:
        with app.app_context():
            alert = Alert(
                title=f"Live model prediction: {attack_type}",
                description=description,
                severity=severity,
                status="open",
                source="Live network ML detection",
                user_id=user_id
            )

            db.session.add(alert)
            db.session.commit()

        app.logger.warning(
            "LIVE MODEL PREDICTION: user=%s type=%s raw_score=%.2f source=%s destination=%s",
            user_id,
            attack_type,
            confidence,
            flow.get("src", "N/A"),
            flow.get("dst", "N/A")
        )
        return True

    except Exception:
        with app.app_context():
            db.session.rollback()

        app.logger.exception("Failed to create live attack alert")
        return False


def load_live_detection_model():
    """Load and cache the existing CyberShield model for live inference."""
    global LIVE_MONITOR_MODEL_CACHE

    if LIVE_MONITOR_MODEL_CACHE is None:
        LIVE_MONITOR_MODEL_CACHE = load_detection_model()

    return LIVE_MONITOR_MODEL_CACHE


def add_packet_activity(user_id, packet):
    """Update counters and store JSON-safe packet activity for the UI."""
    state = get_live_monitor_state(user_id)

    packet_length = int(len(packet))
    now = datetime.now(timezone.utc)
    summary = packet.summary()

    protocol = "OTHER"
    src = "-"
    dst = "-"

    try:
        if packet.haslayer(TCP):
            protocol = "TCP"
            src = str(packet[IP].src if packet.haslayer(IP) else packet[IPv6].src)
            dst = str(packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src = str(packet[IP].src if packet.haslayer(IP) else packet[IPv6].src)
            dst = str(packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst)

        elif packet.haslayer(IP):
            protocol = "IP"
            src = str(packet[IP].src)
            dst = str(packet[IP].dst)

        elif packet.haslayer(IPv6):
            protocol = "IPv6"
            src = str(packet[IPv6].src)
            dst = str(packet[IPv6].dst)

        elif packet.haslayer(UDP):
            protocol = "UDP"

    except Exception:
        protocol = "OTHER"

    event = {
        "timestamp": now.isoformat(),
        "time": now.astimezone(IST).strftime("%I:%M:%S %p"),
        "protocol": protocol,
        "src": src,
        "dst": dst,
        "summary": summary,
        "length": packet_length,
        "threat": False
    }

    state["packet_count"] += 1
    state["byte_count"] += packet_length

    # The HTML monitor reads `events`. Keep the older packet_activity
    # list as well so existing Phase 2 state remains compatible.
    state["events"].append(event)
    state["events"] = state["events"][-25:]

    state["packet_activity"].append({
        "time": event["time"],
        "message": summary
    })
    state["packet_activity"] = state["packet_activity"][-25:]

    # Phase 3: aggregate TCP/UDP packets into bidirectional flows and
    # score mature flows with the existing CyberShield model.
    update_live_flow(user_id, packet)


def packet_capture_worker(user_id, interface):
    """Capture packets until the monitor is stopped."""
    state = get_live_monitor_state(user_id)

    if not SCAPY_AVAILABLE:
        state["running"] = False
        state["message"] = (
            "Scapy is not available. Install it in the CyberShield virtual environment."
        )
        return

    try:
        sniffer = AsyncSniffer(
            iface=interface,
            prn=lambda packet: add_packet_activity(user_id, packet),
            store=False
        )

        LIVE_MONITOR_RUNTIME[user_id] = sniffer
        sniffer.start()

        state["message"] = (
            "Live packet capture is active. Waiting for network traffic."
        )

    except Exception as error:
        LIVE_MONITOR_RUNTIME.pop(user_id, None)
        state["running"] = False
        state["message"] = (
            "Packet capture could not start: "
            f"{concise_error_message(error)}"
        )
        app.logger.exception("Live Monitor capture failed to start")


def refresh_capture_status(user_id):
    """Reflect capture-thread failures in the monitor state."""
    state = get_live_monitor_state(user_id)
    sniffer = LIVE_MONITOR_RUNTIME.get(user_id)

    if not state["running"] or sniffer is None:
        return

    thread = getattr(sniffer, "thread", None)
    if getattr(sniffer, "running", False) or (
        thread is not None and thread.is_alive()
    ):
        return

    error = getattr(sniffer, "exception", None)
    state["running"] = False
    state["message"] = (
        "Packet capture stopped unexpectedly: "
        f"{concise_error_message(error)}"
        if error
        else "Packet capture stopped unexpectedly. Check the selected interface and capture permissions."
    )
    LIVE_MONITOR_RUNTIME.pop(user_id, None)

    if error:
        app.logger.error("Live Monitor capture thread stopped: %s", error)


def stop_packet_capture(user_id):
    """Stop the Scapy sniffer for one user, if it is running."""
    sniffer = LIVE_MONITOR_RUNTIME.pop(user_id, None)

    if sniffer is None:
        return None

    try:
        sniffer.stop()
        return None
    except Exception as error:
        app.logger.warning("Live Monitor sniffer stop warning: %s", error)
        return concise_error_message(error)


app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    ""
)
app.config["SECRET_KEY"] = resolve_secret_key(
    APP_ENV,
    app.config["SECRET_KEY"]
)
app.config["APP_ENV"] = APP_ENV
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_ENV == "production"

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///cybersecurity.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = UPLOAD_MAX_SIZE

db.init_app(app)
login_manager.init_app(app)
csrf.init_app(app)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault(
        "Referrer-Policy",
        "strict-origin-when-cross-origin"
    )
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()"
    )
    return response


# --------------------------------------------------
# DATE AND TIME DISPLAY
# Store timestamps in UTC; display them in Indian Standard Time.
# SQLite may return timezone-naive datetimes, so treat those as UTC.
# --------------------------------------------------

IST = ZoneInfo("Asia/Kolkata")


@app.template_filter("datetime12")
def format_datetime_ist(value):
    if value is None:
        return "N/A"

    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return value

    if not isinstance(value, datetime):
        return str(value)

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(IST).strftime("%d %b %Y, %I:%M:%S %p")


# --------------------------------------------------
# FILE SIZE ERROR HANDLER
# --------------------------------------------------

@app.errorhandler(413)
def request_entity_too_large(error):
    flash(
        "The uploaded file is larger than the 100 MB upload limit. "
        "Please choose a smaller CSV file.",
        "error"
    )
    return redirect(url_for("analysis"))


# --------------------------------------------------
# DATABASE MODELS
# Existing database structure preserved.
# --------------------------------------------------

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(
            self.password_hash,
            password
        )


class AnalysisRun(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    total_records = db.Column(
        db.Integer,
        default=0
    )

    threats_detected = db.Column(
        db.Integer,
        default=0
    )

    status = db.Column(
        db.String(40),
        default="completed"
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True
    )


class Alert(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(200),
        nullable=False
    )

    description = db.Column(
        db.Text,
        default=""
    )

    severity = db.Column(
        db.String(20),
        default="medium"
    )

    status = db.Column(
        db.String(20),
        default="open"
    )

    source = db.Column(
        db.String(120),
        default="Dataset analysis"
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True
    )


# --------------------------------------------------
# LOGIN MANAGER
# --------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def is_safe_redirect_target(target):
    """Accept only same-site absolute paths for post-login redirects."""
    if (
        not target
        or "\\" in target
        or any(ord(char) < 32 for char in target)
    ):
        return False

    decoded_target = unquote(target)
    parsed = urlsplit(decoded_target)

    return (
        decoded_target.startswith("/")
        and not decoded_target.startswith("//")
        and not parsed.scheme
        and not parsed.netloc
        and "\\" not in decoded_target
        and "%2f" not in decoded_target.casefold()
        and "%5c" not in decoded_target.casefold()
    )


@app.context_processor
def inject_navigation_state():
    return {
        "active_user": current_user
    }


# --------------------------------------------------
# MACHINE-LEARNING INFERENCE LIVES IN ml/inference.py
# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
@login_required
def home():

    total_analyses = AnalysisRun.query.filter_by(
        user_id=current_user.id
    ).count()

    total_threats = db.session.query(
        db.func.coalesce(
            db.func.sum(AnalysisRun.threats_detected),
            0
        )
    ).filter_by(
        user_id=current_user.id
    ).scalar()

    critical_alerts = Alert.query.filter_by(
        user_id=current_user.id,
        severity="critical",
        status="open"
    ).count()

    recent_alerts = Alert.query.filter_by(
        user_id=current_user.id
    ).order_by(
        Alert.created_at.desc()
    ).limit(5).all()

    latest_run = AnalysisRun.query.filter_by(
        user_id=current_user.id
    ).order_by(
        AnalysisRun.created_at.desc()
    ).first()

    return render_template(
        "dashboard.html",
        total_analyses=total_analyses,
        total_threats=total_threats or 0,
        critical_alerts=critical_alerts,
        recent_alerts=recent_alerts,
        latest_run=latest_run,
        model_ready=MODEL_PATH.is_file()
    )


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if len(username) < 3 or len(username) > 80:
            flash(
                "Username must be between 3 and 80 characters.",
                "error"
            )

        elif "@" not in email or len(email) > 120:
            flash(
                "Enter a valid email address.",
                "error"
            )

        elif len(password) < 12:
            flash(
                "Password must be at least 12 characters.",
                "error"
            )

        elif password != confirm_password:
            flash(
                "Passwords do not match.",
                "error"
            )

        elif User.query.filter(
            db.or_(
                User.username == username,
                User.email == email
            )
        ).first():
            flash(
                "That username or email is already registered.",
                "error"
            )

        else:
            user = User(
                username=username,
                email=email
            )

            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            login_user(user)

            flash(
                "Your account has been created successfully.",
                "success"
            )

            return redirect(url_for("home"))

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":

        identity = request.form.get(
            "identity", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        user = User.query.filter(
            db.or_(
                User.username == identity,
                User.email == identity.lower()
            )
        ).first()

        if user and user.check_password(password):

            login_user(user)

            flash(
                "Welcome back!",
                "success"
            )

            next_url = request.args.get("next", "")

            if is_safe_redirect_target(next_url):
                return redirect(next_url)

            return redirect(url_for("home"))

        flash(
            "Invalid username/email or password.",
            "error"
        )

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))


# --------------------------------------------------
# DATASET ANALYSIS AND CSV UPLOAD
# --------------------------------------------------

@app.route("/analysis", methods=["GET", "POST"])
@login_required
def analysis():

    result = None

    if request.method == "POST":

        uploaded_file = request.files.get("dataset")

        if uploaded_file is None or not uploaded_file.filename:

            flash(
                "No CSV file was received. Select a file and try again.",
                "error"
            )

        else:

            filename = secure_filename(
                uploaded_file.filename
            )

            try:
                uploaded_file.stream.seek(0, os.SEEK_END)
                uploaded_size = uploaded_file.stream.tell()
                uploaded_file.stream.seek(0)

            except (OSError, AttributeError):
                uploaded_size = None
                uploaded_file.stream.seek(0)

            if uploaded_size == 0:

                flash(
                    "The selected file contains 0 bytes. "
                    "Check the CSV file and select it again.",
                    "error"
                )

            elif not filename.lower().endswith(".csv"):

                flash(
                    "Only CSV files are supported.",
                    "error"
                )

            else:

                try:

                    uploaded_file.stream.seek(0)

                    result = analyze_uploaded_csv(
                        uploaded_file.stream
                    )

                    analysis_run = AnalysisRun(
                        filename=filename,
                        total_records=result["total_records"],
                        threats_detected=result["threats_detected"],
                        status="completed",
                        user_id=current_user.id
                    )

                    db.session.add(analysis_run)

                    # Create one investigation alert per detected attack category.
                    if result["threats_detected"] > 0:

                        for attack in result.get("attack_breakdown", []):

                            attack_type = str(
                                attack.get("attack_type", "Unknown")
                            ).strip()

                            attack_count = int(attack.get("count", 0))
                            attack_percentage = float(
                                attack.get("percentage", 0)
                            )
                            average_confidence = float(
                                attack.get("average_confidence", 0)
                            )

                            if attack_count <= 0:
                                continue

                            # Relative alert-priority heuristic, not impact scoring.
                            if attack_percentage >= 50:
                                severity = "critical"
                            elif attack_percentage >= 10:
                                severity = "high"
                            else:
                                severity = "medium"

                            description_lines = [
                                (
                                    f"{attack_count:,} records classified as "
                                    f"{attack_type} were detected. "
                                    f"This represents {attack_percentage:.2f}% "
                                    f"of all detected attack records."
                                ),
                                f"Dataset: {filename}.",
                                (
                                    f"Total analyzed records: "
                                    f"{result['total_records']:,}."
                                ),
                                (
                                    f"Average raw model score for this "
                                    f"attack category (uncalibrated): "
                                    f"{average_confidence:.2f}%."
                                ),
                                "",
                                "REPRESENTATIVE FLOW DETAILS (up to 3 samples):"
                            ]

                            flow_samples = attack.get("flow_samples", [])

                            if not flow_samples:
                                description_lines.append(
                                    "No representative flow details were available."
                                )

                            for sample_number, sample in enumerate(
                                flow_samples, start=1
                            ):
                                details = sample.get("details", {})

                                description_lines.extend([
                                    "",
                                    (
                                        f"Sample {sample_number} "
                                        f"(raw model score, uncalibrated: "
                                        f"{sample.get('confidence', 0):.2f}%):"
                                    ),
                                    f"Source IP: {details.get('source_ip', 'N/A')}",
                                    (
                                        f"Destination IP: "
                                        f"{details.get('destination_ip', 'N/A')}"
                                    ),
                                    f"Source Port: {details.get('source_port', 'N/A')}",
                                    (
                                        f"Destination Port: "
                                        f"{details.get('destination_port', 'N/A')}"
                                    ),
                                    f"Protocol: {details.get('protocol', 'N/A')}",
                                    f"Timestamp: {details.get('timestamp', 'N/A')}",
                                    (
                                        f"Flow Duration: "
                                        f"{details.get('flow_duration', 'N/A')}"
                                    ),
                                    (
                                        f"Forward Packets: "
                                        f"{details.get('total_fwd_packets', 'N/A')}"
                                    ),
                                    (
                                        f"Backward Packets: "
                                        f"{details.get('total_bwd_packets', 'N/A')}"
                                    )
                                ])

                            alert = Alert(
                                title=f"{attack_type} Detected",
                                description="\\n".join(description_lines),
                                severity=severity,
                                status="open",
                                source="CSV machine-learning analysis",
                                user_id=current_user.id
                            )

                            db.session.add(alert)

                    db.session.commit()

                    result["filename"] = filename

                    flash(
                        "CSV analysis completed successfully.",
                        "success"
                    )

                except (
                    ValueError,
                    FileNotFoundError,
                    pd.errors.ParserError,
                    UnicodeError
                ) as error:

                    db.session.rollback()

                    result = None

                    flash(
                        f"Analysis failed: {error}",
                        "error"
                    )

                    app.logger.warning(
                        "CSV analysis failed: %s",
                        error
                    )

                except Exception:

                    db.session.rollback()

                    result = None

                    app.logger.exception(
                        "Unexpected CSV analysis error"
                    )

                    flash(
                        "An unexpected error occurred during analysis. "
                        "Check the server terminal for details.",
                        "error"
                    )

    runs = AnalysisRun.query.filter_by(
        user_id=current_user.id
    ).order_by(
        AnalysisRun.created_at.desc()
    ).limit(20).all()

    return render_template(
        "analysis.html",
        runs=runs,
        result=result,
        model_ready=MODEL_PATH.is_file()
    )


# --------------------------------------------------
# ALERTS
# --------------------------------------------------

@app.route("/alerts")
@login_required
def alerts():

    user_alerts = Alert.query.filter_by(
        user_id=current_user.id
    ).order_by(
        Alert.created_at.desc()
    ).all()

    return render_template(
        "alerts.html",
        alerts=user_alerts
    )


@app.route(
    "/alerts/<int:alert_id>/resolve",
    methods=["POST"]
)
@login_required
def resolve_alert(alert_id):

    alert = Alert.query.filter_by(
        id=alert_id,
        user_id=current_user.id
    ).first_or_404()

    alert.status = "resolved"

    db.session.commit()

    flash(
        "Alert marked as resolved.",
        "success"
    )

    return redirect(url_for("alerts"))



# --------------------------------------------------
# LIVE MONITOR - PHASE 2
# --------------------------------------------------

@app.route("/monitor")
@login_required
def monitor():
    state = get_live_monitor_state(current_user.id)
    interfaces = get_capture_interfaces()
    default_interface = get_default_capture_interface()
    capture_backend_error = get_capture_backend_error()
    if capture_backend_error and not state["running"]:
        state["message"] = capture_backend_error

    return render_template(
        "monitor.html",
        monitor=state,
        scapy_available=SCAPY_AVAILABLE,
        interfaces=interfaces,
        default_interface=default_interface,
        capture_backend_error=capture_backend_error
    )


@app.route("/monitor/start", methods=["POST"])
@login_required
def start_monitor():
    state = get_live_monitor_state(current_user.id)

    if state["running"]:
        return jsonify({
            "success": True,
            "message": "Live Monitor is already running.",
            "monitor": state
        })

    if not SCAPY_AVAILABLE:
        return jsonify({
            "success": False,
            "message": "Scapy is not available in the current Python environment.",
            "monitor": state
        }), 500

    capture_backend_error = get_capture_backend_error()
    if capture_backend_error:
        state["running"] = False
        state["message"] = capture_backend_error
        return jsonify({
            "success": False,
            "message": capture_backend_error,
            "monitor": state
        }), 503

    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}

    if not isinstance(payload, dict):
        return jsonify({
            "success": False,
            "message": "Invalid monitor start request.",
            "monitor": state
        }), 400

    requested_interface = payload.get("interface")
    if requested_interface is not None and not isinstance(requested_interface, str):
        return jsonify({
            "success": False,
            "message": "The selected network interface must be a string.",
            "monitor": state
        }), 400

    interface = (
        requested_interface or get_default_capture_interface()
    ).strip()
    interfaces = get_capture_interfaces()

    if not interfaces:
        return jsonify({
            "success": False,
            "message": "Scapy found no capture interfaces. Check that Npcap is installed and running.",
            "monitor": state
        }), 503

    interface_values = {
        available_interface["value"]
        for available_interface in interfaces
    }

    if interface not in interface_values:
        return jsonify({
            "success": False,
            "message": "The selected network interface is not available. Refresh the page and choose an available interface.",
            "monitor": state
        }), 400

    state["running"] = True
    state["started_at"] = datetime.now(timezone.utc).isoformat()
    state["packet_count"] = 0
    state["byte_count"] = 0
    state["events"] = []
    state["packet_activity"] = []
    state["threat_count"] = 0
    state["flows_observed"] = 0
    state["flows_analyzed"] = 0
    state["benign_predictions"] = 0
    state["attack_predictions"] = 0
    state["alerts_created"] = 0
    state["inference_errors"] = 0
    state["model_features"] = 0
    state["last_prediction"] = "Not analyzed yet"
    LIVE_MONITOR_FLOWS[current_user.id] = {}
    state["interface"] = interface
    state["message"] = "Starting live packet capture..."

    packet_capture_worker(current_user.id, interface)

    if not state["running"]:
        return jsonify({
            "success": False,
            "message": state["message"],
            "monitor": state
        }), 500

    return jsonify({
        "success": True,
        "message": "Live packet capture started successfully.",
        "monitor": state
    })


@app.route("/monitor/stop", methods=["POST"])
@login_required
def stop_monitor():
    state = get_live_monitor_state(current_user.id)

    if not state["running"]:
        return jsonify({
            "success": True,
            "message": "Live Monitor is already stopped.",
            "monitor": state
        })

    stop_error = stop_packet_capture(current_user.id)
    LIVE_MONITOR_FLOWS.pop(current_user.id, None)

    state["running"] = False
    state["message"] = (
        f"Live Monitor stopped with a capture warning: {stop_error}"
        if stop_error
        else "Live Monitor stopped. Packet capture has been stopped safely."
    )

    return jsonify({
        "success": True,
        "message": "Live Monitor stopped.",
        "monitor": state
    })


@app.route("/api/monitor/status")
@login_required
def monitor_status():
    refresh_capture_status(current_user.id)
    state = get_live_monitor_state(current_user.id)

    return jsonify({
        "success": True,
        "monitor": state
    })


# --------------------------------------------------
# REPORTS
# --------------------------------------------------

@app.route("/reports")
@login_required
def reports():

    runs = AnalysisRun.query.filter_by(
        user_id=current_user.id
    ).order_by(
        AnalysisRun.created_at.desc()
    ).all()

    return render_template(
        "reports.html",
        runs=runs
    )


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():

    css_file = BASE_DIR / "static" / "css" / "style.css"

    model_ready = MODEL_PATH.is_file()
    model_type = "unavailable"

    if model_ready:
        try:
            saved_data = joblib.load(MODEL_PATH)
            model_type = saved_data.get(
                "model_type",
                "binary"
            )
        except Exception:
            model_type = "invalid"

    return jsonify({
        "status": "ok",
        "app": "CyberShield AI",
        "css_file_exists": css_file.is_file(),
        "model_exists": model_ready,
        "model_type": model_type,
        "database_configured": bool(
            app.config["SQLALCHEMY_DATABASE_URI"]
        )
    })


# --------------------------------------------------
# DATABASE COMMANDS
# --------------------------------------------------

@app.cli.command("init-db")
def init_db():

    """Create database tables."""

    with app.app_context():
        db.create_all()

    click.echo(
        "Database tables created successfully."
    )


@app.cli.command("create-admin")
def create_admin():

    """Create an administrator account interactively."""

    with app.app_context():

        db.create_all()

        username = click.prompt(
            "Username"
        ).strip()

        email = click.prompt(
            "Email"
        ).strip().lower()

        password = click.prompt(
            "Password",
            hide_input=True,
            confirmation_prompt=True
        )

        if len(password) < 12:
            raise click.ClickException(
                "Password must be at least 12 characters."
            )

        if User.query.filter(
            db.or_(
                User.username == username,
                User.email == email
            )
        ).first():
            raise click.ClickException(
                "Username or email already exists."
            )

        user = User(
            username=username,
            email=email
        )

        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        click.echo(
            "Account created successfully."
        )


# --------------------------------------------------
# CREATE DATABASE TABLES
# --------------------------------------------------

with app.app_context():
    db.create_all()


# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )