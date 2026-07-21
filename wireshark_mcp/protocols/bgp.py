"""
BGP protocol analyzer for message-type decoding, session summary, and notifications.
"""

from typing import Dict, List, Any
from collections import defaultdict

from .base import BaseProtocolAnalyzer


BGP_TYPE_NAMES = {
    "1": "OPEN",
    "2": "UPDATE",
    "3": "NOTIFICATION",
    "4": "KEEPALIVE",
    "5": "ROUTE-REFRESH",
}

BGP_MAJOR_ERRORS = {
    "1": "Message Header Error",
    "2": "OPEN Message Error",
    "3": "UPDATE Message Error",
    "4": "Hold Timer Expired",
    "5": "Finite State Machine Error",
    "6": "Cease",
}

BGP_OPEN_MINOR = {
    "1": "Unsupported Version Number",
    "2": "Bad Peer AS",
    "3": "Bad BGP Identifier",
    "4": "Unsupported Optional Parameter",
    "5": "Deprecated",
    "6": "Unacceptable Hold Time",
    "7": "Unsupported Capability",
}

BGP_CEASE_MINOR = {
    "1": "Maximum Number of Prefixes Reached",
    "2": "Administrative Shutdown",
    "3": "Peer Unconfigured",
    "4": "Administrative Reset",
    "5": "Connection Rejected",
    "6": "Other Configuration Change",
    "7": "Connection Collision Resolution",
    "8": "Out of Resources",
    "9": "Hard Reset",
}


class BGPProtocolAnalyzer(BaseProtocolAnalyzer):
    """Analyze BGP OPEN/UPDATE/NOTIFICATION/KEEPALIVE exchanges."""

    protocol_name = "BGP"

    def extract_features(
        self,
        packets: List[Dict[str, Any]],
        include_headers: bool = True,
        include_body: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        bgp_packets = self._filter_packets(packets, "bgp")
        # Also accept packets that already have a decoded bgp dict (fields path)
        if not bgp_packets:
            bgp_packets = [p for p in packets if "bgp" in p]

        messages: List[Dict[str, Any]] = []
        type_counts: Dict[str, int] = defaultdict(int)
        sessions: Dict[str, Dict[str, Any]] = {}
        notifications: List[Dict[str, Any]] = []
        opens: List[Dict[str, Any]] = []
        updates: List[Dict[str, Any]] = []
        prefixes_announced: Dict[str, int] = defaultdict(int)
        prefixes_withdrawn: Dict[str, int] = defaultdict(int)

        for packet in bgp_packets:
            bgp = packet.get("bgp", {})
            if not bgp:
                continue

            src_ip = packet.get("ip", {}).get("src") or bgp.get("src_ip", "")
            dst_ip = packet.get("ip", {}).get("dst") or bgp.get("dst_ip", "")
            src_port = packet.get("tcp", {}).get("srcport") or bgp.get("src_port", "")
            dst_port = packet.get("tcp", {}).get("dstport") or bgp.get("dst_port", "")
            timestamp = packet.get("timestamp")

            raw_types = bgp.get("types") or bgp.get("type") or []
            if isinstance(raw_types, str):
                type_list = [t.strip() for t in raw_types.split(",") if t.strip()]
            elif isinstance(raw_types, list):
                type_list = [str(t).strip() for t in raw_types if str(t).strip()]
            else:
                type_list = [str(raw_types)] if raw_types not in (None, "") else []

            if not type_list:
                continue

            session_key = self._session_key(src_ip, src_port, dst_ip, dst_port)
            session = sessions.setdefault(
                session_key,
                {
                    "session": session_key,
                    "peers": sorted({p for p in (src_ip, dst_ip) if p}),
                    "message_count": 0,
                    "types": defaultdict(int),
                    "open": [],
                    "notifications": [],
                    "first_ts": timestamp,
                    "last_ts": timestamp,
                },
            )
            session["message_count"] += 1
            if timestamp is not None:
                if session["first_ts"] is None or timestamp < session["first_ts"]:
                    session["first_ts"] = timestamp
                if session["last_ts"] is None or timestamp > session["last_ts"]:
                    session["last_ts"] = timestamp

            for type_code in type_list:
                type_name = BGP_TYPE_NAMES.get(type_code, f"unknown({type_code})")
                type_counts[type_name] += 1
                session["types"][type_name] += 1

                msg = {
                    "timestamp": timestamp,
                    "type": type_code,
                    "type_name": type_name,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "session": session_key,
                }

                if type_code == "1":  # OPEN
                    open_info = {
                        **msg,
                        "version": bgp.get("open_version") or bgp.get("version", ""),
                        "my_as": bgp.get("open_my_as") or bgp.get("my_as", ""),
                        "hold_time": bgp.get("open_hold_time") or bgp.get("hold_time", ""),
                        "identifier": bgp.get("open_identifier") or bgp.get("identifier", ""),
                    }
                    opens.append(open_info)
                    session["open"].append(open_info)
                    messages.append(open_info)
                elif type_code == "2":  # UPDATE
                    nlri = self._as_list(bgp.get("nlri_prefix") or bgp.get("nlri") or [])
                    withdrawn = self._as_list(
                        bgp.get("withdrawn_prefix") or bgp.get("withdrawn") or []
                    )
                    next_hop = bgp.get("next_hop", "")
                    update_info = {
                        **msg,
                        "nlri": nlri,
                        "withdrawn": withdrawn,
                        "next_hop": next_hop,
                        "nlri_count": len(nlri),
                        "withdrawn_count": len(withdrawn),
                    }
                    for pfx in nlri:
                        prefixes_announced[pfx] += 1
                    for pfx in withdrawn:
                        prefixes_withdrawn[pfx] += 1
                    updates.append(update_info)
                    messages.append(update_info)
                elif type_code == "3":  # NOTIFICATION
                    major = str(bgp.get("notify_major") or bgp.get("major_error") or "")
                    minor = str(
                        bgp.get("notify_minor")
                        or bgp.get("minor_error")
                        or bgp.get("notify_minor_open")
                        or bgp.get("notify_minor_cease")
                        or ""
                    )
                    major_name = BGP_MAJOR_ERRORS.get(major, f"unknown({major})")
                    if major == "2":
                        minor_name = BGP_OPEN_MINOR.get(minor, f"unknown({minor})" if minor else "")
                    elif major == "6":
                        minor_name = BGP_CEASE_MINOR.get(minor, f"unknown({minor})" if minor else "")
                    else:
                        minor_name = minor or ""
                    notif = {
                        **msg,
                        "major_error": major,
                        "major_error_name": major_name,
                        "minor_error": minor,
                        "minor_error_name": minor_name,
                        "communication": bgp.get("notify_communication") or bgp.get("communication", ""),
                    }
                    notifications.append(notif)
                    session["notifications"].append(notif)
                    messages.append(notif)
                else:
                    messages.append(msg)

        # Finalize session type counters as plain dicts
        session_list = []
        for session in sessions.values():
            session_list.append({
                **session,
                "types": dict(session["types"]),
            })
        session_list.sort(key=lambda s: s["message_count"], reverse=True)

        return {
            "messages": messages[:500],
            "opens": opens,
            "updates": updates[:200],
            "notifications": notifications,
            "sessions": session_list,
            "statistics": {
                "total_bgp_packets": len(bgp_packets),
                "total_messages": sum(type_counts.values()),
                "message_types": dict(type_counts),
                "session_count": len(session_list),
                "notification_count": len(notifications),
                "open_count": len(opens),
                "update_count": len(updates),
                "unique_prefixes_announced": len(prefixes_announced),
                "unique_prefixes_withdrawn": len(prefixes_withdrawn),
                "top_announced_prefixes": dict(
                    sorted(prefixes_announced.items(), key=lambda x: x[1], reverse=True)[:20]
                ),
                "top_withdrawn_prefixes": dict(
                    sorted(prefixes_withdrawn.items(), key=lambda x: x[1], reverse=True)[:20]
                ),
            },
        }

    def generate_context(
        self,
        features: Dict[str, Any],
        detail_level: int = 2,
        max_conversations: int = 20,
        **kwargs,
    ) -> Dict[str, Any]:
        stats = features.get("statistics", {})
        sessions = features.get("sessions", [])[:max_conversations]
        notifications = features.get("notifications", [])
        opens = features.get("opens", [])[:max_conversations]

        findings = []
        types = stats.get("message_types", {})
        if notifications:
            findings.append(
                f"{len(notifications)} BGP NOTIFICATION message(s) observed."
            )
            for n in notifications[:5]:
                detail = n.get("major_error_name", "")
                if n.get("minor_error_name"):
                    detail = f"{detail} / {n['minor_error_name']}"
                findings.append(
                    f"NOTIFICATION {n.get('src_ip')} → {n.get('dst_ip')}: {detail}"
                )
        if types.get("KEEPALIVE") and not types.get("UPDATE") and not types.get("OPEN"):
            findings.append("Only KEEPALIVE messages seen (no OPEN/UPDATE in sampled traffic).")
        if stats.get("unique_prefixes_withdrawn"):
            findings.append(
                f"{stats['unique_prefixes_withdrawn']} unique prefix(es) withdrawn."
            )
        if stats.get("unique_prefixes_announced"):
            findings.append(
                f"{stats['unique_prefixes_announced']} unique prefix(es) announced."
            )

        return {
            "protocol": "BGP",
            "summary": {
                "total_bgp_packets": stats.get("total_bgp_packets", 0),
                "total_messages": stats.get("total_messages", 0),
                "sessions": stats.get("session_count", 0),
                "opens": stats.get("open_count", 0),
                "updates": stats.get("update_count", 0),
                "notifications": stats.get("notification_count", 0),
                "keepalives": types.get("KEEPALIVE", 0),
                "message_types": types,
            },
            "statistics": stats,
            "findings": findings,
            "sessions": sessions,
            "notifications": notifications,
            "opens": opens if detail_level >= 2 else opens[:5],
            "sample_updates": features.get("updates", [])[:20] if detail_level >= 2 else [],
        }

    @staticmethod
    def _session_key(src_ip: str, src_port: Any, dst_ip: str, dst_port: Any) -> str:
        a = f"{src_ip}:{src_port}"
        b = f"{dst_ip}:{dst_port}"
        if a <= b:
            return f"{a}-{b}"
        return f"{b}-{a}"

    @staticmethod
    def _as_list(value: Any) -> List[str]:
        if value is None or value == "":
            return []
        if isinstance(value, list):
            return [str(v) for v in value if v not in (None, "")]
        text = str(value).strip()
        if not text:
            return []
        # tshark may join with commas
        return [p.strip() for p in text.replace(",", " ").split() if p.strip()]
