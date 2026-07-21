"""
ARP protocol analyzer for request/reply correlation and lost-ARP detection.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict

from .base import BaseProtocolAnalyzer


class ARPProtocolAnalyzer(BaseProtocolAnalyzer):
    """Analyze ARP who-has / is-at exchanges and find unanswered requests."""

    protocol_name = "ARP"

    OPCODE_REQUEST = "1"
    OPCODE_REPLY = "2"

    def extract_features(
        self,
        packets: List[Dict[str, Any]],
        include_headers: bool = True,
        include_body: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        arp_packets = self._filter_packets(packets, "arp")

        requests: List[Dict[str, Any]] = []
        replies: List[Dict[str, Any]] = []
        by_target: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(
            lambda: {"requests": [], "replies": []}
        )
        requesters = defaultdict(int)
        targets = defaultdict(int)

        for packet in arp_packets:
            arp = packet.get("arp", {})
            if not arp:
                continue

            opcode = str(arp.get("opcode", ""))
            record = {
                "timestamp": packet.get("timestamp"),
                "opcode": opcode,
                "opcode_name": arp.get("opcode_name")
                or ("request" if opcode == self.OPCODE_REQUEST else
                    "reply" if opcode == self.OPCODE_REPLY else f"unknown({opcode})"),
                "sender_ip": arp.get("sender_ip") or arp.get("arp.src.proto_ipv4", ""),
                "sender_mac": arp.get("sender_mac") or arp.get("arp.src.hw_mac", ""),
                "target_ip": arp.get("target_ip") or arp.get("arp.dst.proto_ipv4", ""),
                "target_mac": arp.get("target_mac") or arp.get("arp.dst.hw_mac", ""),
            }

            if opcode == self.OPCODE_REQUEST:
                requests.append(record)
                by_target[record["target_ip"]]["requests"].append(record)
                requesters[record["sender_ip"]] += 1
                targets[record["target_ip"]] += 1
            elif opcode == self.OPCODE_REPLY:
                replies.append(record)
                # Reply announces sender_ip (the resolved address)
                by_target[record["sender_ip"]]["replies"].append(record)

        unanswered = []
        answered = []
        for ip, buckets in by_target.items():
            if not ip:
                continue
            reqs = buckets["requests"]
            reps = buckets["replies"]
            if reqs and not reps:
                unanswered.append({
                    "target_ip": ip,
                    "request_count": len(reqs),
                    "requesters": sorted({r["sender_ip"] for r in reqs if r["sender_ip"]}),
                    "first_request_ts": reqs[0].get("timestamp"),
                    "last_request_ts": reqs[-1].get("timestamp"),
                    "sample_requests": reqs[:5],
                })
            elif reqs and reps:
                answered.append({
                    "target_ip": ip,
                    "request_count": len(reqs),
                    "reply_count": len(reps),
                    "resolved_mac": reps[0].get("sender_mac"),
                    "responders": sorted({r["sender_ip"] for r in reps if r["sender_ip"]}),
                })

        unanswered.sort(key=lambda x: x["request_count"], reverse=True)
        answered.sort(key=lambda x: x["request_count"], reverse=True)

        return {
            "packets": [self._brief(p) for p in (requests + replies)[:200]],
            "requests": requests,
            "replies": replies,
            "unanswered": unanswered,
            "answered": answered,
            "statistics": {
                "total_arp_packets": len(arp_packets),
                "request_count": len(requests),
                "reply_count": len(replies),
                "unique_targets_queried": len([ip for ip, b in by_target.items() if b["requests"]]),
                "unanswered_target_count": len(unanswered),
                "answered_target_count": len(answered),
                "top_requesters": dict(sorted(requesters.items(), key=lambda x: x[1], reverse=True)[:10]),
                "top_targets": dict(sorted(targets.items(), key=lambda x: x[1], reverse=True)[:10]),
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
        unanswered = features.get("unanswered", [])[:max_conversations]
        answered = features.get("answered", [])[:max_conversations]

        findings = []
        if stats.get("unanswered_target_count", 0):
            findings.append(
                f"{stats['unanswered_target_count']} ARP who-has target(s) got no reply "
                f"(lost/unanswered ARP)."
            )
        if stats.get("request_count", 0) and stats.get("reply_count", 0) == 0:
            findings.append("Capture contains ARP requests but zero replies.")
        if stats.get("top_requesters"):
            top = next(iter(stats["top_requesters"].items()))
            findings.append(f"Top ARP requester: {top[0]} ({top[1]} requests).")

        context = {
            "protocol": "ARP",
            "summary": {
                "total_arp_packets": stats.get("total_arp_packets", 0),
                "requests": stats.get("request_count", 0),
                "replies": stats.get("reply_count", 0),
                "unanswered_targets": stats.get("unanswered_target_count", 0),
                "answered_targets": stats.get("answered_target_count", 0),
            },
            "statistics": stats,
            "findings": findings,
            "unanswered_requests": unanswered,
            "answered_requests": answered if detail_level >= 2 else answered[:5],
        }

        if detail_level >= 3:
            context["sample_packets"] = features.get("packets", [])[:50]

        return context

    @staticmethod
    def _brief(record: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "opcode_name": record.get("opcode_name"),
            "sender_ip": record.get("sender_ip"),
            "sender_mac": record.get("sender_mac"),
            "target_ip": record.get("target_ip"),
            "target_mac": record.get("target_mac"),
            "timestamp": record.get("timestamp"),
        }
