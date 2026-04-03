# writes enrichment results to a markdown file

from pathlib import Path


def write_report(results: dict) -> None:
    ioc = results["ioc"]
    ioc_type = results["type"]

    # sanitise ioc for use as a filename
    safe_name = ioc.replace("/", "_").replace(":", "_")
    output_path = Path(f"{safe_name}_report.md")

    lines = [
        "# ioc enrichment report",
        "",
        f"**ioc:** `{ioc}`  ",
        f"**type:** {ioc_type}",
        "",
    ]

    # virustotal section
    lines.append("## virustotal")
    vt = results.get("virustotal")
    if vt and "error" not in vt:
        lines.append(f"- malicious: {vt['malicious']}")
        lines.append(f"- suspicious: {vt['suspicious']}")
        lines.append(f"- harmless: {vt['harmless']}")
        lines.append(f"- undetected: {vt['undetected']}")
    elif vt:
        lines.append(f"- error: {vt['error']}")
    else:
        lines.append("- not queried (no api key or unsupported ioc type)")
    lines.append("")

    # abuseipdb section — only populated for ip iocs
    lines.append("## abuseipdb")
    abuse = results.get("abuseipdb")
    if abuse and "error" not in abuse:
        lines.append(f"- confidence score: {abuse['abuse_confidence_score']}%")
        lines.append(f"- total reports: {abuse['total_reports']}")
        lines.append(f"- country: {abuse['country']}")
        lines.append(f"- isp: {abuse['isp']}")
        lines.append(f"- tor exit node: {abuse['is_tor']}")
    elif abuse:
        lines.append(f"- error: {abuse['error']}")
    else:
        lines.append("- not queried (ip iocs only)")
    lines.append("")

    # shodan section — only populated for ip iocs
    lines.append("## shodan")
    shodan = results.get("shodan")
    if shodan and "error" not in shodan:
        ports = ", ".join(map(str, shodan["ports"])) or "none"
        hostnames = ", ".join(shodan["hostnames"]) or "none"
        lines.append(f"- org: {shodan['org']}")
        lines.append(f"- country: {shodan['country']}")
        lines.append(f"- open ports: {ports}")
        lines.append(f"- hostnames: {hostnames}")
    elif shodan:
        lines.append(f"- error: {shodan['error']}")
    else:
        lines.append("- not queried (ip iocs only)")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[*] markdown report saved to {output_path}")
