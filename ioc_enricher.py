# main entry point — loads config, detects ioc type, runs enrichers, writes reports

import argparse
import json
from config import load_config
from detectors import detect
from enrichers.virustotal import enrich as vt_enrich
from enrichers.abuseipdb import enrich as abuse_enrich
from enrichers.shodan import enrich as shodan_enrich
from reporters.markdown import write_report as write_md
from reporters.docx import write_report as write_docx


def run(ioc: str, config: dict) -> dict:
    ioc_type = detect(ioc)
    print(f"[*] detected ioc type: {ioc_type}")

    results = {
        "ioc": ioc,
        "type": ioc_type,
        "virustotal": None,
        "abuseipdb": None,
        "shodan": None,
    }

    # virustotal supports ip, domain, and all hash types
    if config.get("virustotal"):
        results["virustotal"] = vt_enrich(ioc, ioc_type, config["virustotal"])

    # abuseipdb and shodan are ip-only sources
    if config.get("abuseipdb") and ioc_type == "ip":
        results["abuseipdb"] = abuse_enrich(ioc, config["abuseipdb"])

    if config.get("shodan") and ioc_type == "ip":
        results["shodan"] = shodan_enrich(ioc, config["shodan"])

    return results


def main():
    parser = argparse.ArgumentParser(description="enrich iocs against threat intel sources")
    parser.add_argument("ioc", nargs="?", help="ip, domain, or file hash to enrich")
    parser.add_argument("--json", action="store_true", help="save raw json output alongside reports")
    args = parser.parse_args()

    # fall back to interactive prompt if no ioc was passed as an argument
    if not args.ioc:
        args.ioc = input("enter ioc: ").strip()

    config = load_config()
    results = run(args.ioc, config)

    # always write both report formats
    write_md(results)
    write_docx(results)

    # optionally dump raw enrichment data as json
    if args.json:
        safe_name = results["ioc"].replace("/", "_").replace(":", "_")
        output_path = f"{safe_name}.json"
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] json saved to {output_path}")


if __name__ == "__main__":
    main()
