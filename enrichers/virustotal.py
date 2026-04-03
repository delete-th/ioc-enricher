# queries the virustotal v3 api for ip, domain, or file hash reputation

import requests

BASE_URL = "https://www.virustotal.com/api/v3"

# maps our ioc type to the correct vt api endpoint segment
ENDPOINT_MAP = {
    "ip": "ip_addresses",
    "domain": "domains",
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
}


def enrich(ioc: str, ioc_type: str, api_key: str) -> dict:
    endpoint = ENDPOINT_MAP.get(ioc_type)
    if not endpoint:
        return {"error": f"unsupported ioc type for virustotal: {ioc_type}"}

    url = f"{BASE_URL}/{endpoint}/{ioc}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        # the detection stats are buried under data.attributes.last_analysis_stats
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    except requests.exceptions.HTTPError:
        return {"error": f"http {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
