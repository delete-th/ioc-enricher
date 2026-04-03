# queries abuseipdb v2 api for ip abuse reports and confidence score

import requests

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def enrich(ioc: str, api_key: str) -> dict:
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ioc,
        "maxAgeInDays": 90,  # look back 90 days for reports
        "verbose": True,
    }

    try:
        response = requests.get(BASE_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})

        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "unknown"),
            "isp": data.get("isp", "unknown"),
            "is_tor": data.get("isTor", False),
        }

    except requests.exceptions.HTTPError:
        return {"error": f"http {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
