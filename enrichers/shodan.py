# queries shodan for open ports, services, and org info on an ip

import requests

BASE_URL = "https://api.shodan.io/shodan/host"


def enrich(ioc: str, api_key: str) -> dict:
    url = f"{BASE_URL}/{ioc}"
    params = {"key": api_key}

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        return {
            "org": data.get("org", "unknown"),
            "country": data.get("country_name", "unknown"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
        }

    except requests.exceptions.HTTPError:
        return {"error": f"http {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
