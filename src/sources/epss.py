import requests

class EPSS_Client:
    URL = "https://api.first.org/data/v1/epss"

    def __init__(self):
        self.session = requests.Session()

    def fetch(self, cve_ID):
        try:
            response = self.session.get(self.URL, params={"cve": cve_ID}, timeout=10)
            response.raise_for_status()
            data = response.json()

            if entry := data.get("data", []):
                entry = entry[0]
                return {
                    "epss_Score": float(entry.get("epss", 0)),
                    "epss_Percentile": float(entry.get("percentile", 0)),
                }

        # TODO: Add actual exception handling
        except Exception as e:
            print(f"[!] Some error in EPSS request for CVE {cve_ID}: {e}")
            return None
