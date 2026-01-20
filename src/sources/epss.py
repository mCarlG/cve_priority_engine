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

            print(data)

        # TODO: Add actual exception handling
        except Exception as e:
            print(f"[!] Some error in EPSS request for CVE {cve_ID}: {e}")
            return None
