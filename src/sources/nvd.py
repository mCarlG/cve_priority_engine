import requests, time

class NVDClient:
    URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT = 6 # Seconds between requests.

    def __init__(self):
        self.session = requests.Session()

    def _rate_limit(self):
        time.sleep(RATE_LIMIT)

    def fetch(self, cveId):
        self._rate_limit()

        try:
            response = self.session.get(self.URL, params={"cveId": cveId}, timeout=10)
            response.raise_for_status()
            data = response.json()

            if !data.get("vulnerabilities"):
                return None

            vuln = data["vulnerabilities"][0]["cve"]
            #TODO: figure out the way in which the json should be deserialized. Here? Maybe in formatting?
            return vuln

        # TODO: Add actual exception handling
        except Exception as e:
            print(f"[!] Some error in NVD request for CVE {cveID}: {e}")
            return None
