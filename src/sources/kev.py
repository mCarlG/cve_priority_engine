import requests

class KEVClient:
    URL = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self.session = requests.Session()
        self.cache = None # We can just pull the whole thing once.

    def fetch(self cveId):
        if self.cache == None:
            try:
                response = self.session.get(self.URL, timeout=10)
                response.raise_for_status()
                data = response.json()
                catalog = {}
                for vuln in data.get("vulnerabilities", []):
                    if currentCveId := vuln.get("cveID"): # I love these little walrus guys
                        catalog[currentCveId] = {
                            "kevDueDate": vuln.get("dueDate"),
                            "kevRansomware": vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                        }
                self.cache = catalog

            # TODO: Add actual exception handling
            except Exception as e:
                print(f"[!] Some error in NVD request for CVE {cveID}: {e}")
                return None

        return catalog.get(cveId, {})
