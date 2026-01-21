import requests

class KEV_Client:
    URL = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self.session = requests.Session()
        self.cache = None # We can just pull the whole thing once.

    def fetch(self, cve_ID):
        if self.cache == None:
            try:
                response = self.session.get(self.URL, timeout=10)
                response.raise_for_status()
                data = response.json()
                catalog = {}
                for vuln in data.get("vulnerabilities", []):
                    if current_CVE_ID := vuln.get("cveID"): # I love these little walrus guys
                        catalog[current_CVE_ID] = {
                            "kev_Due_Date": vuln.get("dueDate"),
                            "kev_Ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                        }
                self.cache = catalog

            # TODO: Add actual exception handling
            except Exception as e:
                print(f"[!] Some error in NVD request for CVE {cve_ID}: {e}")
                return None

        return self.cache.get(cve_ID, {})
