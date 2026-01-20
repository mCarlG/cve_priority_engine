import requests, time

class NVD_Client:
    URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT = 6 # Seconds between requests.

    def __init__(self):
        self.session = requests.Session()

    def _rate_limit(self):
        time.sleep(RATE_LIMIT)

    def fetch(self, cve_ID):
        self._rate_limit()

        try:
            response = self.session.get(self.URL, params={"cveId": cve_ID}, timeout=10)
            response.raise_for_status()
            data = response.json()

            if not data.get("vulnerabilities"):
                return None

            vuln = data["vulnerabilities"][0]["cve"]

            cvss_Data = None
            metrics = vuln.get("metrics", {})
            if "cvssMetricsV31" in metrics:
                cvss_Data = metrics["cvssMetricV31"][0]["cvssData"]
            elif "cvssMetricsV30" in metrics:
                cvss_Data = metrics["cvssMetricV30"][0]["cvssData"]
            elif "cvssMetricsV2" in metrics:
                cvss_Data = metrics["cvssMetricV2"][0]["cvssData"]

            cvss_Severity = vuln.get("baseSeverity", None)
            cvss_Sector = vuln.get("vectorString", None)
            cvss_Score = vuln.get("baseSeverity", None)

            cvss_Description = None
            if descriptions := vuln.get("descriptions", []):
                cvss_Description = descriptions[0]["value"]

            return {
                "cve_ID": cve_ID,
                "cvss_Description": cve_Description,
                "cvss_Score": cvss_Score,
                "cvss_Severity": cvss_Severity,
                "cvss_Vector": cvss_Vector,
            }

        # TODO: Add actual exception handling
        except Exception as e:
            print(f"[!] Some error in NVD request for CVE {cve_ID}: {e}")
            return None
