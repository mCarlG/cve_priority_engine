import requests

class NVDClient:
    URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT = 6 # Seconds between requests.

    def __init__(self):
        pass
