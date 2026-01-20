from sources.nvd import NVD_Client
from sources.epss import EPSS_Client
from sources.kev import KEV_Client

class CVE_Priority:

    def __init__(self):
        self.nvd = NVD_Client()
        self.epss = EPSS_Client()
        self.kev = KEV_Client()

    def analyse(self, cve_IDs):
        cve_Data_Values = []
        for cve_ID in cve_IDs:
            cve_Data = {
                "kev_Data": self.kev.fetch(cve_ID),
                "nvd_Data": self.nvd.fetch(cve_ID),
                "epss_Data": self.epss.fetch(cve_ID),
            }
            cve_Data_Values.append(cve_Data)
        return cve_Data_Values
