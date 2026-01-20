from src.sources.nvd import NVD_Client
from src.sources.epss import EPSS_Client
from src.sources.kev import KEV_Client

class CVEPriority:

    def __init__(self):
        self.nvd = NVD_Client()
        self.epss = EPSS_Client()
        self.kev = KEV_Client()

    def analyse(self, cveIds):
        pass
