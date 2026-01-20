from src.sources.nvd import NVDClient
from src.sources.epss import EPSSClient
from src.sources.kev import KEVClient

class CVEPriority:

    def __init__(self):
        self.nvd = NVDClient()
        self.epss = EPSSClient()
        self.kev = KEVClient()

    def analyse(self, cveIds):
        pass
