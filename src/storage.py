from dataclasses import dataclass

@dataclass
class CVE_Data:
    cve_ID: str
    description: str
    cvss_Score: float
    cvss_Severity: str
    cvss_Vector: float
    epss_Score: float
    epss_Percentile: float
    in_KEV: bool
    kev_Due_Date: str | None
    kev_Ransomware: bool | None
    composite_Score: float
    priority_Tier: str
    reasoning: str
