from sources.nvd import NVD_Client
from sources.epss import EPSS_Client
from sources.kev import KEV_Client
from storage import CVE_Data

class CVE_Priority:

    def __init__(self):
        self.nvd = NVD_Client()
        self.epss = EPSS_Client()
        self.kev = KEV_Client()

    def analyse(self, cve_IDs):
        cve_Data_Values = []
        for cve_ID in cve_IDs:
            kev_Data = self.kev.fetch(cve_ID)
            in_KEV = kev_Data != {}
            nvd_Data = self.nvd.fetch(cve_ID)
            epss_Data = self.epss.fetch(cve_ID)

            composite_Score = self._calculate_Composite_Score(
                cvss_Score=nvd_Data.get("cvss_Score"),
                epss_Score=epss_Data.get("epss_Score"),
                in_KEV=in_KEV,
            )

            priority_Tier = self._assign_Tier(
                composite_Score=composite_Score,
                in_KEV=in_KEV,
                epss_Score=epss_Data.get("epss_Score"),
            )

            reasoning = self._generate_Reasoning(
                priority_Tier=priority_Tier,
                cvss_Score=nvd_Data.get("cvss_Score"),
                cvss_Severity=nvd_Data.get("cvss_Severity"),
                epss_Score=epss_Data.get("epss_Score"),
                epss_Percentile=epss_Data.get("epss_Percentile"),
                in_KEV=in_KEV,
                kev_Due_Date=kev_Data.get("kev_Due_Date", None),
                kev_Ransomware=kev_Data.get("kev_Ransomware", None),
            )

            cve_Data = CVE_Data(
                cve_ID = cve_ID,
                description = nvd_Data.get("description", ""),
                cvss_Score = nvd_Data.get("cvss_Score"),
                cvss_Severity = nvd_Data.get("cvss_Severity"),
                cvss_Vector = nvd_Data.get("cvss_Vector"),
                epss_Score = epss_Data.get("epss_Score"),
                epss_Percentile = epss_Data.get("epss_Percentile"),
                in_KEV = in_KEV,
                kev_Due_Date = kev_Data.get("kev_Due_Date", None),
                kev_Ransomware = kev_Data.get("kev_Ransomware", None),
                composite_Score = composite_Score,
                priority_Tier = priority_Tier,
                reasoning = reasoning,
            )

            cve_Data_Values.append(cve_Data)

        cve_Data_Values.sort(key=lambda x: x.composite_Score, reverse=True)
        return cve_Data_Values

    def _calculate_Composite_Score(self, cvss_Score, epss_Score, in_KEV):
        # Can tweak ratios, just placeholder.
        epss_Component = epss_Score * 40
        kev_Component = 30 if in_KEV else 0
        cvss_Component = (cvss_Score / 10) * 30 # Easier to see as 30%
        return epss_Component + kev_Component + cvss_Component

    def _assign_Tier(self, composite_Score, in_KEV, epss_Score):
        if in_KEV and epss_Score > 0.7:
            return "CRITICAL"
        if in_KEV:
            return "HIGH" if composite_Score < 70 else "CRITICAL"
        if composite_Score >= 70:
            return "CRITICAL"
        elif composite_Score >= 50:
            return "HIGH"
        elif composite_Score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_Reasoning(self, priority_Tier, cvss_Score, cvss_Severity, epss_Score, epss_Percentile, in_KEV, kev_Due_Date, kev_Ransomware):
        cvss_Reason = f"CVSS {cvss_Score} ({cvss_Severity})"
        epss_Reason = f"EPSS {(epss_Score * 100):.1f}% (top {((1 - epss_Percentile) * 100):.1f}%)"
        if in_KEV:
            kev_Reason = "IN CISA KEV"
            if kev_Due_Date:
                kev_Reason += f" (due {kev_Due_Date})"
            if kev_Ransomware:
                kev_Reason += f" with known ransomware use"
        else:
            kev_Reason = "Not in CISA KEV"

        if priority_Tier == "CRITICAL":
            if in_KEV:
                recommendation = "Immediate patching required - confirmed active exploitation."
            else:
                recommendation = "Immediate patching required - extremely high risk."
        elif priority_Tier == "HIGH":
            if in_KEV:
                recommendation = "Prioritize patching - confirmed active exploitation."
            else:
                recommendation = "Prioritize patching - high risk."
        elif priority_Tier == "MEDIUM":
            recommendation = "Schedule for next maintenance window - moderate risk."
        else:
            recommendation = "Schedule as needed - low risk."

        return f"{priority_Tier}: {cvss_Reason}, {epss_Reason}, {kev_Reason}. {recommendation}"
