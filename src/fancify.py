from storage import CVE_Data
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

class OutputFancify:

    def __init__(self):
        self.console = Console()

    def format(self, results):
        self.console.print()
        self.console.print(
            Panel.fit(
                "[bold cyan]CVE Priority Engine Results[/bold cyan]",
                border_style="cyan",
            )
        )
        self.console.print()

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("CVE ID", style="cyan", no_wrap=True)
        table.add_column("Priority", no_wrap=True)
        table.add_column("Score", justify="right")
        table.add_column("CVSS", justify="right")
        table.add_column("EPSS", justify="right")
        table.add_column("KEV", justify="right")

        for cve in results:
            priority_Colour = self._get_Priority_Colour(cve.priority_Tier)
            priority_Text = f"[{priority_Colour}]{cve.priority_Tier}[/{priority_Colour}]"

            if cve.in_KEV:
                kev_Status = "Y"
                if cve.kev_Ransomware:
                    kev_Status += " [red](ransomware)[/red]"
            else:
                kev_Status = "N"

            table.add_row(
                cve.cve_ID,
                priority_Text,
                f"{cve.composite_Score:.1f}",
                f"{cve.cvss_Score}",
                f"{(cve.epss_Score * 100):.1f}%",
                kev_Status,
            )

        self.console.print(table)

        self.console.print()
        self.console.print("[bold]Reasoning:[/bold]")
        self.console.print("-" * 80)

        for cve in results:
            priority_Colour = self._get_Priority_Colour(cve.priority_Tier)
            self.console.print(f"* [bold]{cve.cve_ID}[/bold]: {cve.reasoning}")
            self.console.print()

        summary = self._generate_Summary(results)
        self.console.print(f"[bold]{summary}[/bold]")
        self.console.print()

    def _get_Priority_Colour(self, tier):
        colours = {
            "CRITICAL": "bold red",
            "HIGH": "bold orange1",
            "MEDIUM": "bold yellow",
            "LOW": "bold green",
        }
        return colours.get(tier, "white")

    def _generate_Summary(self, results):
        total = len(results)
        critical = sum(1 for cve in results if cve.priority_Tier == "CRITICAL")
        high = sum(1 for cve in results if cve.priority_Tier == "HIGH")
        medium = sum(1 for cve in results if cve.priority_Tier == "MEDIUM")
        low = sum(1 for cve in results if cve.priority_Tier == "LOW")

        return f"Summary: {total} CVEs analyzed | {critical} CRITICAl | {high} HIGH | {medium} MEDIUM | {low} LOW"
