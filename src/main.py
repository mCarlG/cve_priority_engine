import argparse
import priorities
def main():
    parser = argparse.ArgumentParser(
        description="CVE Priority Engine"
    )

    parser.add_argument(
        "cves",
        nargs="?",
        help="CVE IDs to analyze, in CSV format."),

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose logging.",
    )

    args = parser.parse_args()

    if args.verbose:
        print(f"[*] Verbose logging enabled.")

    priority_Check = priorities.CVE_Priority()
    cve_IDs = [cve for cve in args.cves.split(',')]
    cve_Data = priority_Check.analyse(cve_IDs)
    for cve in cve_Data:
        print(f"{cve}")

if __name__ == "__main__":
    main()
