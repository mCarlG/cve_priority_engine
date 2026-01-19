import argparse

def main():
    parser = argparse.ArgumentParser(
        description="CVE Priority Engine"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose logging.",
    )

    args = parser.parse_args()

    if args.verbose:
        print(f"[*] Verbose logging enabled: {args.verbose} (obviously.)")

if __name__ == "__main__":
    main()
