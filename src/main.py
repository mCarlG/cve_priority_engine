import argparse

if __name__ == "__main__":
    main()

def main():
    parser = argparse.ArgumentParser(
        description="CVE Priority Engine"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Verbose logging."
    )

    args = parser.parse_args()

    if args.verbose:
        print(f"[*] Verbose logging enabled: {args.verbose} (obviously.)")
