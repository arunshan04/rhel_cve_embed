#!/usr/bin/env python3
"""
Script to download Red Hat CSAF advisories.
"""

from downloader import RedHatAdvisoriesDownloader

def main():
    downloader = RedHatAdvisoriesDownloader()

    print("Red Hat CSAF Downloader")
    print("=" * 40)
    
    choice = input("\nChoose download method:\n1. Latest archive\n2. Specific years\n3. All years\nEnter choice (1-3): ")

    if choice == "1":
        archive_path = downloader.download_latest_archive("redhat_advisories")
        print("Download complete. Please extract and process using the next step.")

    elif choice == "2":
        years = input("Enter years separated by commas (e.g., 2023,2024): ").split(',')
        for year in map(str.strip, years):
            downloader.download_year_advisories(year, "redhat_advisories")

    elif choice == "3":
        for year in range(2001, 2026):
            downloader.download_year_advisories(str(year), "redhat_advisories")

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
