#!/usr/bin/env python3
"""
Script to process downloaded Red Hat CSAF advisories and extract package info.
"""

from downloader import RedHatAdvisoriesDownloader
import sys

def main():
    downloader = RedHatAdvisoriesDownloader()

    print("Red Hat CSAF Processor")
    print("=" * 40)

    advisories_dir = 'redhat_advisories_extracted'
    output_csv = "output/redhat_packages.csv"

    downloader.process_all_advisories(advisories_dir, output_csv)

if __name__ == "__main__":
    main()
