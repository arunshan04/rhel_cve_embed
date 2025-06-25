#!/usr/bin/env python3
"""
Red Hat CSAF Advisories Downloader and Package Extractor
Downloads all Red Hat security advisories and extracts package information
"""

import requests
import json
import csv
import os
import tarfile
import zstandard as zstd
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin
import logging
from typing import List, Dict, Any
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RedHatAdvisoriesDownloader:
    def __init__(self, base_url="https://security.access.redhat.com/data/csaf/v2/advisories/"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RedHat-Advisories-Downloader/1.0'
        })
        
    def get_directory_listing(self, url: str) -> List[str]:
        """Extract directory/file listings from HTML directory index"""
        try:
            response = self.session.get(url)
            response.raise_for_status()
            
            # Parse directory listing - look for href patterns
            href_pattern = r'href="([^"]+)"'
            matches = re.findall(href_pattern, response.text)
            
            # Filter out parent directory and non-relevant links
            items = []
            for match in matches:
                if match not in ['../', '../'] and not match.startswith('http'):
                    items.append(match)
            
            return items
        except Exception as e:
            logger.error(f"Error getting directory listing for {url}: {e}")
            return []
    
    def download_file(self, url: str, local_path: str) -> bool:
        """Download a file from URL to local path"""
        try:
            logger.info(f"Downloading {url}")
            response = self.session.get(url, stream=True)
            response.raise_for_status()
            
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"Downloaded to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Error downloading {url}: {e}")
            return False
    
    def download_latest_archive(self, download_dir: str = "redhat_advisories") -> str:
        """Download the latest complete archive"""
        try:
            # Get the main directory listing
            items = self.get_directory_listing(self.base_url)
            
            # Find the latest tar.zst archive
            archive_files = [item for item in items if item.endswith('.tar.zst') and not item.endswith('.asc')]
            
            if not archive_files:
                raise Exception("No archive files found")
            
            # Get the most recent archive (they're dated)
            latest_archive = sorted(archive_files)[-1]
            archive_url = urljoin(self.base_url, latest_archive)
            
            local_path = os.path.join(download_dir, latest_archive)
            
            if self.download_file(archive_url, local_path):
                return local_path
            else:
                raise Exception("Failed to download archive")
                
        except Exception as e:
            logger.error(f"Error downloading latest archive: {e}")
            return None
    
    def extract_archive(self, archive_path: str, extract_dir: str) -> bool:
        """Extract zstandard compressed tar archive"""
        try:
            logger.info(f"Extracting {archive_path}")
            
            # Decompress zstandard file
            with open(archive_path, 'rb') as compressed:
                dctx = zstd.ZstdDecompressor()
                with open(archive_path.replace('.zst', ''), 'wb') as destination:
                    dctx.copy_stream(compressed, destination)
            
            # Extract tar file
            tar_path = archive_path.replace('.zst', '')
            with tarfile.open(tar_path, 'r') as tar:
                tar.extractall(extract_dir)
            
            # Clean up intermediate tar file
            os.remove(tar_path)
            
            logger.info(f"Extracted to {extract_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Error extracting archive: {e}")
            return False
    
    def download_year_advisories(self, year: str, download_dir: str) -> List[str]:
        """Download all advisories for a specific year"""
        year_url = urljoin(self.base_url, f"{year}/")
        year_dir = os.path.join(download_dir, year)
        
        try:
            items = self.get_directory_listing(year_url)
            json_files = [item for item in items if item.endswith('.json')]
            
            downloaded_files = []
            for json_file in json_files:
                file_url = urljoin(year_url, json_file)
                local_path = os.path.join(year_dir, json_file)
                
                if self.download_file(file_url, local_path):
                    downloaded_files.append(local_path)
                
                # Rate limiting
                time.sleep(0.1)
            
            return downloaded_files
            
        except Exception as e:
            logger.error(f"Error downloading year {year}: {e}")
            return []
    
    def extract_package_info(self, advisory_file: str) -> List[Dict[str, Any]]:
        """Extract package information from CSAF advisory JSON"""
        try:
            with open(advisory_file, 'r', encoding='utf-8') as f:
                advisory = json.load(f)
            
            packages = []
            advisory_id = advisory.get('document', {}).get('tracking', {}).get('id', 'Unknown')
            advisory_title = advisory.get('document', {}).get('title', '')
            
            # Extract vulnerability information
            vulnerabilities = advisory.get('vulnerabilities', [])
            
            # Extract product tree information
            product_tree = advisory.get('product_tree', {})
            branches = product_tree.get('branches', [])
            
            def extract_from_branches(branches, parent_name=""):
                nonlocal packages
                for branch in branches:
                    branch_name = branch.get('name', '')
                    full_name = f"{parent_name}/{branch_name}" if parent_name else branch_name
                    
                    # Check if this branch has product information
                    if 'product' in branch:
                        product = branch['product']
                        package_info = {
                            'advisory_id': advisory_id,
                            'advisory_title': advisory_title,
                            'product_id': product.get('product_id', ''),
                            'product_name': product.get('name', ''),
                            'full_product_name': full_name,
                            'category': branch.get('category', ''),
                            'vulnerabilities': len(vulnerabilities),
                            'cve_list': [vuln.get('cve', '') for vuln in vulnerabilities if vuln.get('cve')]
                        }
                        packages.append(package_info)
                    
                    # Recursively process sub-branches
                    if 'branches' in branch:
                        extract_from_branches(branch['branches'], full_name)
            
            extract_from_branches(branches)
            
            # Also check relationships for additional package info
            relationships = product_tree.get('relationships', [])
            for rel in relationships:
                if rel.get('category') == 'default_component_of':
                    full_product_name = rel.get('full_product_name', {}).get('name', '')
                    product_ref = rel.get('product_reference', '')
                    
                    package_info = {
                        'advisory_id': advisory_id,
                        'advisory_title': advisory_title,
                        'product_id': product_ref,
                        'product_name': full_product_name,
                        'full_product_name': full_product_name,
                        'category': 'component',
                        'vulnerabilities': len(vulnerabilities),
                        'cve_list': [vuln.get('cve', '') for vuln in vulnerabilities if vuln.get('cve')]
                    }
                    packages.append(package_info)
            
            return packages
            
        except Exception as e:
            logger.error(f"Error extracting from {advisory_file}: {e}")
            return []
    
    def process_all_advisories(self, advisories_dir: str, output_file: str = "redhat_packages.csv"):
        """Process all downloaded advisories and extract package information"""
        all_packages = []
        
        # Find all JSON files
        json_files = []
        for root, dirs, files in os.walk(advisories_dir):
            for file in files:
                if file.endswith('.json'):
                    json_files.append(os.path.join(root, file))
        
        logger.info(f"Processing {len(json_files)} advisory files")
        
        for i, json_file in enumerate(json_files):
            if i % 100 == 0:
                logger.info(f"Processed {i}/{len(json_files)} files")
            
            packages = self.extract_package_info(json_file)
            all_packages.extend(packages)
        
        # Write to CSV
        if all_packages:
            fieldnames = ['advisory_id', 'advisory_title', 'product_id', 'product_name', 
                         'full_product_name', 'category', 'vulnerabilities', 'cve_list']
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for package in all_packages:
                    # Convert CVE list to string
                    package['cve_list'] = '; '.join(package['cve_list'])
                    writer.writerow(package)
            
            logger.info(f"Exported {len(all_packages)} package records to {output_file}")
        
        return all_packages

def main():
    """Main execution function"""
    downloader = RedHatAdvisoriesDownloader()
    
    print("Red Hat CSAF Advisories Downloader")
    print("=" * 40)
    
    choice = input("\nChoose download method:\n1. Download latest complete archive (recommended)\n2. Download specific years\n3. Download all years individually\nEnter choice (1-3): ")
    
    if choice == "1":
        # Download latest archive
        archive_path = downloader.download_latest_archive()
        if archive_path:
            extract_dir = "redhat_advisories_extracted"
            if downloader.extract_archive(archive_path, extract_dir):
                downloader.process_all_advisories(extract_dir)
            else:
                print("Failed to extract archive")
        else:
            print("Failed to download archive")
    
    elif choice == "2":
        # Download specific years
        years_input = input("Enter years separated by commas (e.g., 2023,2024): ")
        years = [year.strip() for year in years_input.split(',')]
        
        download_dir = "redhat_advisories_years"
        all_files = []
        
        for year in years:
            print(f"\nDownloading advisories for {year}...")
            files = downloader.download_year_advisories(year, download_dir)
            all_files.extend(files)
            print(f"Downloaded {len(files)} files for {year}")
        
        if all_files:
            downloader.process_all_advisories(download_dir)
    
    elif choice == "3":
        # Download all years
        download_dir = "redhat_advisories_all"
        years = [str(year) for year in range(2001, 2026)]  # 2001 to 2025
        
        all_files = []
        for year in years:
            print(f"\nDownloading advisories for {year}...")
            files = downloader.download_year_advisories(year, download_dir)
            all_files.extend(files)
            print(f"Downloaded {len(files)} files for {year}")
        
        if all_files:
            downloader.process_all_advisories(download_dir)
    
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
