#!/usr/bin/env python3
"""
Red Hat CSAF Advisories Downloader and Package Extractor
Downloads all Red Hat security advisories and extracts package information with descriptions
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
    
    def extract_descriptions(self, advisory: Dict[str, Any]) -> Dict[str, str]:
        """Extract English descriptions from advisory notes"""
        descriptions = {
            'summary': '',
            'details': '',
            'topic': '',
            'legal_disclaimer': ''
        }
        
        # Extract from document notes
        notes = advisory.get('document', {}).get('notes', [])
        for note in notes:
            if note.get('category') == 'summary':
                descriptions['summary'] = note.get('text', '').strip()
            elif note.get('category') == 'general':
                descriptions['details'] = note.get('text', '').strip()
            elif note.get('title', '').lower() == 'topic':
                descriptions['topic'] = note.get('text', '').strip()
            elif note.get('category') == 'legal_disclaimer':
                descriptions['legal_disclaimer'] = note.get('text', '').strip()
        
        return descriptions
    
    def extract_vulnerability_details(self, vulnerabilities: List[Dict]) -> List[Dict[str, Any]]:
        """Extract detailed vulnerability information"""
        vuln_details = []
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve', '')
            title = vuln.get('title', '')
            
            # Extract notes/descriptions for this vulnerability
            vuln_notes = vuln.get('notes', [])
            vuln_description = ''
            for note in vuln_notes:
                if note.get('category') in ['description', 'summary', 'general']:
                    vuln_description = note.get('text', '').strip()
                    break
            
            # Extract CVSS scores
            scores = vuln.get('scores', [])
            cvss_score = ''
            cvss_vector = ''
            for score in scores:
                if 'cvss_v3' in score:
                    cvss_score = score['cvss_v3'].get('baseScore', '')
                    cvss_vector = score['cvss_v3'].get('vectorString', '')
                    break
                elif 'cvss_v2' in score:
                    cvss_score = score['cvss_v2'].get('baseScore', '')
                    cvss_vector = score['cvss_v2'].get('vectorString', '')
            
            vuln_details.append({
                'cve_id': cve_id,
                'title': title,
                'description': vuln_description,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector
            })
        
        return vuln_details
    
    def extract_package_info(self, advisory_file: str) -> List[Dict[str, Any]]:
        """Extract package information from CSAF advisory JSON with descriptions"""
        try:
            with open(advisory_file, 'r', encoding='utf-8') as f:
                advisory = json.load(f)
            
            packages = []
            
            # Basic advisory information
            doc = advisory.get('document', {})
            tracking = doc.get('tracking', {})
            
            advisory_id = tracking.get('id', 'Unknown')
            advisory_title = doc.get('title', '')
            
            # Extract descriptions
            descriptions = self.extract_descriptions(advisory)
            
            # Extract vulnerability information
            vulnerabilities = advisory.get('vulnerabilities', [])
            vuln_details = self.extract_vulnerability_details(vulnerabilities)
            
            # Create CVE summary strings
            cve_list = [vuln['cve_id'] for vuln in vuln_details if vuln['cve_id']]
            cve_titles = [f"{vuln['cve_id']}: {vuln['title']}" for vuln in vuln_details if vuln['cve_id'] and vuln['title']]
            cve_descriptions = [f"{vuln['cve_id']}: {vuln['description']}" for vuln in vuln_details if vuln['cve_id'] and vuln['description']]
            
            # Extract severity
            severity = doc.get('aggregate_severity', {}).get('text', '')
            
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
                            'severity': severity,
                            'summary': descriptions['summary'],
                            'details': descriptions['details'],
                            'topic': descriptions['topic'],
                            'product_id': product.get('product_id', ''),
                            'product_name': product.get('name', ''),
                            'full_product_name': full_name,
                            'category': branch.get('category', ''),
                            'vulnerability_count': len(vulnerabilities),
                            'cve_list': '; '.join(cve_list),
                            'cve_titles': ' | '.join(cve_titles),
                            'cve_descriptions': ' | '.join(cve_descriptions),
                            'file_path': advisory_file
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
                        'severity': severity,
                        'summary': descriptions['summary'],
                        'details': descriptions['details'],
                        'topic': descriptions['topic'],
                        'product_id': product_ref,
                        'product_name': full_product_name,
                        'full_product_name': full_product_name,
                        'category': 'component',
                        'vulnerability_count': len(vulnerabilities),
                        'cve_list': '; '.join(cve_list),
                        'cve_titles': ' | '.join(cve_titles),
                        'cve_descriptions': ' | '.join(cve_descriptions),
                        'file_path': advisory_file
                    }
                    packages.append(package_info)
            
            # If no packages found but we have advisory info, create a record anyway
            if not packages and advisory_id != 'Unknown':
                package_info = {
                    'advisory_id': advisory_id,
                    'advisory_title': advisory_title,
                    'severity': severity,
                    'summary': descriptions['summary'],
                    'details': descriptions['details'],
                    'topic': descriptions['topic'],
                    'product_id': '',
                    'product_name': '',
                    'full_product_name': '',
                    'category': 'advisory_only',
                    'vulnerability_count': len(vulnerabilities),
                    'cve_list': '; '.join(cve_list),
                    'cve_titles': ' | '.join(cve_titles),
                    'cve_descriptions': ' | '.join(cve_descriptions),
                    'file_path': advisory_file
                }
                packages.append(package_info)
            
            return packages
            
        except Exception as e:
            logger.error(f"Error extracting from {advisory_file}: {e}")
            return []
    
    def process_all_advisories(self, advisories_dir: str, output_file: str = "redhat_packages_with_descriptions.csv"):
        """Process all downloaded advisories and extract package information with descriptions"""
        all_packages = []
        
        # Find all JSON files
        json_files = []
        for root, dirs, files in os.walk(advisories_dir):
            for file in files:
                if file.endswith('.json'):
                    json_files.append(os.path.join(root, file))
        
        # Remove the test limit from original code
        # json_files = json_files[:10000]  # Remove this line for full processing
        
        logger.info(f"Processing {len(json_files)} advisory files")
        
        for i, json_file in enumerate(json_files):
            if i % 1000 == 0:
                logger.info(f"Processed {i}/{len(json_files)} files")
            
            packages = self.extract_package_info(json_file)
            all_packages.extend(packages)
        
        logger.info(f"Total packages extracted: {len(all_packages)}")
        
        # Write to CSV with enhanced fields
        if all_packages:
            fieldnames = [
                'advisory_id', 'advisory_title', 'severity', 'summary', 'details', 'topic',
                'product_id', 'product_name', 'full_product_name', 'category', 
                'vulnerability_count', 'cve_list', 'cve_titles', 'cve_descriptions', 'file_path'
            ]
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for package in all_packages:
                    writer.writerow(package)
            
            logger.info(f"Exported {len(all_packages)} package records to {output_file}")
        else:
            logger.warning("No packages found to export")
        
        return all_packages

