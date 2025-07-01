import csv
import sqlite3
import requests
import re
import json
import os
from datetime import datetime
from urllib.parse import urljoin
import logging
import time
from typing import List, Dict, Any

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class RedHatIncrementalDownloader:
    def __init__(self, db_path="redhat_advisories.db"):
        self.base_url = "https://security.access.redhat.com/data/csaf/v2/advisories/"
        self.changes_csv_url = urljoin(self.base_url, "changes.csv")
        self.download_dir = "incremental_advisories"
        self.conn = sqlite3.connect(db_path)
        self._create_tables()

    def _create_tables(self):
        cur = self.conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS advisories (
            advisory_id TEXT PRIMARY KEY,
            title TEXT,
            severity TEXT,
            summary TEXT,
            details TEXT,
            topic TEXT,
            product_id TEXT,
            product_name TEXT,
            full_product_name TEXT,
            category TEXT,
            vulnerability_count INTEGER,
            file_path TEXT,
            initial_release_date TEXT,
            current_release_date TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT,
            cve_id TEXT,
            title TEXT,
            description TEXT,
            cvss_score TEXT,
            cvss_vector TEXT,
            FOREIGN KEY(advisory_id) REFERENCES advisories(advisory_id)
        )
        """)
        self.conn.commit()

    def get_latest_modified_date(self) -> str:
        cur = self.conn.cursor()
        cur.execute("SELECT MAX(current_release_date) FROM advisories")
        row = cur.fetchone()
        return row[0] if row and row[0] else "1970-01-01"

    def fetch_changes(self) -> List[Dict[str, str]]:
        try:
            logger.info(f"Fetching changes.csv from {self.changes_csv_url}")
            r = requests.get(self.changes_csv_url)
            r.raise_for_status()
            lines = r.text.strip().splitlines()

            changes = []
            reader = csv.reader(lines)
            for row in reader:
                if len(row) != 2:
                    continue
                file_path, timestamp = row
                if not file_path.lower().endswith('.json'):
                    continue

                filename = os.path.basename(file_path)
                if not filename.startswith("rhsa-"):
                    continue

                # Convert file to RHSA ID format: rhsa-2024_10758 -> RHSA-2024:10758
                advisory_id = filename.replace(".json", "").replace("_", ":").upper()

                date_part = timestamp.split("T")[0] if timestamp else datetime.utcnow().strftime("%Y-%m-%d")
                changes.append({
                    "advisory": advisory_id,
                    "initial_release_date": date_part,
                    "current_release_date": date_part
                })

            logger.info(f"Parsed {len(changes)} advisory changes")
            return changes
        except Exception as e:
            logger.error(f"Error fetching changes.csv: {e}")
            return []



    def advisory_already_processed(self, advisory_id: str, modified_date: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("SELECT current_release_date FROM advisories WHERE advisory_id = ?", (advisory_id,))
        row = cur.fetchone()
        if row and row[0]:
            # Parse dates for comparison
            try:
                existing_date = datetime.fromisoformat(row[0].replace('Z', '+00:00'))
                new_date = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
                return existing_date >= new_date
            except ValueError:
                # If date parsing fails, assume we need to update
                return False
        return False

    def download_and_process_advisory(self, rhsa: str, modified: str, released: str):
        # Extract year from RHSA ID (e.g., "RHSA-2025:10092" -> "2025")
        try:
            year = rhsa.split('-')[1].split(':')[0]
        except (IndexError, ValueError):
            logger.error(f"Could not extract year from advisory ID: {rhsa}")
            return
            
        # Convert advisory ID to filename format (e.g., "RHSA-2025:10092" -> "rhsa-2025_10092")
        filename = rhsa.lower().replace('rhsa-', 'rhsa-').replace(':', '_') + '.json'
        advisory_url = urljoin(self.base_url, f"{year}/{filename}")
        local_path = os.path.join(self.download_dir, filename)
        os.makedirs(self.download_dir, exist_ok=True)

        try:
            if os.path.exists(local_path):
                with open(local_path, 'r', encoding='utf-8') as f:
                    advisory = json.load(f)
            else:
                logger.info(f"Downloading {rhsa} from {advisory_url}")
                headers = {
                    'User-Agent': 'Mozilla/5.0 (compatible; RedHat Advisory Downloader/1.0)'
                }
                r = requests.get(advisory_url, headers=headers, timeout=30)
                r.raise_for_status()
                advisory = r.json()
                with open(local_path, 'w', encoding='utf-8') as f:
                    json.dump(advisory, f, indent=2)

            self.process_advisory(advisory, rhsa, local_path, released, modified)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download advisory {rhsa}: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON for advisory {rhsa}: {e}")
        except Exception as e:
            logger.error(f"Failed to process advisory {rhsa}: {e}")

    def process_advisory(self, advisory, advisory_id, file_path, released, modified):
        if self.advisory_already_processed(advisory_id, modified):
            logger.info(f"Advisory {advisory_id} already up to date")
            return

        # Remove old CVEs if re-processing
        self.conn.execute("DELETE FROM cves WHERE advisory_id = ?", (advisory_id,))
        self.conn.execute("DELETE FROM advisories WHERE advisory_id = ?", (advisory_id,))

        doc = advisory.get('document', {})
        desc = self.extract_descriptions(doc.get('notes', []))
        severity = doc.get('aggregate_severity', {}).get('text', '')
        title = doc.get('title', '')

        # Basic product info
        tree = advisory.get('product_tree', {})
        product_id, product_name, full_name, category = '', '', '', ''
        if tree.get('branches'):
            branch = tree['branches'][0]
            product = branch.get('product', {})
            if product:
                product_id = product.get('product_id', '')
                product_name = product.get('name', '')
            full_name = branch.get('name', '')
            category = branch.get('category', '')

        vulns = self.extract_vulnerabilities(advisory.get('vulnerabilities', []))

        # Insert advisory
        self.conn.execute("""
            INSERT OR REPLACE INTO advisories (
                advisory_id, title, severity, summary, details, topic,
                product_id, product_name, full_product_name, category,
                vulnerability_count, file_path, initial_release_date, current_release_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            advisory_id, title, severity, desc['summary'], desc['details'], desc['topic'],
            product_id, product_name, full_name, category,
            len(vulns), file_path, released, modified
        ))

        # Insert CVEs
        for v in vulns:
            self.conn.execute("""
                INSERT INTO cves (
                    advisory_id, cve_id, title, description, cvss_score, cvss_vector
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                advisory_id, v['cve_id'], v['title'], v['description'],
                v['cvss_score'], v['cvss_vector']
            ))

        self.conn.commit()
        logger.info(f"Processed {advisory_id} with {len(vulns)} CVEs.")

    def extract_descriptions(self, notes: List[Dict[str, str]]) -> Dict[str, str]:
        result = {'summary': '', 'details': '', 'topic': ''}
        for note in notes:
            category = note.get('category', '').lower()
            title = note.get('title', '').lower()
            text = note.get('text', '')
            
            if category == 'summary':
                result['summary'] = text
            elif category == 'general' or category == 'details':
                result['details'] = text
            elif title == 'topic' or category == 'topic':
                result['topic'] = text
        return result

    def extract_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        out = []
        for v in vulns:
            entry = {
                'cve_id': v.get('cve', ''),
                'title': v.get('title', ''),
                'description': '',
                'cvss_score': '',
                'cvss_vector': ''
            }
            
            # Extract description from notes
            for note in v.get('notes', []):
                if note.get('category') in ('summary', 'general', 'description'):
                    entry['description'] = note.get('text', '')
                    break
            
            # Extract CVSS scores
            for score in v.get('scores', []):
                if 'cvss_v3' in score:
                    cvss3 = score['cvss_v3']
                    entry['cvss_score'] = str(cvss3.get('baseScore', ''))
                    entry['cvss_vector'] = cvss3.get('vectorString', '')
                    break
                elif 'cvss_v2' in score:
                    cvss2 = score['cvss_v2']
                    entry['cvss_score'] = str(cvss2.get('baseScore', ''))
                    entry['cvss_vector'] = cvss2.get('vectorString', '')
            
            out.append(entry)
        return out

    def run_incremental_sync(self):
        latest_modified = self.get_latest_modified_date()
        logger.info(f"Fetching changes since: {latest_modified}")
        changes = self.fetch_changes()

        if not changes:
            logger.warning("No changes found in CSV file")
            return

        # Filter advisories that are newer or not processed yet
        new_or_updated = []
        for change in changes:
            advisory_id = change['advisory']
            modified_date = change['current_release_date']
            
            if not self.advisory_already_processed(advisory_id, modified_date):
                new_or_updated.append(change)

            
        logger.info(f"{len(new_or_updated)} advisories to update out of {len(changes)} total changes")

        if not new_or_updated:
            logger.info("No new advisories to process")
            return

        # Process each advisory
        for i, change in enumerate(new_or_updated, 1):
            logger.info(f"Processing {i}/{len(new_or_updated)}: {change['advisory']}")
            self.download_and_process_advisory(
                rhsa=change['advisory'], 
                modified=change['current_release_date'], 
                released=change['initial_release_date']
            )
            
            # Add a small delay to be respectful to the server
            time.sleep(0.5)

        logger.info(f"Incremental sync completed. Processed {len(new_or_updated)} advisories.")

    def get_stats(self):
        """Get statistics about the current database content"""
        cur = self.conn.cursor()
        
        # Count advisories
        cur.execute("SELECT COUNT(*) FROM advisories")
        advisory_count = cur.fetchone()[0]
        
        # Count CVEs
        cur.execute("SELECT COUNT(*) FROM cves")
        cve_count = cur.fetchone()[0]
        
        # Get latest advisory date
        cur.execute("SELECT MAX(current_release_date) FROM advisories")
        latest_date = cur.fetchone()[0]
        
        logger.info(f"Database stats: {advisory_count} advisories, {cve_count} CVEs, latest: {latest_date}")
        return {
            'advisories': advisory_count,
            'cves': cve_count,
            'latest_date': latest_date
        }


if __name__ == "__main__":
    downloader = RedHatIncrementalDownloader()
    
    # Show current stats
    downloader.get_stats()
    
    # Run incremental sync
    downloader.run_incremental_sync()
    
    # Show updated stats
    downloader.get_stats()