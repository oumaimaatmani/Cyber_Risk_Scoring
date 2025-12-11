"""
CVE data collection from NVD API (v2.0)
Cyber Risk Scoring

Notes:
- Keeps the original logic intact (time window collection, keyword search, KEV backfill, parsing, CSV save).
- Adds clear English comments, small refactors for readability, basic type hints, and safer default handling.
- Respects NVD rate limits via the delay parameter (non-API-key vs API-key).
"""

import os
import time
import json
import requests
import pandas as pd
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class NVDCollector:
    """NVD 2.0 API collector"""

    def __init__(self, api_key: Optional[str] = None) -> None:
        """
        Initialize collector with base URL, headers, and API rate delay.
        If an API key is provided, use faster delay.
        """
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.headers = {
            "User-Agent": "CyberRiskScoring/1.0 (+https://example.org)",
            "Accept": "application/json",
        }
        if api_key:
            self.headers["apiKey"] = api_key

        # Respect NVD rate limits (approx); lower delay if api_key is set.
        self.delay = 6 if not api_key else 0.6

        # Lazy-initialized session for backfill with retries
        self.session: Optional[requests.Session] = None

    def collect_recent_cves(self, days: int = 90, results_per_page: int = 2000) -> List[Dict[str, Any]]:
        """
        Collect CVEs for the last `days` using pubStartDate/pubEndDate window.
        Paginates via startIndex until totalResults is reached.

        Args:
            days: number of days back from now to collect CVEs
            results_per_page: page size (max 2000 allowed by NVD)
        Returns:
            list of raw vulnerability items (JSON objects)
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
        pub_end = end_date.strftime("%Y-%m-%dT23:59:59.999Z")

        all_cves: List[Dict[str, Any]] = []
        start_index = 0

        print(f" Collecting CVEs from {start_date.date()} to {end_date.date()}")

        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }
            try:
                resp = requests.get(self.base_url, headers=self.headers, params=params, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", []) or []
                    if not vulnerabilities:
                        break

                    all_cves.extend(vulnerabilities)
                    print(f" Retrieved {len(all_cves)} CVEs so far...")

                    total_results = data.get("totalResults", 0)
                    if start_index + results_per_page >= total_results:
                        break

                    start_index += results_per_page
                    time.sleep(self.delay)
                else:
                    print(f" HTTP {resp.status_code}: {resp.text}")
                    break
            except Exception as e:
                print(f" Exception: {e}")
                break

        print(f" Total collected: {len(all_cves)} CVEs")
        return all_cves

    def collect_by_keywords(self, keywords: List[str], max_results: int = 500) -> List[Dict[str, Any]]:
        """
        Collect CVEs using keywordSearch (technology-specific terms).

        Args:
            keywords: list of keywords (e.g., ['apache', 'mysql'])
            max_results: max results per keyword (capped at 2000)
        Returns:
            list of raw vulnerability items (JSON objects)
        """
        all_cves: List[Dict[str, Any]] = []
        for keyword in keywords:
            print(f" Searching CVEs for keyword: {keyword}")
            params = {"keywordSearch": keyword, "resultsPerPage": min(max_results, 2000)}
            try:
                resp = requests.get(self.base_url, headers=self.headers, params=params, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", []) or []
                    all_cves.extend(vulnerabilities)
                    print(f" Found {len(vulnerabilities)} CVEs for {keyword}")
                time.sleep(self.delay)
            except Exception as e:
                print(f" Error for keyword '{keyword}': {e}")

        print(f" Total collected by keywords: {len(all_cves)} CVEs")
        return all_cves

    def parse_cve_data(self, cves: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Transform raw JSON vulnerabilities into a structured DataFrame.
        Extracts IDs, dates, CVSS, severity, short description, CPEs, references, and exploit tag.

        Args:
            cves: list of raw vulnerability items
        Returns:
            pandas DataFrame with normalized columns
        """
        parsed_rows: List[Dict[str, Any]] = []

        for item in cves:
            cve = item.get("cve", {}) or {}
            cve_id = cve.get("id", "N/A")

            # CVSS metrics (prefer v3.1 then v3.0, then v2)
            metrics = cve.get("metrics", {}) or {}
            cvss_v3 = None
            cvss_v2 = None
            severity = "UNKNOWN"

            if metrics.get("cvssMetricV31"):
                m = metrics["cvssMetricV31"][0]
                cvss_v3 = m["cvssData"]["baseScore"]
                severity = m["cvssData"]["baseSeverity"]
            elif metrics.get("cvssMetricV30"):
                m = metrics["cvssMetricV30"][0]
                cvss_v3 = m["cvssData"]["baseScore"]
                severity = m["cvssData"]["baseSeverity"]
            elif metrics.get("cvssMetricV2"):
                m = metrics["cvssMetricV2"][0]
                cvss_v2 = m["cvssData"]["baseScore"]
                severity = m.get("baseSeverity", "MEDIUM")

            # English description (fallback if missing)
            descriptions = cve.get("descriptions", []) or []
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description")

            # Dates
            published = cve.get("published", "")
            modified = cve.get("lastModified", "")

            # CPE list (affected products) – collect criteria strings
            configurations = cve.get("configurations", []) or []
            cpe_list: List[str] = []
            for config in configurations:
                for node in config.get("nodes", []) or []:
                    for match in node.get("cpeMatch", []) or []:
                        cpe_list.append(match.get("criteria", ""))

            # References
            references = cve.get("references", []) or []
            ref_count = len(references)
            exploit_exists = any("exploit" in (r.get("tags") or []) for r in references)

            parsed_rows.append({
                "cve_id": cve_id,
                "published_date": published,
                "modified_date": modified,
                "cvss_v3_score": cvss_v3,
                "cvss_v2_score": cvss_v2,
                "severity": severity,
                "description": description[:200],  # truncate for readability
                "cpe_count": len(cpe_list),
                "reference_count": ref_count,
                "exploit_available": exploit_exists,
                "cpe_list": "|".join(cpe_list[:5]),  # limit list size in CSV
            })

        return pd.DataFrame(parsed_rows)

    def save_data(self, df: pd.DataFrame, filename: str = "nvd_cves.csv") -> str:
        """
        Save the normalized CVE DataFrame to data/<filename>.
        Ensures the data directory exists.
        """
        os.makedirs("data", exist_ok=True)
        filepath = os.path.join("data", filename)
        df.to_csv(filepath, index=False)
        print(f" Saved: {filepath}")
        return filepath

    def _ensure_session(self) -> requests.Session:
        """
        Lazily create a requests.Session configured with retry policy for backfill.
        """
        if self.session is None:
            self.session = requests.Session()
            retries = Retry(
                total=5,
                backoff_factor=1.5,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET"],
            )
            self.session.mount("https://", HTTPAdapter(max_retries=retries))
        return self.session

    def collect_by_cve_ids(self, cve_ids: List[str], chunk_size: int = 200) -> List[Dict[str, Any]]:
        """
        Backfill NVD by explicit CVE IDs (chunked requests + retry).
        This is used to ensure KEV coverage even when outside the time window or keyword queries.

        Args:
            cve_ids: list of CVE identifiers (e.g., ['CVE-2023-...'])
            chunk_size: number of IDs per request (keep reasonable to avoid URL length errors)
        Returns:
            list of raw vulnerability items (JSON objects)
        """
        ids = [str(x).strip().upper() for x in cve_ids if x]
        if not ids:
            return []

        session = self._ensure_session()
        all_items: List[Dict[str, Any]] = []

        for i in range(0, len(ids), chunk_size):
            chunk = ids[i : i + chunk_size]
            # NVD expects multiple cveId params; also include pagination params
            params = [("cveId", cid) for cid in chunk] + [("resultsPerPage", 2000), ("startIndex", 0)]
            try:
                r = session.get(self.base_url, headers=self.headers, params=params, timeout=60)
                if r.status_code == 200:
                    data = r.json()
                    vulns = data.get("vulnerabilities", []) or []
                    all_items.extend(vulns)
                    print(f" Backfill KEV: chunk {i // chunk_size + 1} → +{len(vulns)}")
                else:
                    print(f" Backfill HTTP {r.status_code} ({r.url}) → {r.text[:200]}")
                    if r.status_code == 429:
                        wait = max(self.delay, 12)
                        print(f" Rate limit: pause {wait}s")
                        time.sleep(wait)
                        # Retry once
                        rr = session.get(self.base_url, headers=self.headers, params=params, timeout=60)
                        if rr.status_code == 200:
                            data = rr.json()
                            vulns = data.get("vulnerabilities", []) or []
                            all_items.extend(vulns)
                            print(f" Backfill KEV (retry): +{len(vulns)}")
                time.sleep(self.delay)
            except Exception as e:
                print(f" Exception backfill: {e}")

        return all_items


# Example usage (kept identical in logic)
if __name__ == "__main__":
    # Initialize collector (reads NVD_API_KEY from environment if present)
    collector = NVDCollector(api_key=os.getenv("NVD_API_KEY"))

    # Option 1: recent CVEs (last 90 days)
    print("=" * 60)
    print("COLLECTE DES CVE RÉCENTS")
    print("=" * 60)
    cves_recent = collector.collect_recent_cves(days=90)

    # Option 2: technology keywords
    print("\n" + "=" * 60)
    print("COLLECTE PAR TECHNOLOGIES")
    print("=" * 60)
    technologies = ["apache", "nginx", "mysql", "postgresql", "wordpress", "drupal"]
    cves_tech = collector.collect_by_keywords(technologies, max_results=200)

    # Combine recent + keyword results
    all_cves = cves_recent + cves_tech

    # KEV backfill to ensure exploited CVEs are included even if outside window
    from CISA_KEV_collector import CISACollector

    kev_payload = CISACollector().collect_kev()
    if kev_payload:
        kev_df = CISACollector().parse_kev_data(kev_payload)
        kev_ids = set(kev_df["cve_id"].astype(str).str.upper().str.strip())
        nvd_ids = set(item["cve"]["id"] for item in all_cves if "cve" in item and "id" in item["cve"])
        missing = sorted(kev_ids - nvd_ids)
        print(f" KEV missing to backfill: {len(missing)}")
        if missing:
            added = collector.collect_by_cve_ids(missing)
            all_cves += added
            still_missing = sorted(set(missing) - set(item["cve"]["id"] for item in added if "cve" in item))
            if still_missing:
                pd.Series(still_missing).to_csv("data/kev_missing_ids.csv", index=False)
                print(f" Remaining KEV not retrieved: {len(still_missing)} → data/kev_missing_ids.csv")

    # Deduplicate by CVE ID
    unique_cves = {item["cve"]["id"]: item for item in all_cves}.values()
    print(f"\n Unique CVEs collected: {len(unique_cves)}")

    # Parse and save
    df = collector.parse_cve_data(list(unique_cves))

    print("\n Data preview:")
    print(df.head())
    print(f"\nShape: {df.shape}")
    print("\nSeverity distribution:")
    print(df["severity"].value_counts())

    collector.save_data(df)
    print("\n Collection completed successfully!")