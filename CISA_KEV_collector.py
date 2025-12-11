"""
CISA KEV catalog collector
Known Exploited Vulnerabilities
"""

import os
import json
import time
import requests
import pandas as pd
from typing import Dict, Any, Optional


class CISACollector:
    """CISA KEV JSON collector"""

    def __init__(self) -> None:
        # Official KEV JSON endpoint
        self.url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.headers = {
            "User-Agent": "CyberRiskScoring/1.0 (+https://example.org)",
            "Accept": "application/json",
        }

    def collect_kev(self, timeout: int = 40) -> Optional[Dict[str, Any]]:
        """
        Fetch KEV JSON payload from CISA.
        Returns the raw JSON object or None on error.
        """
        try:
            resp = requests.get(self.url, headers=self.headers, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            print(f"HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            print(f"Exception KEV fetch: {e}")
        return None

    def parse_kev_data(self, payload: Dict[str, Any]) -> pd.DataFrame:
        """
        Parse KEV payload to a normalized DataFrame.
        Important fields are mapped and boolean flags coerced safely.
        """
        vulns = payload.get("vulnerabilities", []) or []
        rows = []
        for v in vulns:
            rows.append({
                "cve_id": (v.get("cveID") or "").strip().upper(),
                "vendor_project": v.get("vendorProject") or "",
                "product": v.get("product") or "",
                "vulnerability_name": v.get("vulnerabilityName") or "",
                "date_added": v.get("dateAdded") or "",
                "short_description": v.get("shortDescription") or "",
                "required_action": v.get("requiredAction") or "",
                "due_date": v.get("dueDate") or "",
                "known_ransomware": bool(v.get("knownRansomwareCampaignUse", False)),
                "notes": v.get("notes") or "",
            })
        return pd.DataFrame(rows)

    def save_csv(self, df: pd.DataFrame, filename: str = "cisa_kev.csv") -> str:
        """
        Save KEV DataFrame to data/<filename>.
        """
        os.makedirs("data", exist_ok=True)
        path = os.path.join("data", filename)
        df.to_csv(path, index=False)
        print(f"Saved: {path}")
        return path


if __name__ == "__main__":
    collector = CISACollector()
    print("Collecting CISA KEV...")
    payload = collector.collect_kev()
    if not payload:
        print("KEV collection failed.")
        raise SystemExit(1)

    kev_df = collector.parse_kev_data(payload)
    print(f"KEV entries: {len(kev_df)}")
    collector.save_csv(kev_df)
    print("KEV collection completed.")