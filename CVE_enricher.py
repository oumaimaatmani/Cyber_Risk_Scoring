"""
CVE data processing and feature engineering
- Clean NVD data
- Merge with CISA KEV
- Extract features and technology info
"""

import os
import pandas as pd
import numpy as np
from datetime import datetime


class CVEDataProcessor:
    """Process and enrich CVE data"""

    def __init__(self) -> None:
        pass

    def load_data(self, nvd_path: str = "data/nvd_cves.csv", kev_path: str = "data/cisa_kev.csv"):
        """
        Load NVD and KEV CSVs. Provide empty frames if missing.
        """
        df_nvd = pd.read_csv(nvd_path) if os.path.exists(nvd_path) else pd.DataFrame()
        df_kev = pd.read_csv(kev_path) if os.path.exists(kev_path) else pd.DataFrame()
        return df_nvd, df_kev

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Basic cleaning: normalize IDs, parse dates, coerce numeric fields, drop duplicates and N/A.
        """
        if df.empty:
            return df

        df = df.copy()
        df["cve_id"] = df["cve_id"].astype(str).str.upper().str.strip()

        # Parse dates safely
        df["published_date"] = pd.to_datetime(df.get("published_date"), errors="coerce")
        df["modified_date"] = pd.to_datetime(df.get("modified_date"), errors="coerce")

        # Numeric coercion with default zeros
        for col in ["cvss_v3_score", "cvss_v2_score", "cpe_count", "reference_count"]:
            df[col] = pd.to_numeric(df.get(col), errors="coerce").fillna(0)

        # Severity fallback
        df["severity"] = df.get("severity", "UNKNOWN").fillna("UNKNOWN").astype(str)

        # Description fallback
        df["description"] = df.get("description", "").astype(str)

        # Drop dupes on cve_id
        df = df.drop_duplicates(subset=["cve_id"])

        # Compute temporal features
        today = pd.Timestamp(datetime.now().date())
        df["age_days"] = (today - df["published_date"]).dt.days
        df["days_since_modified"] = (today - df["modified_date"]).dt.days

        # Fill NaN ages with a large number to avoid negative influence
        df["age_days"] = df["age_days"].fillna(9999)
        df["days_since_modified"] = df["days_since_modified"].fillna(9999)

        return df

    def merge_with_kev(self, df_nvd: pd.DataFrame, df_kev: pd.DataFrame) -> pd.DataFrame:
        """
        Merge NVD with KEV flags: is_exploited and used_by_ransomware.
        """
        if df_nvd.empty:
            return df_nvd

        kev = df_kev.copy()
        if not kev.empty:
            kev["cve_id"] = kev["cve_id"].astype(str).str.upper().str.strip()
            kev = kev[["cve_id", "known_ransomware"]].drop_duplicates("cve_id")
        else:
            kev = pd.DataFrame(columns=["cve_id", "known_ransomware"])

        df = df_nvd.merge(kev, on="cve_id", how="left")
        df["is_exploited"] = df["known_ransomware"].notna()  # KEV presence means exploited
        df["used_by_ransomware"] = df["known_ransomware"].fillna(False).astype(bool)
        df = df.drop(columns=["known_ransomware"], errors="ignore")
        return df

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create simple feature set:
        - severity_weight, reference_score, exploit_score, scope_score
        - danger_keywords_count from description
        """
        if df.empty:
            return df

        df = df.copy()
        # Severity mapping
        sev_map = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.3, "NONE": 0.0, "UNKNOWN": 0.5}
        df["severity_weight"] = df["severity"].map(sev_map).fillna(0.5)

        # Danger keywords
        keywords = ["rce", "remote code", "authentication bypass", "privilege escalation", "sql injection", "xss"]
        df["danger_keywords_count"] = df["description"].str.lower().apply(
            lambda d: sum(k in d for k in keywords)
        )

        # Reference score (proxy for awareness)
        df["reference_score"] = np.log1p(df["reference_count"]).clip(0, 5)

        # Exploit score (from NVD refs tag + KEV)
        df["exploit_score"] = df["is_exploited"].astype(int) * 2 + df["exploit_available"].astype(int)

        # Scope score (from cpe_count)
        df["scope_score"] = np.log1p(df["cpe_count"]).clip(0, 5)

        # CVSS consolidate
        df["cvss_score"] = df[["cvss_v3_score", "cvss_v2_score"]].max(axis=1)

        # Age buckets for reporting
        bins = [-1, 7, 30, 180, 365, 10000]
        labels = ["Very Recent", "Recent", "Medium", "Old", "Very Old"]
        df["age_category"] = pd.cut(df["age_days"], bins=bins, labels=labels)

        return df

    def extract_technology_info(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract primary vendor/product from first CPE criteria if available.
        """
        if df.empty:
            return df

        def parse_vendor_product(cpe: str):
            # CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
            try:
                parts = cpe.split(":")
                vendor = parts[3] if len(parts) > 4 else "unknown"
                product = parts[4] if len(parts) > 5 else "unknown"
                return vendor.lower(), product.lower()
            except Exception:
                return "unknown", "unknown"

        first_cpe = df.get("cpe_list", "").astype(str).str.split("|").str[0].fillna("")
        vendor_product = first_cpe.apply(parse_vendor_product)
        df["primary_vendor"] = vendor_product.apply(lambda t: t[0])
        df["primary_product"] = vendor_product.apply(lambda t: t[1])

        return df

    def save_processed_data(self, df: pd.DataFrame, filename: str = "processed_cves.csv") -> str:
        """
        Save processed CVEs to data/<filename>.
        """
        os.makedirs("data", exist_ok=True)
        path = os.path.join("data", filename)
        df.to_csv(path, index=False)
        print(f"Processed CVEs saved: {path}")
        return path


if __name__ == "__main__":
    processor = CVEDataProcessor()
    print("Loading data...")
    df_nvd, df_kev = processor.load_data()

    print("Cleaning NVD data...")
    df_nvd = processor.clean_data(df_nvd)

    print("Merging with KEV...")
    df_merged = processor.merge_with_kev(df_nvd, df_kev)

    print("Extracting features...")
    df_feat = processor.extract_features(df_merged)

    print("Extracting technology info...")
    df_final = processor.extract_technology_info(df_feat)

    print("Saving processed data...")
    processor.save_processed_data(df_final)
    print("Enrichment completed.")