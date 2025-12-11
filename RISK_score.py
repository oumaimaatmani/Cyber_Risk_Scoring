"""
Cyber risk scoring model
- Compute composite risk score per CVE
- Categorize risk levels
- Export statistics and scored CSV
"""

import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler


class CyberRiskScorer:
    """Compute risk scores for CVEs"""

    def __init__(self) -> None:
        # Weights can be tuned; keep them consistent with prior runs
        self.weights = {
            "severity": 0.25,
            "exploitability": 0.30,
            "recency": 0.15,
            "impact": 0.20,
            "context": 0.10,
        }
        self.scaler = MinMaxScaler(feature_range=(0, 100))

    def calculate_severity_score(self, df: pd.DataFrame) -> pd.Series:
        # Normalize CVSS and severity_weight into a severity component
        cvss = pd.to_numeric(df.get("cvss_score"), errors="coerce").fillna(0)
        sev_w = pd.to_numeric(df.get("severity_weight"), errors="coerce").fillna(0.5)
        return (cvss / 10.0) * 70 + sev_w * 30  # out of 100

    def calculate_exploitability_score(self, df: pd.DataFrame) -> pd.Series:
        # is_exploited and exploit_score boosts; references add minor weight
        exploited = df.get("is_exploited", False).astype(int) * 60
        exploit_ref = pd.to_numeric(df.get("exploit_score"), errors="coerce").fillna(0) * 20
        ref_s = pd.to_numeric(df.get("reference_score"), errors="coerce").fillna(0) * 4
        return exploited + exploit_ref + ref_s  # cap later by scaling

    def calculate_recency_score(self, df: pd.DataFrame) -> pd.Series:
        # Newer CVEs should have higher attention
        age = pd.to_numeric(df.get("age_days"), errors="coerce").fillna(9999)
        rec = np.exp(-age / 180.0) * 100  # decays with age
        return pd.Series(rec, index=df.index)

    def calculate_impact_score(self, df: pd.DataFrame) -> pd.Series:
        # cpe_count as exposure proxy + severity
        cpe = pd.to_numeric(df.get("cpe_count"), errors="coerce").fillna(0)
        sev = pd.to_numeric(df.get("severity_weight"), errors="coerce").fillna(0.5)
        return np.log1p(cpe) * 40 + sev * 60

    def calculate_context_score(self, df: pd.DataFrame) -> pd.Series:
        # danger keywords and scope_score
        danger = pd.to_numeric(df.get("danger_keywords_count"), errors="coerce").fillna(0)
        scope = pd.to_numeric(df.get("scope_score"), errors="coerce").fillna(0)
        return danger * 15 + scope * 10

    def calculate_risk_score(self, df: pd.DataFrame) -> pd.DataFrame:
        # Compose the weighted risk score
        comp = pd.DataFrame(index=df.index)
        comp["severity"] = self.calculate_severity_score(df)
        comp["exploitability"] = self.calculate_exploitability_score(df)
        comp["recency"] = self.calculate_recency_score(df)
        comp["impact"] = self.calculate_impact_score(df)
        comp["context"] = self.calculate_context_score(df)

        # Weighted sum then scale to 0-100
        raw = (
            comp["severity"] * self.weights["severity"]
            + comp["exploitability"] * self.weights["exploitability"]
            + comp["recency"] * self.weights["recency"]
            + comp["impact"] * self.weights["impact"]
            + comp["context"] * self.weights["context"]
        ).fillna(0).to_numpy().reshape(-1, 1)

        scaled = self.scaler.fit_transform(raw).flatten()
        df_out = df.copy()
        df_out["risk_score"] = scaled.round(2)
        return df_out

    def categorize_risk(self, df: pd.DataFrame) -> pd.DataFrame:
        # Buckets for risk levels
        cuts = [0, 20, 40, 60, 80, 101]
        labels = ["VERY LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        df["risk_level"] = pd.cut(df["risk_score"], bins=cuts, labels=labels, include_lowest=True)
        return df

    def generate_statistics(self, df: pd.DataFrame) -> None:
        # Print simple stats (kept minimal, no emojis)
        print("\nRISK SCORE STATISTICS")
        print(f"Total CVE: {len(df)}")
        print(f"Average: {df['risk_score'].mean():.2f}")
        print(f"Median: {df['risk_score'].median():.2f}")
        print(f"Max: {df['risk_score'].max():.2f}")
        dist = df["risk_level"].value_counts().sort_index()
        print("\nDistribution by risk level:")
        print(dist)

    def save_scored_data(self, df: pd.DataFrame, filename: str = "scored_cves.csv") -> str:
        os.makedirs("data", exist_ok=True)
        path = os.path.join("data", filename)
        df.to_csv(path, index=False)
        print(f"\nSaved scored CVEs: {path}")
        return path


if __name__ == "__main__":
    # Load processed CVEs
    df = pd.read_csv("data/processed_cves.csv") if os.path.exists("data/processed_cves.csv") else pd.DataFrame()
    if df.empty or "cve_id" not in df.columns:
        print("processed_cves.csv not found or invalid.")
        raise SystemExit(1)

    # Compute scores
    scorer = CyberRiskScorer()
    df_scored = scorer.calculate_risk_score(df)
    df_scored = scorer.categorize_risk(df_scored)
    scorer.generate_statistics(df_scored)
    scorer.save_scored_data(df_scored)
    print("\nScoring completed.")