"""
Streamlit dashboard for Cyber Risk Scoring
- Robust CSV loading with fallbacks
- Advanced filters and multiple views
"""

import os
import io
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px

st.set_page_config(page_title="Cyber Risk Dashboard", layout="wide")

PALETTE = {
    "VERY LOW": "#8dd3c7",
    "LOW": "#80b1d3",
    "MEDIUM": "#fdb462",
    "HIGH": "#fb8072",
    "CRITICAL": "#b15928",
}


@st.cache_data(show_spinner=True)
def load_data() -> pd.DataFrame:
    scored = pd.read_csv("data/scored_cves.csv") if os.path.exists("data/scored_cves.csv") else pd.DataFrame()
    processed = pd.read_csv("data/processed_cves.csv") if os.path.exists("data/processed_cves.csv") else pd.DataFrame()
    nvd = pd.read_csv("data/nvd_cves.csv") if os.path.exists("data/nvd_cves.csv") else pd.DataFrame(columns=["cve_id", "published_date"])

    # Ensure minimum columns
    for col in [
        "cve_id", "published_date", "reference_count", "cpe_count", "danger_keywords_count",
        "age_days", "severity", "days_since_modified", "primary_vendor", "primary_product",
        "cvss_score", "is_exploited", "used_by_ransomware"
    ]:
        if col not in processed.columns:
            processed[col] = np.nan

    scored["cve_id"] = scored.get("cve_id", "").astype(str).str.upper().str.strip()
    processed["cve_id"] = processed.get("cve_id", "").astype(str).str.upper().str.strip()
    nvd["cve_id"] = nvd.get("cve_id", "").astype(str).str.upper().str.strip()

    df = scored.merge(processed, on="cve_id", how="left", suffixes=("", "_proc"))

    # Fallback published_date from NVD if missing
    if "published_date" not in df.columns or df["published_date"].isna().all():
        df = df.drop(columns=[c for c in df.columns if c == "published_date"], errors="ignore")
        df = df.merge(nvd[["cve_id", "published_date"]], on="cve_id", how="left")

    # Types
    df["published_date"] = pd.to_datetime(df.get("published_date"), errors="coerce")
    df["risk_level"] = df.get("risk_level", "LOW").astype(str)
    df["primary_vendor"] = df.get("primary_vendor", "unknown").astype(str).fillna("unknown")
    df["primary_product"] = df.get("primary_product", "unknown").astype(str).fillna("unknown")
    df["cvss_score"] = pd.to_numeric(df.get("cvss_score"), errors="coerce")
    df["is_exploited"] = df.get("is_exploited", False).fillna(False).astype(bool)
    df["used_by_ransomware"] = df.get("used_by_ransomware", False).fillna(False).astype(bool)
    df["reference_count"] = pd.to_numeric(df.get("reference_count"), errors="coerce").fillna(0).astype(int)
    df["cpe_count"] = pd.to_numeric(df.get("cpe_count"), errors="coerce").fillna(0).astype(int)
    df["danger_keywords_count"] = pd.to_numeric(df.get("danger_keywords_count"), errors="coerce").fillna(0).astype(int)

    df["week"] = df["published_date"].dt.to_period("W").astype(str)
    df["month"] = df["published_date"].dt.to_period("M").astype(str)
    return df


df = load_data()

# Sidebar filters
st.sidebar.title("Filters")
risk_levels = st.sidebar.multiselect("Risk Levels", options=list(PALETTE.keys()), default=list(PALETTE.keys()))
only_exploited = st.sidebar.checkbox("Only exploited (CISA KEV)", value=False)
only_ransomware = st.sidebar.checkbox("Only ransomware-related", value=False)
vendors = st.sidebar.multiselect("Vendors", sorted(df["primary_vendor"].dropna().unique()), default=[])
products = st.sidebar.multiselect("Products", sorted(df["primary_product"].dropna().unique()), default=[])
date_min = st.sidebar.date_input("Min date (published)", value=df["published_date"].min().date() if df["published_date"].notna().any() else None)
date_max = st.sidebar.date_input("Max date (published)", value=df["published_date"].max().date() if df["published_date"].notna().any() else None)
min_cve_per_vendor = st.sidebar.slider("Min CVE per vendor (aggregations)", 1, 50, 5)
search_text = st.sidebar.text_input("Search (CVE/Vendor/Product/Description)", "")

# Apply filters
mask = df["risk_level"].isin(risk_levels)
if only_exploited:
    mask &= df["is_exploited"]
if only_ransomware:
    mask &= df["used_by_ransomware"]
if vendors:
    mask &= df["primary_vendor"].isin(vendors)
if products:
    mask &= df["primary_product"].isin(products)
if date_min:
    mask &= (df["published_date"] >= pd.Timestamp(date_min))
if date_max:
    mask &= (df["published_date"] <= pd.Timestamp(date_max))
if search_text.strip():
    txt = search_text.lower()
    cols = ["cve_id", "primary_vendor", "primary_product"]
    hay = df[cols].astype(str).apply(lambda s: s.str.contains(txt, case=False, na=False)).any(axis=1)
    if "description" in df.columns:
        desc = df["description"].astype(str).str.contains(txt, case=False, na=False)
        mask &= (hay | desc)
    else:
        mask &= hay

dff = df[mask].copy()

# KPIs
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Filtered CVEs", f"{len(dff):,}")
c2.metric("Average risk", f"{dff['risk_score'].mean():.2f}" if "risk_score" in dff.columns else "N/A")
c3.metric("Max risk", f"{dff['risk_score'].max():.2f}" if "risk_score" in dff.columns else "N/A")
c4.metric("Exploited (KEV)", f"{int(dff['is_exploited'].sum())}")
c5.metric("Ransomware", f"{int(dff['used_by_ransomware'].sum())}")

# Overview
st.subheader("Overview")
colA, colB = st.columns((1, 1))
fig_dist = px.histogram(dff, x="risk_score", nbins=40, color="risk_level",
                        color_discrete_map=PALETTE, title="Risk score distribution")
colA.plotly_chart(fig_dist, use_container_width=True)

counts = dff["risk_level"].value_counts().reindex(list(PALETTE.keys())).fillna(0).reset_index()
counts.columns = ["risk_level", "count"]
fig_bar = px.bar(counts, x="risk_level", y="count", color="risk_level",
                 color_discrete_map=PALETTE, title="Risk level distribution")
colB.plotly_chart(fig_bar, use_container_width=True)

# Time series by week
st.subheader("Weekly volume by risk level")
wagg = dff.dropna(subset=["week"]).groupby(["week", "risk_level"], as_index=False)["cve_id"].count()
fig_week = px.line(wagg, x="week", y="cve_id", color="risk_level",
                   color_discrete_map=PALETTE, title="Weekly CVE count")
st.plotly_chart(fig_week, use_container_width=True)

# Top 20 CVEs
st.subheader("Top 20 CVEs by risk")
top20 = dff.sort_values("risk_score", ascending=False).head(20)
fig_top = px.bar(top20, x="risk_score", y="cve_id", color="is_exploited",
                 title="Top 20 CVEs", orientation="h")
st.plotly_chart(fig_top, use_container_width=True)

# Vendors view
st.subheader("Vendors (aggregated)")
vagg = dff.groupby("primary_vendor", as_index=False).agg(
    avg_risk=("risk_score", "mean"), cve_count=("cve_id", "count"), total_risk=("risk_score", "sum")
)
vagg = vagg[vagg["cve_count"] >= min_cve_per_vendor].sort_values("avg_risk", ascending=False).head(20)
fig_vendor = px.bar(vagg, x="avg_risk", y="primary_vendor", color="cve_count",
                    title="Top vendors by average risk", orientation="h")
st.plotly_chart(fig_vendor, use_container_width=True)

# Explorer table and export
st.subheader("Explorer")
display_cols = [
    "cve_id", "risk_score", "risk_level", "cvss_score", "severity", "age_days",
    "is_exploited", "used_by_ransomware", "primary_vendor", "primary_product",
    "reference_count", "cpe_count", "danger_keywords_count", "published_date"
]
present_cols = [c for c in display_cols if c in dff.columns]
st.dataframe(dff[present_cols].sort_values("risk_score", ascending=False), height=480)

csv_bytes = dff[present_cols].to_csv(index=False).encode("utf-8")
st.download_button("Download filtered CSV", data=csv_bytes, file_name="cve_risk_filtered.csv", mime="text/csv")