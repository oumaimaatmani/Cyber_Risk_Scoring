# Cyber Risk Scoring

End-to-end CVE risk scoring pipeline with interactive Streamlit dashboard.

## Features

- **Data Collection**: NVD API 2.0 (time window + keyword search) + CISA KEV catalog
- **Enrichment**: Temporal features, severity mapping, KEV flags, vendor/product extraction
- **Risk Scoring**: Weighted composite score (severity, exploitability, recency, impact, context)
- **Visualization**: Streamlit dashboard with filters, drilldown, exports

## Project Structure

```
Cyber_Risk_Scoring/
├── data/                      # CSV datasets (committed for reproducibility)
│   ├── .gitkeep
│   ├── cisa_kev.csv          # CISA Known Exploited Vulnerabilities
│   ├── nvd_cves.csv          # NVD raw CVE data
│   ├── processed_cves.csv    # Enriched features
│   ├── scored_cves.csv       # Risk scores and levels
│   └── kev_missing_ids.csv   # KEV IDs not found in NVD
├── CVE_collector.py          # NVD API collector (time, keywords, KEV backfill)
├── CISA_KEV_collector.py     # CISA KEV JSON collector
├── CVE_enricher.py           # Data cleaning, feature engineering
├── RISK_score.py             # Risk scoring model
├── risk_dashboard.py         # Streamlit interactive dashboard
├── requirements.txt          # Python dependencies
├── .gitignore                # Ignore venv, pycache, IDE files
└── README.md                 # This file
```

## Installation

```bash
# Clone repository
git clone https://github.com/<your-username>/Cyber_Risk_Scoring.git
cd Cyber_Risk_Scoring

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### 1. Collect Data

```bash
# Collect CISA KEV catalog
python3 CISA_KEV_collector.py

# Collect NVD CVEs (90 days + keywords + KEV backfill)
# Optional: export NVD_API_KEY=your_key for faster rate limit
python3 CVE_collector.py
```

### 2. Process & Score

```bash
# Enrich with features and KEV flags
python3 CVE_enricher.py

# Calculate risk scores
python3 RISK_score.py
```

### 3. Launch Dashboard

```bash
streamlit run risk_dashboard.py
```

Open browser at `http://localhost:8501`.

## Risk Scoring Model

Weighted composite score (0–100):

| Component       | Weight | Description                                      |
|-----------------|--------|--------------------------------------------------|
| Severity        | 25%    | CVSS score + severity level                      |
| Exploitability  | 30%    | KEV presence, exploit references, awareness      |
| Recency         | 15%    | Age decay (newer CVEs prioritized)               |
| Impact          | 20%    | CPE count (exposure) + severity                  |
| Context         | 10%    | Danger keywords + scope                          |

**Risk Levels**: VERY LOW (0-20), LOW (20-40), MEDIUM (40-60), HIGH (60-80), CRITICAL (80-100)

## Dashboard Features

- **Filters**: Risk level, exploited (KEV), ransomware, vendor, product, date range, search
- **KPIs**: Total CVEs, avg/max risk, exploited count, ransomware count
- **Visualizations**:
  - Risk score distribution (histogram)
  - Risk level breakdown (bar chart)
  - Weekly volume timeline (line chart)
  - Top 20 CVEs by risk (horizontal bar)
  - Top vendors by average risk (horizontal bar, threshold-filtered)
- **Explorer**: Sortable table + CSV export

## Data Sources

- **NVD**: [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- **CISA KEV**: [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Configuration

- **NVD API Key** (optional): Set `NVD_API_KEY` env var to reduce rate limit delays (6s → 0.6s)
- **Time Window**: Edit `days=90` in `CVE_collector.py` main block
- **Keywords**: Edit `technologies` list in `CVE_collector.py`
- **Risk Weights**: Edit `self.weights` dict in `RISK_score.py`

## Results (Example Run)

- **Total CVEs**: 12,564 (90 days + keywords)
- **KEV Exploited**: 28
- **Ransomware-related**: 3
- **Risk Distribution**: Dominated by LOW/MEDIUM, few HIGH, no CRITICAL (threshold ≥80)

## Troubleshooting

**Dashboard slow to load?**
- Normal for ~12k CVEs. `@st.cache_data` speeds up subsequent runs.
- Reduce dataset size or filter early in `load_data()`.

**`KeyError: 'published_date'`?**
- Ensure `CVE_enricher.py` and `RISK_score.py` ran successfully.
- Dashboard has fallback to `nvd_cves.csv` for `published_date`.

**KEV IDs missing?**
- Check `data/kev_missing_ids.csv` for CVE IDs NVD couldn't resolve.
- Possible causes: withdrawn CVEs, typos in KEV catalog.

## License

MIT License (adjust as needed)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit changes (`git commit -m 'Add feature'`)
4. Push to branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## Acknowledgments

- NVD for CVE data
- CISA for KEV catalog
- Streamlit and Plotly communities