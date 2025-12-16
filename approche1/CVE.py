import pandas as pd
import re
import warnings
from datetime import datetime

warnings.filterwarnings('ignore')

# Charger ton dataset CVE
print(" Chargement du dataset CVE (peut prendre 1-2 minutes)...")
try:
    df = pd.read_csv("hf://datasets/stasvinokur/cve-and-cwe-dataset-1999-2025/CVE_CWE_2025.csv")
    print(f" Dataset chargé : {len(df)} lignes")
except Exception as e:
    print(f" Erreur de chargement : {e}")
    exit(1)
# --- 1️ Identifier un type de vulnérabilité ---
def detect_vuln_type(desc):
    """Détecte le type de vulnérabilité à partir de la description"""
    desc = str(desc).lower()
    
    if "overflow" in desc or "buffer" in desc:
        return "Buffer Overflow"
    elif "sql" in desc or "sql injection" in desc:
        return "SQL Injection"
    elif "xss" in desc or "cross-site" in desc:
        return "XSS"
    elif "csrf" in desc or "cross-site request" in desc:
        return "CSRF"
    elif "denial of service" in desc or "dos" in desc or "ddos" in desc:
        return "DoS"
    elif "remote code" in desc or "rce" in desc:
        return "Remote Code Execution"
    elif "privilege escalation" in desc or "privilege" in desc:
        return "Privilege Escalation"
    elif "authentication" in desc or "bypass" in desc:
        return "Auth Bypass"
    elif "path traversal" in desc or "directory traversal" in desc:
        return "Path Traversal"
    elif "information disclosure" in desc or "information leak" in desc:
        return "Information Disclosure"
    else:
        return "Other"

df['Vuln_Type'] = df['DESCRIPTION'].apply(detect_vuln_type)

# --- 2️ Mapping SEVERITY en Risk_Score ---
severity_map = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0
}
df['Risk_Score'] = df['SEVERITY'].fillna('UNKNOWN').map(lambda x: severity_map.get(str(x).upper().strip(), 0))

# --- 3️ Dictionnaire de normalisation des produits ---

product_map = {
    "WordPress": ["wordpress", "wp plugin", "wp theme"],
    "Linux": ["linux", "ubuntu", "debian", "centos", "redhat", "fedora", "kernel"],
    "Apache": ["apache", "httpd", "tomcat", "struts", "activemq", "cxf", "hadoop"],
    "Windows": ["windows", "win32", "win64", "iis", "microsoft"],
    "Oracle": ["oracle", "oracle db", "oracle forms", "oracle linux"],
    "FTP": ["ftp", "vsftpd", "proftpd"],
    "POP": ["pop", "pop3"],
    "IMAP": ["imap", "imap4"],
    "SSH": ["ssh", "openssh", "putty"],
    "BIND": ["bind", "named"],
    "CDE": ["cde"],
    "MySQL": ["mysql", "mariadb"],
    "PostgreSQL": ["postgresql", "pgadmin"],
    "Redis": ["redis"],
    "NGINX": ["nginx"],
    "Magento": ["magento"],
    "Joomla": ["joomla"],
    "Drupal": ["drupal"],
    "Docker": ["docker"],
    "Kubernetes": ["kubernetes", "k8s"],
    "Jenkins": ["jenkins"],
    "MongoDB": ["mongodb", "mongo"],
    "AWS": ["aws", "amazon s3", "ec2"],
    "Azure": ["azure"],
    "Postfix": ["postfix"],
    "Dovecot": ["dovecot"],
    "Perl": ["perl"],
    "Python": ["python"],
    "PHP": ["php"],
    "Node.js": ["node.js", "nodejs"],
    "Java": ["java"],
    "Ruby": ["ruby"],
    "Go": ["go", "golang"],
    "Rust": ["rust"]
}

STOPWORDS = {"the","that","all","before","sensitive","unspecified","multiple","versions","index","which","where","contains"}

# --- 3️ Fonction consolidée d'extraction et normalisation ---
def extract_and_normalize_product(row):
    """Extrait le produit de la description et le normalise"""
    text = str(row.get('AFFECTED_PRODUCT') or row.get('DESCRIPTION') or "").lower()
    # 1) Prioritize keyword mapping anywhere in text
    for key, keywords in product_map.items():
        for kw in keywords:
            if kw in text:
                return key
    # 2) Try stricter regex captures
    patterns = [
        r'affects?\\s+([A-Za-z0-9\\-\\._ ]{3,60?})(?:[\\.,;]|$)',
        r'(?:in|via)\\s+([A-Za-z0-9\\-\\._ ]{3,60?})(?:[\\.,;]|$)',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            cand = m.group(1).strip()
            # remove generic tokens
            tokens = [t for t in re.split(r'\\s+', cand) if t not in STOPWORDS]
            cand_clean = " ".join(tokens)
            for key, keywords in product_map.items():
                for kw in keywords:
                    if kw in cand_clean:
                        return key
    # 3) No reliable product found → return Unknown (do not fallback to 'The' etc.)
    return "Unknown"

df['PRODUCT_CLEAN'] = df.apply(extract_and_normalize_product, axis=1)


# --- 4️ Garder seulement les CVE valides (produit != Unknown) ---
df_clean = df[df['PRODUCT_CLEAN'] != "Unknown"]

# --- 5️ Sélectionner les colonnes finales pour power bi ---
df_final = df_clean[['CVE-ID', 'PRODUCT_CLEAN', 'SEVERITY', 'Risk_Score', 'Vuln_Type']]

# --- 6️ Sauvegarder en CSV ---
df_final.to_csv("Cyber_Risk_Enriched.csv", index=False)

print(f"Dataset prêt pour power bi : {len(df_final)} lignes")
print(df_final.head(10))

# Compter le nombre de CVE par produit
product_counts = df['PRODUCT_CLEAN'].value_counts()

print(product_counts)


df_summary = df_final.groupby("PRODUCT_CLEAN").agg(
    Total_Risk_Score=("Risk_Score", "sum"),
    Nb_Vulnerabilities=("CVE-ID", "count")
)
df_summary["Avg_Risk_Per_Vuln"] = df_summary["Total_Risk_Score"] / df_summary["Nb_Vulnerabilities"]
df_summary.to_csv("Cyber_Risk_Summary.csv")
print(df_summary.sort_values("Total_Risk_Score", ascending=False).head(20))
