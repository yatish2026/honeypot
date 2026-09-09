"""Honeypot vs Production Server Dataset Generator & Model Training Pipeline."""

import os
import random
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
import joblib

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import DATASETS_DIR, MODELS_DIR
from modules.honeypot_detector.feature_extractor import FEATURE_NAMES, extract_features_from_scan


def generate_synthetic_scan_dataset(n_samples: int = 1200) -> pd.DataFrame:
    """
    Generates realistic honeypot and production server telemetry dataset.
    Simulates real-world scan observations across Cowrie, Dionaea, Conpot, Kippo, Glastopf,
    and genuine production services (Nginx, Apache, OpenSSH, AWS, Azure, GCP hosts).
    """
    np.random.seed(42)
    random.seed(42)
    
    records = []
    
    for i in range(n_samples):
        is_honeypot = random.random() < 0.5
        
        if is_honeypot:
            honeypot_type = random.choice(["cowrie", "dionaea", "conpot", "kippo", "glastopf", "generic_trap"])
            
            if honeypot_type == "cowrie":
                ports = random.choice([[22, 2222], [22, 23, 2222], [2222]])
                banners = {
                    22: random.choice(["SSH-2.0-Cowrie linux-x86_64", "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2", "SSH-2.0-OpenSSH_7.9p1 Raspbian"]),
                    2222: "SSH-2.0-Cowrie twisted.conch",
                    23: "Debian GNU/Linux 7.0 login: "
                }
                latencies = {p: random.uniform(1.5, 6.0) for p in ports}
                
            elif honeypot_type == "dionaea":
                ports = random.choice([[21, 445, 1433, 3306], [21, 445, 1433], [21, 23, 445, 3306, 5060]])
                banners = {
                    21: random.choice(["220 Welcome to virtual FTP", "220 FTP server ready", "220 (vsFTPd 2.0.8)"]),
                    445: "SMB-Emulation-v1.0 Dionaea",
                    1433: "Microsoft SQL Server 2012 Service Pack 1",
                    3306: "5.5.40-0ubuntu0.14.04.1-log MySQL honeyd"
                }
                latencies = {p: random.uniform(0.8, 3.5) for p in ports}
                
            elif honeypot_type == "conpot":
                ports = random.choice([[102, 502], [502, 161], [102, 502, 161]])
                banners = {
                    102: "Siemens S7-200 SIMATIC S7 PLC Emulated Responder conpot",
                    502: "Modbus TCP Slave ID: 1, Schneider Electric Conpot Node",
                    161: "SNMPv2-MIB::sysDescr.0 = STRING: Siemens SIMATIC S7"
                }
                latencies = {p: random.uniform(4.0, 12.0) for p in ports}
                
            elif honeypot_type == "kippo":
                ports = [22, 2222]
                banners = {
                    22: "SSH-2.0-OpenSSH_5.1p1 Debian-5",
                    2222: "SSH-2.0-OpenSSH_5.5p1"
                }
                latencies = {p: random.uniform(2.0, 5.5) for p in ports}
                
            elif honeypot_type == "glastopf":
                ports = [80, 8080]
                banners = {
                    80: "Server: Glastopf\nX-Powered-By: PHP/5.3.10-1ubuntu3.26",
                    8080: "Server: Python/2.7 SimpleHTTP/0.6"
                }
                latencies = {p: random.uniform(2.5, 8.0) for p in ports}
                
            else: # generic trap
                ports = random.sample([21, 22, 23, 80, 445, 1433, 2222], k=random.randint(3, 5))
                banners = {p: "Generic Deception Daemon v1.0" for p in ports}
                latencies = {p: random.uniform(1.0, 4.0) for p in ports}
                
            scan_data = {
                "open_ports": ports,
                "banners": {p: banners[p] for p in ports if p in banners},
                "latencies": latencies
            }
            label = 1  # 1 = Honeypot
            
        else:
            # Real Production Server Profiles
            prod_type = random.choice(["web_cloud", "ssh_gateway", "db_server", "enterprise_app"])
            
            if prod_type == "web_cloud":
                ports = random.choice([[80, 443], [443], [80, 443, 8443]])
                banners = {
                    80: random.choice(["HTTP/1.1 301 Moved Permanently\nServer: cloudflare", "HTTP/1.1 301 Moved Permanently\nServer: nginx/1.18.0"]),
                    443: random.choice(["HTTP/1.1 200 OK\nServer: nginx/1.24.0 (Ubuntu)\nStrict-Transport-Security: max-age=31536000", "HTTP/1.1 200 OK\nServer: Apache/2.4.52 (Ubuntu)"])
                }
                latencies = {p: random.uniform(25.0, 120.0) for p in ports}
                
            elif prod_type == "ssh_gateway":
                ports = [22]
                banners = {
                    22: random.choice(["SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", "SSH-2.0-OpenSSH_8.7"])
                }
                latencies = {p: random.uniform(35.0, 95.0) for p in ports}
                
            elif prod_type == "db_server":
                ports = random.choice([[22, 3306], [22, 1433], [22, 5432]])
                banners = {
                    22: "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
                    3306: "8.0.35-0ubuntu0.22.04.1 MySQL Community Server (GPL)",
                    1433: "Microsoft SQL Server 2019 RTM (CU14) Enterprise"
                }
                latencies = {p: random.uniform(30.0, 80.0) for p in ports}
                
            else: # enterprise app
                ports = [80, 443, 8080]
                banners = {
                    80: "HTTP/1.1 302 Found\nLocation: https://login.microsoftonline.com",
                    443: "HTTP/1.1 200 OK\nServer: Microsoft-IIS/10.0",
                    8080: "HTTP/1.1 401 Unauthorized\nServer: Jetty(9.4.44.v20210927)"
                }
                latencies = {p: random.uniform(40.0, 150.0) for p in ports}
                
            scan_data = {
                "open_ports": ports,
                "banners": {p: banners[p] for p in ports if p in banners},
                "latencies": latencies
            }
            label = 0  # 0 = Real Production Server
            
        features = extract_features_from_scan(scan_data)
        record = {name: val for name, val in zip(FEATURE_NAMES, features)}
        record["is_honeypot"] = label
        records.append(record)
        
    df = pd.DataFrame(records)
    return df


def train_and_export_model():
    """Trains the RandomForestClassifier and saves the model artifact."""
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    csv_path = DATASETS_DIR / "honeypot_dataset.csv"
    model_path = MODELS_DIR / "honeypot_model.joblib"
    
    print("[*] Generating synthetic honeypot & production telemetry dataset...")
    df = generate_synthetic_scan_dataset(n_samples=1500)
    df.to_csv(csv_path, index=False)
    print(f"[+] Dataset saved to {csv_path} ({len(df)} samples)")
    
    X = df[FEATURE_NAMES]
    y = df["is_honeypot"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    
    print("[*] Training RandomForest Deception Classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)
    
    # Evaluation
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cv_scores = cross_val_score(clf, X, y, cv=5)
    
    print("\n" + "="*50)
    print("MODEL PERFORMANCE METRICS")
    print("="*50)
    print(f"Accuracy:        {acc*100:.2f}%")
    print(f"Precision:       {prec*100:.2f}%")
    print(f"Recall:          {rec*100:.2f}%")
    print(f"F1-Score:        {f1*100:.2f}%")
    print(f"5-Fold CV Mean:  {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")
    print("="*50)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Production Server", "Honeypot"]))
    
    # Feature Importances
    importances = pd.Series(clf.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=False)
    print("\nTop 7 Most Influential Features:")
    for feat, val in importances.head(7).items():
        print(f"  - {feat:30s}: {val*100:.2f}%")
        
    # Save model and feature names bundle
    model_bundle = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "cv_mean": round(cv_scores.mean(), 4)
        },
        "feature_importances": importances.to_dict()
    }
    
    joblib.dump(model_bundle, model_path)
    print(f"\n[+] Trained model exported successfully to {model_path}")


if __name__ == "__main__":
    train_and_export_model()
