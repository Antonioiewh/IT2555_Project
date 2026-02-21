# MLTK Training Data Generators

This directory contains data generators for training Splunk Machine Learning Toolkit (MLTK) models to detect security anomalies.

## Available Generators

### 1. Login Anomaly Detection
**File:** `mltk_data_login.py`

**Purpose:** Detect anomalous login patterns

**Anomalies Detected:**
- Logins at unusual hours
- Logins from unusual IP addresses  
- Rapid succession logins (credential stuffing)
- Unusual day patterns (weekend activity for weekday users)

**Usage:**
```bash
# Preview data
python mltk_data_login.py --dry-run

# Generate training data
python mltk_data_login.py

# Skip anomalies (baseline only)
python mltk_data_login.py --no-anomalies
```

**MLTK Queries:**
- Detect unusual login hours
- Detect unusual IP addresses
- Detect rapid login attempts

---

### 2. Content Security / PII Detection
**File:** `mltk_data_content_security.py`

**Purpose:** Detect anomalous PII/sensitive information posting patterns

**Anomalies Detected:**
- Spike in PII detections (7 events in 1 hour)
- Repeated HIGH severity detections
- Suspicious PII type combinations
- Off-hours PII posting (2-5 AM)

**Usage:**
```bash
# Preview data
python mltk_data_content_security.py --dry-run

# Generate training data
python mltk_data_content_security.py

# Skip anomalies (baseline only)
python mltk_data_content_security.py --no-anomalies
```

**MLTK Queries:**
- Detect unusual PII posting frequency
- Detect unusual risk score patterns
- Detect unusual PII type combinations
- Time-based anomaly detection

**See:** `CONTENT_SECURITY_MLTK_GUIDE.md` for detailed implementation

---

## Quick Start

### 1. Ensure Splunk is Running
```bash
docker ps | grep splunk
```

### 2. Generate Training Data
```bash
# Generate login data
python mltk_data_login.py

# Generate content security data
python mltk_data_content_security.py
```

### 3. Verify in Splunk
```spl
# Check login data
index=main sourcetype=app_security_event event_type="login_success" 
| stats count by username

# Check PII detection data
index=main event_type="pii_detected" 
| stats count by username, severity
```

### 4. Train MLTK Models
See individual guides for specific SPL queries:
- Login: Standard MLTK DensityFunction queries
- Content Security: `CONTENT_SECURITY_MLTK_GUIDE.md`

---

## Data Profiles

### Login Data
- **Users:** 5 (office worker, night shift, freelancer, executive, admin)
- **Events per user:** 100-120 normal logins over 14 days
- **Anomalies:** ~20-30 per flagged user
- **Total events:** ~600-700

### Content Security Data  
- **Users:** 4 (careful, average, careless, business)
- **Events per user:** 80-150 content checks
- **PII rate:** 2%-12% depending on user type
- **Anomalies:** ~20-25 per flagged user
- **Total events:** ~450-550

---

## Environment Variables

Set in `.env` file or environment:
```bash
SPLUNK_HOST=splunk
SPLUNK_PORT=8088
SPLUNK_HEC_TOKEN=your-hec-token-here
```

**Note:** Update `hec_token` in each script with your actual token from Splunk settings.

---

## File Structure

```
MLTK/
├── README.md                           # This file
├── mltk_data_login.py                  # Login anomaly generator
├── mltk_data_content_security.py       # PII detection anomaly generator
└── CONTENT_SECURITY_MLTK_GUIDE.md      # Detailed PII/MLTK guide
```

---

## Common SPL Patterns

### View All Security Events
```spl
index=main sourcetype=app_security_event
| stats count by event_type
```

### Anomaly Detection Template
```spl
index=main event_type="YOUR_EVENT_TYPE"
| bucket _time span=1h
| stats YOUR_METRIC by _time, username
| fit DensityFunction YOUR_METRIC by username into YOUR_MODEL_NAME
| where 'IsOutlier(YOUR_METRIC)' = "True"
```

### Alert Template
```spl
index=main event_type="YOUR_EVENT_TYPE"
| KEY_DETECTION_LOGIC
| where THRESHOLD_CONDITION
| eval alert_message="Alert: " + username + " triggered anomaly"
| table _time, username, alert_message
```

---

## Tips

1. **Run dry-run first** to verify data patterns before sending to Splunk
2. **Wait 2-3 minutes** after data generation for Splunk indexing
3. **Tune sensitivity** in MLTK queries based on false positive rate
4. **Retrain models weekly** as user behavior evolves
5. **Monitor model performance** using `| fit summary model_name`

---

## Troubleshooting

**Q: No data showing in Splunk**
- Check HEC token is correct
- Verify Splunk is accessible: `curl http://splunk:8088`
- Check Docker network connectivity

**Q: Too many false positives**
- Increase DensityFunction sensitivity parameter (0.1 to 0.9)
- Extend training period for better baseline
- Review user profiles in generator code

**Q: Missing real anomalies**  
- Decrease sensitivity threshold
- Check if training includes enough edge cases
- Review anomaly generation logic

---

## Future Generators (Potential)

- File upload anomaly detection
- Message attachment security patterns
- Rate limiting violation patterns
- WAF rule violation clustering
- Session hijacking detection
- Permission escalation attempts

---

## Contributing

When adding new generators:
1. Follow existing code structure
2. Include dry-run mode
3. Document MLTK queries in markdown guide
4. Add user profiles with normal + anomalous behavior
5. Update this README

---

## License

Part of AppSecurity project - Educational purposes only
