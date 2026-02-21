# MLTK Content Security Implementation Guide

## Overview
This guide explains how to use Splunk's Machine Learning Toolkit (MLTK) to detect anomalous PII/sensitive information patterns in your application.

## What Was Implemented

### 1. PII Detection in Application (app.py)

**Locations:**
- **Signup** (`/signup`): Checks username for PII during registration
- **Edit Profile** (`/edit_profile`): Validates username changes
- **Create Post** (`/create_post`): Scans post content for sensitive information

**PII Types Detected (13+ patterns):**
- **HIGH severity:** NRIC, Credit Cards, SSN, Passport, API Keys
- **MEDIUM severity:** Phone numbers, Bank accounts, Driving licenses, MAC addresses, Bitcoin addresses
- **LOW severity:** Emails, Postal codes, IP addresses

**Behavior:**
- **HIGH severity:** Blocks the action, logs to Splunk
- **MEDIUM severity:** Warns user, allows action, logs to Splunk
- **LOW severity:** Silent logging only

### 2. Splunk Event Logging

**Event Types:**
```json
{
  "event_type": "pii_detected_post",  // or "pii_detected_username", "pii_detected_signup"
  "data": {
    "user_id": 123,
    "username": "john_doe",
    "content_type": "post",
    "severity": "HIGH",
    "risk_score": 85,
    "match_count": 3,
    "pii_types": ["credit_card", "nric", "ssn"],
    "safe_for_storage": false
  },
  "severity": "HIGH",
  "timestamp": "2026-02-21T10:30:45Z",
  "source_ip": "192.168.1.100"
}
```

### 3. MLTK Training Data Generator

**File:** `project/MLTK/mltk_data_content_security.py`

**User Profiles:**
- `normal_user_1`: Careful user (2% PII rate)
- `normal_user_2`: Average user (5% PII rate)
- `careless_user`: Moderate PII posting (12% PII rate)
- `business_user`: Posts contact info (8% PII rate)

**Anomaly Types Generated:**
1. **Spike in detections:** 7 HIGH severity events in 1 hour
2. **Repeated high severity:** Multiple HIGH severity in short time
3. **Suspicious combinations:** credit_card + NRIC + passport together
4. **Off-hours posting:** PII detected at 2-5 AM

## How to Use MLTK for Anomaly Detection

### Step 1: Generate Training Data

```bash
cd project/MLTK

# Dry run to preview data
python mltk_data_content_security.py --dry-run

# Generate actual data to Splunk
python mltk_data_content_security.py

# Generate without anomalies (baseline only)
python mltk_data_content_security.py --no-anomalies
```

### Step 2: Verify Data in Splunk

```spl
index=main event_type="pii_detected" 
| stats count by username, severity
```

### Step 3: MLTK Anomaly Detection Models

#### A) Detect Unusual PII Posting Frequency

**Training Query:**
```spl
index=main event_type="pii_detected" 
| bucket _time span=1h
| stats count as pii_count by _time, username
| fit DensityFunction pii_count by username into pii_frequency_model
```

**Detection Query:**
```spl
index=main event_type="pii_detected" 
| bucket _time span=1h
| stats count as pii_count by _time, username
| apply pii_frequency_model
| where 'IsOutlier(pii_count)' = "True"
| table _time, username, pii_count
```

**What it detects:** Users suddenly posting much more PII than normal

---

#### B) Detect Unusual Risk Score Patterns

**Training Query:**
```spl
index=main event_type="pii_detected"
| stats avg(data.risk_score) as avg_risk, max(data.risk_score) as max_risk by username
| fit DensityFunction avg_risk max_risk by username into risk_pattern_model
```

**Detection Query:**
```spl
index=main event_type="pii_detected"
| bucket _time span=1h
| stats avg(data.risk_score) as avg_risk by _time, username
| apply risk_pattern_model
| where 'IsOutlier(avg_risk)' = "True"
| table _time, username, avg_risk
```

**What it detects:** Users with abnormally high risk scores

---

#### C) Detect Unusual PII Type Combinations

**Query:**
```spl
index=main event_type="pii_detected"
| eval pii_combo=mvjoin('data.pii_types', ",")
| rare pii_combo by username limit=10
| where count < 3
```

**What it detects:** Rare/suspicious combinations like "credit_card,nric,passport"

---

#### D) Time-Based Anomaly Detection

**Training Query:**
```spl
index=main event_type="pii_detected"
| eval hour=tonumber(strftime(_time, "%H"))
| stats count by hour, username
| fit DensityFunction hour by username into time_pattern_model
```

**Detection Query:**
```spl
index=main event_type="pii_detected"
| eval hour=tonumber(strftime(_time, "%H"))
| apply time_pattern_model
| where 'IsOutlier(hour)' = "True"
| where hour >= 2 AND hour <= 5
| table _time, username, hour, data.severity
```

**What it detects:** PII posting during unusual hours (2-5 AM)

---

#### E) Severity Escalation Detection

**Query:**
```spl
index=main event_type="pii_detected"
| bucket _time span=1d
| stats count(eval(data.severity="HIGH")) as high_count,
        count(eval(data.severity="MEDIUM")) as medium_count,
        count(eval(data.severity="LOW")) as low_count by _time, username
| fit DensityFunction high_count by username into severity_escalation_model
| where 'IsOutlier(high_count)' = "True"
| where high_count > 2
```

**What it detects:** Sudden increase in HIGH severity PII detections

---

### Step 4: Create Alerts

**Example Alert for Suspicious Activity:**
```spl
index=main event_type="pii_detected"
| bucket _time span=1h
| stats count as pii_count, values(data.pii_types) as pii_types by _time, username
| where pii_count >= 5
| eval alert_message="User " + username + " triggered " + pii_count + " PII detections in 1 hour"
| table _time, username, pii_count, pii_types, alert_message
```

**Alert Conditions:**
- **Trigger:** When search returns results
- **Throttle:** Once per hour per user
- **Action:** Email security team

---

### Step 5: Dashboard Visualization

**SPL for Dashboard Panel:**
```spl
index=main event_type="pii_detected"
| timechart span=1h count by data.severity
```

**Recommended Panels:**
1. **PII Detections Over Time** (line chart by severity)
2. **Top Users by PII Count** (bar chart)
3. **Risk Score Distribution** (histogram)
4. **PII Types Breakdown** (pie chart)
5. **Anomaly Alerts** (single value with trend)

---

## Real-World Use Cases

### 1. Insider Threat Detection
**Scenario:** Employee copying customer data to posts
- **Detection:** Spike in HIGH severity + unusual PII combinations
- **MLTK Model:** Frequency + Combination analysis

### 2. Account Compromise
**Scenario:** Stolen account used for data exfiltration
- **Detection:** Off-hours activity + risk score escalation
- **MLTK Model:** Time-based + Risk pattern analysis

### 3. Accidental Data Leakage
**Scenario:** User accidentally pasting sensitive data
- **Detection:** Sudden increase from normally careful user
- **MLTK Model:** User behavior baseline + frequency analysis

### 4. Data Harvesting Bot
**Scenario:** Automated scraping posting stolen data
- **Detection:** Rapid succession + consistent HIGH severity
- **MLTK Model:** Frequency + Time clustering

---

## Advanced MLTK Techniques

### Multi-Variable Clustering
```spl
index=main event_type="pii_detected"
| stats count as freq, avg(data.risk_score) as avg_risk, 
        dc(data.pii_types) as unique_types by username
| fit KMeans freq avg_risk unique_types k=3
```

### Predictive Forecasting
```spl
index=main event_type="pii_detected" username="careless_user"
| timechart span=1h count as pii_count
| fit StateSpaceForecast pii_count forecast_k=24
```

### Correlation with Other Events
```spl
index=main (event_type="pii_detected" OR event_type="login_failure")
| stats count by username, event_type
| fit FieldSelector event_type from count by username
```

---

## Monitoring and Tuning

### Model Performance Metrics
```spl
| fit summary pii_frequency_model
```

### Retraining Schedule
- **Weekly:** Update baseline models with new normal behavior
- **Monthly:** Review and adjust anomaly thresholds
- **Quarterly:** Audit false positives and retune

### Threshold Tuning
```spl
| apply pii_frequency_model sensitivity=0.9  # More sensitive (more alerts)
| apply pii_frequency_model sensitivity=0.1  # Less sensitive (fewer alerts)
```

---

## Integration with Response Actions

### Automatic Account Lockout
When HIGH severity spike detected:
```python
# In app.py - add to PII detection block
if pii_check['severity'] == 'HIGH':
    # Check recent history
    recent_high = get_recent_pii_count(user_id, severity='HIGH', hours=1)
    if recent_high >= 3:
        # Temporary lock account
        current_user.current_status = 'suspended'
        db.session.commit()
        
        # Alert admins
        create_admin_alert(user_id, 'multiple_high_severity_pii')
```

### Content Redaction
Automatically redact detected PII:
```python
# Apply redaction to post content
if pii_check['match_count'] > 0:
    redacted_content = post_content
    for match in pii_check['matches']:
        redacted_content = redacted_content.replace(
            match['original_text'], 
            f"[{match['type'].upper()}_REDACTED]"
        )
    new_post.post_content = redacted_content
```

---

## Files Modified/Created

1. **app.py** - Added PII detection to:
   - `/signup` route
   - `/edit_profile` route  
   - `/create_post` route

2. **MLTK/mltk_data_content_security.py** - New training data generator

3. **validators_py/content_validate.py** - Existing PII checker (already implemented)

4. **splunk_logger.py** - Existing Splunk logger (already implemented)

---

## Next Steps

1. ✅ Generate training data: `python mltk_data_content_security.py`
2. ✅ Verify logs in Splunk
3. ⬜ Train MLTK models using queries above
4. ⬜ Set up alerts for anomalous patterns
5. ⬜ Create monitoring dashboard
6. ⬜ Integrate automated response actions
7. ⬜ Schedule weekly model retraining

---

## Troubleshooting

**Issue:** No data in Splunk
- Check HEC token is correct
- Verify Splunk is running: `docker ps | grep splunk`
- Check network connectivity: `curl http://splunk:8088`

**Issue:** Too many false positives
- Increase sensitivity threshold in MLTK queries
- Extend training period for better baseline
- Adjust user profiles in data generator

**Issue:** Missing anomalies
- Decrease sensitivity threshold
- Review anomaly generation parameters
- Check if training data includes edge cases

---

## References

- [Splunk MLTK Documentation](https://docs.splunk.com/Documentation/MLApp)
- [DensityFunction Algorithm](https://docs.splunk.com/Documentation/MLApp/latest/User/Algorithms#DensityFunction)
- [Anomaly Detection Best Practices](https://www.splunk.com/en_us/blog/tips-and-tricks/anomaly-detection-with-machine-learning.html)
