import re
import os

def parse_modsec_audit_log(file_path):
    logs = []
    with open(file_path, 'r') as file:
        content = file.read()

    # Split the log file into individual entries using the delimiter
    entries = content.split('---Z--')
    for entry in entries:
        if entry.strip():  # Ignore empty entries
            # Check if the entry contains "ModSecurity: Warning. detected ..."
            if "ModSecurity: Warning. detected" in entry:
                log = {}
                # Extract transaction section
                transaction_match = re.search(r'---A--\n\[(.*?)\]', entry)
                if transaction_match:
                    transaction_data = transaction_match.group(1)  # Extract full transaction data
                    # Split transaction data into date and time
                    date_time_match = re.match(r'(\d{2}/\w{3}/\d{4}):(\d{2}:\d{2}:\d{2})', transaction_data)
                    if date_time_match:
                        log['date'] = date_time_match.group(1)  # Extract date (e.g., 12/Jun/2025)
                        log['time'] = date_time_match.group(2)  # Extract time (e.g., 10:05:24)
                    else:
                        log['date'] = "Unknown Date"
                        log['time'] = "Unknown Time"

                    # Extract source IP
                    source_match = re.search(r'---A--\n.*? (\S+) (\S+) (\S+) (\S+)', entry)
                    log['source'] = source_match.group(3) if source_match else "Unknown Source"
                else:
                    log['date'] = "Unknown Date"
                    log['time'] = "Unknown Time"
                    log['source'] = "Unknown Source"

                # Extract request section
                request_match = re.search(r'---B--\n(.*?)\n', entry, re.DOTALL)
                log['request'] = request_match.group(1).strip() if request_match else "Unknown Request"

                # Extract response section
                response_match = re.search(r'---F--\n(.*?)\n', entry, re.DOTALL)
                log['response'] = response_match.group(1).strip() if response_match else "Unknown Response"

                # Extract the attack detected (exclude data after "XSS using libinjection.")
                attack_match = re.search(r'ModSecurity: Warning\. detected (.*?)\.', entry)
                if attack_match:
                    log['attack_detected'] = attack_match.group(1).strip() + "."  # Include only the attack description up to the period
                else:
                    log['attack_detected'] = "Unknown Attack"

                logs.append(log)
    return logs


def parse_error_log(file_path):
    """
    Parses error.log and extracts critical information for specific keywords.
    Includes logs with 'limiting requests' or 'ModSecurity: Access denied'.
    """
    logs = []
    with open(file_path, 'r') as file:
        for line in file:
            # Regular expression to match error log entries
            match = re.match(
                r'(?P<date>\d{4}/\d{2}/\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] \d+#\d+: \*(?P<connection_id>\d+) (?P<message>.*?), client: (?P<client_ip>\S+)',
                line
            )
            if match:
                message = match.group('message')
                # Filter logs based on keywords
                if 'limiting requests' in message or 'ModSecurity: Access denied' in message:
                    log = {
                        'date': match.group('date'),
                        'time': match.group('time'),
                        'level': match.group('level'),
                        'message': message,
                        'client_ip': match.group('client_ip')  # Removed trailing comma
                    }
                    logs.append(log)
    return logs


# Example usage for error logs
error_log_folder = os.path.join(os.path.dirname(__file__), "shared_logs")
error_log_file_path = os.path.join(error_log_folder, "error.log")
parsed_error_logs = parse_error_log(error_log_file_path)

