from collections import Counter

def count_requests_per_ip(log_entries):
    ip_counter = Counter(entry['ip'] for entry in log_entries)
    return ip_counter.most_common()

def most_frequent_endpoint(log_entries):
    endpoint_counter = Counter(entry['endpoint'] for entry in log_entries)
    return endpoint_counter.most_common(1)[0]

def detect_suspicious_activity(log_entries, threshold = 10):
    failed_attempts = Counter(entry['ip'] for entry in log_entries if entry['status'] == '401' or 'Invalid credentials' in entry.get('status_message', ''))
    return [(ip, count) for ip, count in failed_attempts.items() if count > threshold]
