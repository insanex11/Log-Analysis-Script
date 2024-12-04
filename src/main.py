import os
from log_parser import parse_log_file
from analysis import count_requests_per_ip, most_frequent_endpoint, detect_suspicious_activity
from output_writer import write_to_csv

def main():
    log_file_path = '../data/sample.log'
    output_file_path = '../output/log_analysis_results.csv'

    if not os.path.exists(log_file_path):
        print(f"Log file not found at {log_file_path}")
        return

    # Parsing log file
    log_entries = parse_log_file(log_file_path)

    # Analysing logs by declaring variables for count of requests per ip, endpoint and suspicious activity
    requests = count_requests_per_ip(log_entries)
    endpoint = most_frequent_endpoint(log_entries)
    suspicious_ips = detect_suspicious_activity(log_entries)

    # Displaying the final results
    
    # Requests per ip
    print("Requests per IP Address:")
    for ip, count in requests:
        print(f"{ip} - {count}")

    # Most frequently accessed endpoint
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{endpoint[0]} - Accessed {endpoint[1]} times")

    # suspicious activity detection
    if not suspicious_ips:
        print("\nNo suspicious activity detected.")
    else:
        print("\nSuspicious Activity Detected:")
        for ip, count in suspicious_ips:
            print(f"{ip} - {count} failed attempts")

    # Writing results to CSV
    write_to_csv(output_file_path, requests, endpoint, suspicious_ips)

if __name__ == "__main__":
    main()