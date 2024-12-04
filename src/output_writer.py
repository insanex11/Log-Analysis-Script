import csv

def write_to_csv(file_path, requests, endpoint, suspicious_ips):
    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Writing Requests per IP Address
        writer.writerow(['Requests per IP Address'])
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(requests)
        writer.writerow([])
        
        # Writing Most Frequently Accessed Endpoint
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(endpoint)
        writer.writerow([])
        
        # Writing Suspicious Activity
        if suspicious_ips:
            writer.writerow(['Suspicious Activity'])
            writer.writerow(['IP Address', 'Failed Login Count'])
            writer.writerows(suspicious_ips)
        else:
            writer.writerow(['No suspicious activity detected.'])
