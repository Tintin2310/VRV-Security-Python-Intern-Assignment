import re
import csv
from collections import Counter

def parse_log_file(log_file):
    """
    Parses the log file to extract and analyze key data.
    - Counts requests per IP address.
    - Counts requests for each endpoint.
    - Identifies failed login attempts.

    Args:
        log_file (str): Path to the log file.

    Returns:
        tuple: Contains three dictionaries:
            - ip_requests (Counter): Counts of requests per IP address.
            - endpoint_requests (Counter): Counts of requests per endpoint.
            - failed_logins (Counter): Failed login attempts per IP address.
    """
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = Counter()

    with open(log_file, "r") as file:
        for line in file:
            # Extract IP address (first element in the line)
            ip = line.split()[0]
            ip_requests[ip] += 1

            # Extract endpoint (inside the quoted request string)
            try:
                endpoint = line.split('"')[1].split()[1]
                endpoint_requests[endpoint] += 1
            except IndexError:
                continue

            # Detect failed login attempts (based on status code 401 or specific message)
            if "401" in line or "Invalid credentials" in line:
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def count_requests_per_ip(ip_requests):
    """
    Displays the count of requests per IP address, sorted in descending order.

    Args:
        ip_requests (Counter): Counts of requests per IP address.
    """
    print("\nIP Address           Request Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")

def most_frequent_endpoint(endpoint_requests):
    """
    Displays the most frequently accessed endpoint.

    Args:
        endpoint_requests (Counter): Counts of requests per endpoint.
    """
    if endpoint_requests:
        endpoint, count = endpoint_requests.most_common(1)[0]
        print(f"\nMost Frequently Accessed Endpoint:\n{endpoint} (Accessed {count} times)\n")
    else:
        print("No endpoints found.")

def detect_suspicious_activity(failed_logins, threshold=10):
    """
    Detects suspicious activity by identifying IPs with more than a given threshold of failed login attempts.

    Args:
        failed_logins (Counter): Failed login attempts per IP address.
        threshold (int): The threshold above which IP addresses are flagged as suspicious.
    """
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

def save_results_to_csv(ip_requests, endpoint_requests, failed_logins, filename="log_analysis_results.csv", threshold=10):
    """
    Save the results to a CSV file with the structure specified.
    
    Args:
        ip_requests (Counter): Counts of requests per IP address.
        endpoint_requests (Counter): Counts of requests per endpoint.
        failed_logins (Counter): Failed login attempts per IP address.
        filename (str): Path to the CSV file.
        threshold (int): The threshold above which IP addresses are flagged as suspicious.
    """
    # Open the CSV file for writing
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        # Write the headers
        writer.writerow(['Section', 'IP Address/Endpoint', 'Count'])
        
        # Write IP request counts
        writer.writerow(['Requests per IP', '', ''])
        for ip, count in ip_requests.items():
            writer.writerow(['', ip, count])

        # Write most accessed endpoint
        writer.writerow(['Most Accessed Endpoint', '', ''])
        if endpoint_requests:
            endpoint, count = endpoint_requests.most_common(1)[0]
            writer.writerow(['', endpoint, count])
        
        # Write suspicious activity
        writer.writerow(['Suspicious Activity', '', ''])
        for ip, count in failed_logins.items():
            if count > threshold:
                writer.writerow([ip, 'Failed Login Attempts', count])

def main():
    log_file = "sample.log"  # Path to your log file

    # Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file)

    # Count requests per IP address
    count_requests_per_ip(ip_requests)

    # Identify the most frequently accessed endpoint
    most_frequent_endpoint(endpoint_requests)

    # Detect suspicious activity based on failed login attempts
    detect_suspicious_activity(failed_logins, threshold=3)  # Example threshold of 3 failed attempts

    # Save the results to a CSV file
    save_results_to_csv(ip_requests, endpoint_requests, failed_logins, filename="log_analysis_results.csv", threshold=3)

if __name__ == "__main__":
    main()
