import re
import csv
from collections import defaultdict

# Configurable threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(log_file):
    """
    Parses the log file and extracts relevant details.
    Returns a dictionary with:
        - 'ip_counts': Requests count per IP
        - 'endpoint_counts': Requests count per endpoint
        - 'failed_logins': Failed login attempts by IP
    """
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regular expressions to extract IP, endpoint, and HTTP status code
    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) .* "(?P<method>[A-Z]+) (?P<endpoint>/\S*) HTTP/\d\.\d" (?P<status>\d{3})')
    
    with open(log_file, 'r') as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = match.group('status')
                
                # Update counts
                ip_counts[ip] += 1
                endpoint_counts[endpoint] += 1
                
                # Check for failed logins (status code 401)
                if status == '401':
                    failed_logins[ip] += 1

    return {
        'ip_counts': ip_counts,
        'endpoint_counts': endpoint_counts,
        'failed_logins': failed_logins
    }

def analyze_logs(log_data):
    """
    Analyzes parsed log data and prepares the results.
    Returns a dictionary with:
        - 'ip_requests': Sorted IP request counts
        - 'most_accessed_endpoint': Most accessed endpoint details
        - 'suspicious_activity': Suspicious activity details
    """
    # Sort IP requests in descending order
    ip_requests = sorted(log_data['ip_counts'].items(), key=lambda x: x[1], reverse=True)
    
    # Find the most accessed endpoint
    most_accessed_endpoint = max(log_data['endpoint_counts'].items(), key=lambda x: x[1])
    
    # Detect suspicious activity
    suspicious_activity = [(ip, count) for ip, count in log_data['failed_logins'].items() if count > FAILED_LOGIN_THRESHOLD]
    
    return {
        'ip_requests': ip_requests,
        'most_accessed_endpoint': most_accessed_endpoint,
        'suspicious_activity': suspicious_activity
    }

def save_to_csv(results, output_file):
    """
    Saves analysis results to a CSV file.
    """
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(results['ip_requests'])
        writer.writerow([])

        # Write most accessed endpoint
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(results['most_accessed_endpoint'])
        writer.writerow([])

        # Write suspicious activity
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        writer.writerows(results['suspicious_activity'])

def main():
    log_file = 'sample.log'
    output_file = 'log_analysis_results.csv'

    # Step 1: Parse log file
    log_data = parse_log_file(log_file)

    # Step 2: Analyze logs
    results = analyze_logs(log_data)

    # Step 3: Display results
    print("IP Address           Request Count")
    for ip, count in results['ip_requests']:
        print(f"{ip:20} {count}")
    print()

    print(f"Most Frequently Accessed Endpoint:")
    print(f"{results['most_accessed_endpoint'][0]} (Accessed {results['most_accessed_endpoint'][1]} times)")
    print()

    print("Suspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in results['suspicious_activity']:
        print(f"{ip:20} {count}")
    print()

    # Step 4: Save to CSV
    save_to_csv(results, output_file)
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
