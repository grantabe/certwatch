import socket, ssl, datetime as dt, csv



hosts_file = 'hosts.txt'
days_to_check = 14

# Convert host text file to a list
def get_hosts(file=hosts_file):
    host_list = []
    with open(hosts_file, 'r') as f:
        for line in f:
            host = line.strip()
            if host:
                host_list.append(host)
    return host_list


hostname = "google.com"
context = ssl.create_default_context()

def fetch(host):
    # Creating a socket connection. Plain TCP connection on port 443
    with socket.create_connection((hostname, 443), timeout=8) as sock:
    # Wrapping the connection in TLS. This is where the certificate is presented
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            expire_date = cert['notAfter']
            # Convert date to epoch format
            expire_epoch = ssl.cert_time_to_seconds(expire_date)
            # Convert to timezone aware datetime object
            expire = dt.datetime.fromtimestamp(expire_epoch, tz=dt.timezone.utc)         
            return expire
        
def status(days_until_expire):
    if days_until_expire > days_to_check:
        return "Good"
    elif days_to_check >= days_until_expire > 0: 
        return "Expiring soon"
    else:
        return "Expired"
    
def check_host(host):
    try:
        expire = fetch(hostname)
        # Create a timezone aware datetime object
        today =  dt.datetime.now(tz=dt.timezone.utc)
        days_until_expire = (expire - today).days
        cert_status = status(days_until_expire)
        print(cert_status)
    except ssl.SSLCertVerificationError as e:
        print(f"Error {e.verify_code}: {e.verify_message}")

check_host(hostname)


