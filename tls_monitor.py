import socket, ssl, datetime as dt, csv

hosts_file = 'hosts.txt'
days_to_check = 14

# Convert host text file to a list
def get_hosts(file):
    host_list = []
    with open(file, 'r') as f:
        for line in f:
            host = line.strip()
            if host:
                host_list.append(host)
    return host_list

# Returns cert fields that must be recursively parsed
def get_fields(cert_field, field_name):
    for name in cert_field:
        for (field_holder, field_value) in name:
            if field_holder == field_name:
                return field_value
    return "N/A"

# Makes the connection towards the host and returns the necessary cert information
def get_cert_info(host, context, timeout:int=8):
    # Creating a socket connection. Plain TCP connection on port 443
    with socket.create_connection((host, 443), timeout=timeout) as sock:
    # Wrapping the connection in TLS. This is where the certificate is presented
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            expire_date = cert['notAfter']
            # Convert date to epoch format
            expire_epoch = ssl.cert_time_to_seconds(expire_date)
            # Convert to timezone aware datetime object
            expire = dt.datetime.fromtimestamp(expire_epoch, tz=dt.timezone.utc)  
            # Grab the rest of the cert info
            issuer = get_fields(cert['issuer'], 'organizationName')
            subject = get_fields(cert['subject'], 'commonName')  
            serial_number = cert['serialNumber']
            cert_info = {
                'expire': expire,
                'expire_date': expire_date,
                'subject': subject,
                'issuer': issuer,
                'serial_number': serial_number
            }
            return cert_info

# Logic to check if the certificate is expiring soon
def check_status(days_until_expire):
    if days_until_expire > days_to_check:
        return "Good"
    elif days_until_expire >= 0: 
        return "Expiring soon"
    else:
        return "Expired"

# Puts the cert data in dict format one by one and catches any errors
def check_host(host):
    context = ssl.create_default_context()
    try:
        cert_info = get_cert_info(host, context, 8)
        expire_date = cert_info['expire_date']
        expire = cert_info['expire']
        issuer = cert_info['issuer']
        subject = cert_info['subject']
        serial_number = cert_info['serial_number']
        # Create a timezone aware datetime object
        today =  dt.datetime.now(tz=dt.timezone.utc)
        days_until_expire = (expire - today).days
        cert_status = check_status(days_until_expire)
        return {
            'host': host,
            'status': cert_status,
            'days_left': days_until_expire,
            'expiry': expire_date,
            'issuer': issuer,
            'subject': subject,
            'serial': serial_number
        }
    except ssl.SSLCertVerificationError as e:
        if e.verify_code == 10: 
            return {
                'host': host,
                'status': "Expired",
                'days_left': "0",
                'expiry': "Expired",
                'issuer': "Expired",
                'subject': "Expired",
                'serial': "Expired"
            }
        else:
            return {
                'host': host,
                'status': e.verify_message,
                'days_left': "Error",
                'expiry': "Error",
                'issuer': "Error",
                'subject': "Error",
                'serial': "Error"
            }
    except (TimeoutError, socket.gaierror, ConnectionRefusedError) as e:
        return {
            'host': host,
            'status': {e},
            'days_left': "Error",
            'expiry': "Error",
            'issuer': "Error",
            'subject': "Error",
            'serial': "Error"
        }


