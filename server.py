from flask import Flask, request, jsonify
from waitress import serve
import ipaddress, json, logging, requests, secrets, time

app = Flask(__name__)

# Dummy database to store authentication requests
auth_requests = {}

# Dummy database to store failed authentication attempts
failed_attempts = {}

# Default configuration values
TRUSTED_REVERSE_PROXIES = []
TRUSTED_SERVERS = []
TRUSTED_IP_NETWORKS = []
LISTEN_ADDR = '127.0.0.1'
LISTEN_PORT = 5000
HOST_ADRR = "https://mfa.example.org"

# Brute force protection settings
MAX_FAILED_ATTEMPTS = 3
BLOCK_DURATION = 60  # seconds

# Authentication settings
AUTH_TIMEOUT = 60  # seconds

# Notification Templates
USER_SETTINGS = {'user_settings': {'default': {'notification_text': 'Default notification text', 'notification_link': 'Default notification link'}}}

# Load configuration from config.json with fallback to default values
try:
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)

    TRUSTED_REVERSE_PROXIES = config.get('Authentication', {}).get('trusted_reverse_proxies', TRUSTED_REVERSE_PROXIES)
    TRUSTED_SERVERS = config.get('Authentication', {}).get('trusted_servers', TRUSTED_SERVERS)
    TRUSTED_IP_NETWORKS = config.get('Authentication', {}).get('trusted_ip_networks', TRUSTED_IP_NETWORKS)
    LISTEN_ADDR = config.get('Server', {}).get('listen_addr', LISTEN_ADDR)
    LISTEN_PORT = config.get('Server', {}).get('listen_port', LISTEN_PORT)
    HOST_ADRR = config.get('Server', {}).get('host_addr', HOST_ADRR)
    MAX_FAILED_ATTEMPTS = config.get('Authentication', {}).get('max_failed_attempts', MAX_FAILED_ATTEMPTS)
    BLOCK_DURATION = config.get('Authentication', {}).get('block_duration', BLOCK_DURATION)
    AUTH_TIMEOUT = config.get('Authentication', {}).get('auth_timeout', AUTH_TIMEOUT)
    USER_SETTINGS = config.get('user_settings', USER_SETTINGS)
except:
    pass


### AUTHENTICATION

def is_authentication_confirmed(token):
    # Check if the authentication request associated with the token was confirmed
    return token in auth_requests and auth_requests[token].get('confirmed', True)

def verify_api_token(ssh_server, api_token):
    # Verify if the provided API token matches the stored token for the server
    return TRUSTED_SERVERS.get(ssh_server) == api_token

def should_bypass_mfa(username, client_ip):
    # Check if the client IP is in a trusted network to bypass MFA
    for network in TRUSTED_IP_NETWORKS:
        if ipaddress.ip_address(client_ip) in ipaddress.ip_network(network, strict=False):
            return True
    return False

def get_client_ip(request):
    if request.remote_addr in TRUSTED_REVERSE_PROXIES:
        return request.headers.get('X-Forwarded-For', request.remote_addr)
    return request.remote_addr


### BRUTEFORCE PROTECTION

def block_ip(ip):
    # Add the blocked IP to the failed_attempts dictionary with a timestamp
    failed_attempts[ip] = time.time() + BLOCK_DURATION

def is_ip_blocked(ip):
    # Check if the IP is currently blocked due to repeated failed attempts
    return ip in failed_attempts and failed_attempts[ip] > time.time()

def record_failed_attempt(ip):
    # Record a failed authentication attempt for an IP
    if ip not in failed_attempts:
        failed_attempts[ip] = 1
    else:
        failed_attempts[ip] += 1


### USER HANDLING
        
def send_notification(user_id, message, push_link):
    # Sending a push notification
    try:
        # Send the POST request
        response = requests.get(push_link)
        # Check the response status code
        if response.status_code == 200:
            print(response.content)
            print(f"Notification sent successfully to user {user_id}")
        else:
            print(f"Failed to send notification. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {e}")

def get_notification_templates(username):
    # Return the notification templates based on the username
    return USER_SETTINGS.get(username, USER_SETTINGS.get('default'))


### WEBSERVER

@app.route('/request_mfa', methods=['GET'])
def request_mfa():
    remote_addr = str(get_client_ip(request))
    print(remote_addr)

    # Check if the IP is blocked
    if is_ip_blocked(remote_addr):
        block_ip(remote_addr)
        return jsonify({'status': 'IP blocked due to repeated failed attempts. Please try again later.'}), 403
    
    user_id = request.args.get('user_id')
    api_token = request.args.get('api_token')
    client_ip = request.args.get('client_ip')
    server_name = request.args.get('server_name')


    # Verify if the requesting server is trusted
    if not verify_api_token(server_name, api_token):
        record_failed_attempt(remote_addr)
        if failed_attempts[remote_addr] >= MAX_FAILED_ATTEMPTS:
            block_ip(remote_addr)
        return jsonify({'status': 'Unauthorized - Invalid API token'}), 401

    # Generate a unique token for this request
    token = secrets.token_hex(32)

    # Store the authentication request
    auth_requests[token] = {'user_id': user_id, 'server_name': server_name, 'client_ip': client_ip, 'confirmed': False}

    # Check if MFA bypass is allowed based on the client IP
    if should_bypass_mfa(user_id, client_ip):
        auth_requests[token]['confirmed'] = True
        return jsonify({'status': 'MFA bypassed due to trusted IP'}), 200
    
    # Format the notification text and link based on the templates
    templates = get_notification_templates(user_id)
    notification_message = templates['notification_message'].format(username=user_id, server_name=server_name, client_ip=client_ip)
    notification_link = f"{HOST_ADRR}/confirm_mfa?token={token}"
    push_link = templates['push_link'].format(notification_message=notification_message, notification_link=notification_link)
    # Send a push notification
    print(f"Link: {push_link}")
    send_notification(user_id, notification_message, push_link)

    return jsonify({'token': token, 'status': 'Notification sent'}), 200

@app.route('/confirm_mfa', methods=['GET'])
def confirm_mfa():
    remote_addr = str(get_client_ip(request))
    # Check if the IP is blocked
    if is_ip_blocked(remote_addr):
        block_ip(remote_addr)
        return jsonify({'status': 'IP blocked due to repeated failed attempts. Please try again later.'}), 403
    token = request.args.get('token')
    # Confirm token
    if token in auth_requests:
        auth_requests[token]['confirmed'] = True
        return jsonify({'status': 'Authentication confirmed'}), 200
    # If auth token is invalid, count as auth fail to prevent auth token bruteforcing
    record_failed_attempt(remote_addr)
    if failed_attempts[remote_addr] >= MAX_FAILED_ATTEMPTS:
        block_ip(remote_addr)
    return jsonify({'status': 'Invalid token'}), 401

@app.route('/check_mfa_authentication', methods=['GET'])
def check_mfa_authentication():
    remote_addr = str(get_client_ip(request))
    # Check if the IP is blocked
    if is_ip_blocked(remote_addr):
        block_ip(remote_addr)
        return jsonify({'status': 'IP blocked due to repeated failed attempts. Please try again later.'}), 403

    api_token = request.args.get('api_token')
    server_name = request.args.get('server_name')

    # Verify if the requesting server is trusted
    if not verify_api_token(server_name, api_token):
        record_failed_attempt(remote_addr)
        if failed_attempts[remote_addr] >= MAX_FAILED_ATTEMPTS:
            block_ip(remote_addr)
        return jsonify({'status': 'Unauthorized - Invalid API token'}), 401
    token = request.args.get('token')

    if token in auth_requests:
        confirmation_timeout = time.time() + AUTH_TIMEOUT
        # Wait for the auth token to be confirmed, until timeout is reached
        while True:
            time.sleep(0.25) # Save cpu
            if time.time() > confirmation_timeout: break
            if is_authentication_confirmed(token):
                del auth_requests[token]  # Remove the used token so its single use only
                return jsonify({'status': 'Authentication confirmed'}), 200
        del auth_requests[token]  # Remove the used token so its single use only
        return jsonify({'status': 'Authentication not confirmed'}), 401
    # Since the requesting server is already authenticated and trusted, no bruteforce protection is required here :)
    return jsonify({'status': 'Invalid token'})


if __name__ == '__main__':
    # For debugging purposes
    # app.run(debug=True, host=LISTEN_ADDR, port=LISTEN_PORT)
    # For debugging, comment out the code below

    # Set waitress log level
    logger = logging.getLogger('waitress')
    logger.setLevel(logging.INFO)

    serve(app=app, host=LISTEN_ADDR, port=LISTEN_PORT)