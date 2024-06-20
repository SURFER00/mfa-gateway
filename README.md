# Python MFA Gateway
A lightweight server for multifactor authentication

This project is a simple implementation of a Multi-Factor Authentication (MFA) gateway. The MFA gateway sends push notifications for login requests and provides a mechanism for users to confirm their login.

It is recommended to have a working reverse-proxy with https support.

## Features

- Push notification system for user confirmation. (Using your own push notification provider)
- Brute force protection to prevent repeated failed attempts.
- Support for trusting reverse proxy headers (e.g., `X-Forwarded-For`).
- Customizable notification templates based on the username.


## Examples

### SSH multi-factor authentication
I included a shell script that can be hooked into pam authentication to secure ssh with push based multi-factor authentication

Save the script from `examples/request-mfa.sh` to `/bin/request-mfa` and configure the values.
Make sure to set secure file permissions for the file to make sure the script can't be used for privilege escalation of some sort:
```
chown root:root /bin/request-mfa&&chmod 555 /bin/request-mfa
```

And finally just add this line to the bottom of `/etc/pam.d/sshd`:
```
session   required   pam_exec.so /bin/request-mfa
```

Now as soon as you try to login using ssh, you get a notification using your notification provider to approve the login

## Installation

### Manual installation

```
git clone https://github.com/Surferr0815/mfa-gateway.git mfa-gateway
pip install -r mfa-gateway/requirements.txt
```

Run the server (a config.json must be present in the current working directory):
```
cd mfa-gateway&&python ./server.py
```


### Docker


```
git clone https://github.com/Surferr0815/mfa-gateway.git mfa-gateway
cp config.sample.json config.json
docker compose up -d
```

## Configuration

```
"trusted_servers": {
  // The key values need to be set to the hostnames of the servers that can request mfa
  "ssh_server_1": "your_api_token_1",
  "ssh_server_2": "your_api_token_2"
},
// Enter the network ranges in which you want to bypass authentication, for example ["192.168.1.0/24", "10.0.0.0/8"]
"trusted_ip_networks": [],
// Enter the ip addresses of your reverse proxies, for example ["10.1.1.10", "10.1.1.11"]
"trusted_reverse_proxies": [],
// Security settings
"max_failed_attempts": 3,
"block_duration": 60,
"auth_timeout": 30
```
```
"Server": {
  "listen_addr": "0.0.0.0", // Normally you can leave this unchanged
  "listen_port": 5000,
  "host_addr": "https://mfa.example.org" // Set this to your public facing reverse proxy address
},
```

```
// Define your notification templates for your users
"user_settings": {
  "default": {
    "notification_message": "SSH login request from {server_name} ({client_ip})",
    "push_link": "https://your-push-provider/sendNotification?message={notification_message}"
  },
  "user1": {
    "notification_message": "Hello {username}! You have a login request from {server_name} ({client_ip})",
    "push_link": "https://your-push-provider/sendNotification?message={notification_message}"
  }
}
```
