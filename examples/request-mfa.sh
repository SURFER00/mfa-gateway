#!/bin/bash

check_mfa() {
  # Set the necessary parameters
  SERVER="https://mfa.example.org"
  API_TOKEN="your_api_token_1"
  USER_ID="$PAM_USER"
  CLIENT_IP="$PAM_RHOST"
  SERVER_NAME="$HOSTNAME"

  # Make a request to request_mfa endpoint
  response=$(curl -s "$SERVER/request_mfa?user_id=$USER_ID&api_token=$API_TOKEN&client_ip=$CLIENT_IP&server_name=$SERVER_NAME")

  # Extract the token from the response
  token=$(echo "$response" | grep -o '"token": "[^"]*' | cut -d'"' -f4)


  if [ -z "$token" ]; then
    echo "Failed to get authentication token. Exiting."
    exit 1
  fi

  echo "Waiting for login approval..."

  # Check the status using check_mfa_authentication endpoint
  while true; do
    check_response=$(curl -s "$SERVER/check_mfa_authentication?server_name=$SERVER_NAME&api_token=$API_TOKEN&token=$token")

    status=$(echo "$check_response" | grep -o '"status": "[^"]*' | cut -d'"' -f4)

    if [ "$status" == "Authentication confirmed" ]; then
      echo "Authentication successful."
      exit 0
    elif [ "$status" == "" ]; then
      echo "Authentication timed out. Exiting."
      exit 1
    else
      echo "Authentication timed out. Exiting."
      exit 1
    fi
  done
}

case "$PAM_TYPE" in
  open_session)
    check_mfa  
    ;;
  close_session)
    ;;
esac
exit 0