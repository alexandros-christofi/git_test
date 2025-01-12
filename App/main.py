import requests

API_KEY = ''

# Replace with the IP address you want to query
IP_ADDRESS = "8.8.8.8"

# VirusTotal API URL for IP lookups
url = f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}"

# Set up headers
headers = {
    "x-apikey": API_KEY
}

# Send GET request to VirusTotal
response = requests.get(url, headers=headers)

# Check if the request was successful
if response.status_code == 200:
    data = response.json()

        # Extract reputation and location
    attributes = data.get("data", {}).get("attributes", {})
    reputation = attributes.get("reputation", "Unknown")
    location = attributes.get("as_owner", "Unknown")
    
    # Print the details
    print(f"Details for IP {IP_ADDRESS}:")
    print(f"Reputation: {reputation}")
    print(f"Location: {location}")

else:
    print(f"Error: {response.status_code} - {response.text}")



