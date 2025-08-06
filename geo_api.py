import time
from collections import deque
from datetime import datetime, timedelta
import requests

request_times = deque()

REQUEST_LIMIT = 40

def already_45_requests_in_minute():
    current_time = datetime.now()

    while request_times and request_times[0] < current_time - timedelta(minutes=1):
        request_times.popleft()

    if len(request_times) >= REQUEST_LIMIT:
        return True
    return False

def get_geolocation(ip):

    if already_45_requests_in_minute():
        print("API request limit reached. Waiting for a minute...")
        time.sleep(60)

    request_times.append(datetime.now())

    endpoint = f'http://ip-api.com/json/{ip}?fields=country,region,city,timezone,lat,lon'
    response = requests.get(endpoint)
    if response.status_code == 200:
        try:
            data = response.json()
            return data
        except ValueError:
            print(f"Error: Unable to parse JSON for IP: {ip}")
            return None
    else:
        print(f"Error: Unable to retrieve data for IP: {ip}, Status code: {response.status_code}")
        return None