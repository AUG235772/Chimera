import requests
import sys

def get_latest_url():
    try:
        # Get the latest release data from GitHub API
        url = "https://api.github.com/repos/zaproxy/zaproxy/releases/latest"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        # Find the Linux tar.gz asset
        for asset in data.get('assets', []):
            if "Linux.tar.gz" in asset['name']:
                return asset['browser_download_url']
        
        # Fallback to 2.14.0 if latest logic fails (Safety Net)
        return "https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz"
        
    except Exception as e:
        print(f"Error finding ZAP URL: {e}")
        # Fallback to known stable version
        return "https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz"

if __name__ == "__main__":
    print(get_latest_url())