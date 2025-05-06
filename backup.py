add...a...--block-5g...and..--block-2.4g...function..in....main.py...that...blocks...devices..connected.to...either...2.4g..or...5g..except...those...in....whitelist..also..the....white..list.....is...in...a..".env"..file...only...accessible...by...the..script..calling..this...package....When..blocking...first..get...devices...connected..to..either...then..extract..mac..addresses..neatly......then..generate..post..payload....



CSRFValue=64394055&MacAddressFilter01MA0=c2&MacAddressFilter01MA1=97&MacAddressFilter01MA2=93&MacAddressFilter01MA3=4b&MacAddressFilter01MA4=32&MacAddressFilter01MA5=0d&MacAddressFilter02MA0=00&MacAddressFilter02MA1=00&MacAddressFilter02MA2=00&MacAddressFilter02MA3=00&MacAddressFilter02MA4=00&MacAddressFilter02MA5=00&MacAddressFilter03MA0=00&MacAddressFilter03MA1=00&MacAddressFilter03MA2=00&MacAddressFilter03MA3=00&MacAddressFilter03MA4=00&MacAddressFilter03MA5=00&MacAddressFilter04MA0=00&MacAddressFilter04MA1=00&MacAddressFilter04MA2=00&MacAddressFilter04MA3=00&MacAddressFilter04MA4=00&MacAddressFilter04MA5=00&MacAddressFilter05MA0=00&MacAddressFilter05MA1=00&MacAddressFilter05MA2=00&MacAddressFilter05MA3=00&MacAddressFilter05MA4=00&MacAddressFilter05MA5=00&MacAddressFilter06MA0=00&MacAddressFilter06MA1=00&MacAddressFilter06MA2=00&MacAddressFilter06MA3=00&MacAddressFilter06MA4=00&MacAddressFilter06MA5=00&MacAddressFilter07MA0=00&MacAddressFilter07MA1=00&MacAddressFilter07MA2=00&MacAddressFilter07MA3=00&MacAddressFilter07MA4=00&MacAddressFilter07MA5=00&MacAddressFilter08MA0=00&MacAddressFilter08MA1=00&MacAddressFilter08MA2=00&MacAddressFilter08MA3=00&MacAddressFilter08MA4=00&MacAddressFilter08MA5=00&MacAddressFilter09MA0=00&MacAddressFilter09MA1=00&MacAddressFilter09MA2=00&MacAddressFilter09MA3=00&MacAddressFilter09MA4=00&MacAddressFilter09MA5=00&MacAddressFilter10MA0=00&MacAddressFilter10MA1=00&MacAddressFilter10MA2=00&MacAddressFilter10MA3=00&MacAddressFilter10MA4=00&MacAddressFilter10MA5=00&MacAddressFilter11MA0=00&MacAddressFilter11MA1=00&MacAddressFilter11MA2=00&MacAddressFilter11MA3=00&MacAddressFilter11MA4=00&MacAddressFilter11MA5=00&MacAddressFilter12MA0=00&MacAddressFilter12MA1=00&MacAddressFilter12MA2=00&MacAddressFilter12MA3=00&MacAddressFilter12MA4=00&MacAddressFilter12MA5=00&MacAddressFilter13MA0=00&MacAddressFilter13MA1=00&MacAddressFilter13MA2=00&MacAddressFilter13MA3=00&MacAddressFilter13MA4=00&MacAddressFilter13MA5=00&MacAddressFilter14MA0=00&MacAddressFilter14MA1=00&MacAddressFilter14MA2=00&MacAddressFilter14MA3=00&MacAddressFilter14MA4=00&MacAddressFilter14MA5=00&MacAddressFilter15MA0=00&MacAddressFilter15MA1=00&MacAddressFilter15MA2=00&MacAddressFilter15MA3=00&MacAddressFilter15MA4=00&MacAddressFilter15MA5=00&MacAddressFilter16MA0=00&MacAddressFilter16MA1=00&MacAddressFilter16MA2=00&MacAddressFilter16MA3=00&MacAddressFilter16MA4=00&MacAddressFilter16MA5=00&MacAddressFilter17MA0=00&MacAddressFilter17MA1=00&MacAddressFilter17MA2=00&MacAddressFilter17MA3=00&MacAddressFilter17MA4=00&MacAddressFilter17MA5=00&MacAddressFilter18MA0=00&MacAddressFilter18MA1=00&MacAddressFilter18MA2=00&MacAddressFilter18MA3=00&MacAddressFilter18MA4=00&MacAddressFilter18MA5=00&MacAddressFilter19MA0=00&MacAddressFilter19MA1=00&MacAddressFilter19MA2=00&MacAddressFilter19MA3=00&MacAddressFilter19MA4=00&MacAddressFilter19MA5=00&MacAddressFilter20MA0=00&MacAddressFilter20MA1=00&MacAddressFilter20MA2=00&MacAddressFilter20MA3=00&MacAddressFilter20MA4=00&MacAddressFilter20MA5=00


in..the..above..data..example...the...first..mac..address..here..is...c2:97:93:4b:32:0d...the..rest..are...00:00:00:00:00:00...........limit...them..to....20...and...ignore..macaddresses..in..whitelist......if..less.than..20...the..remaining..ones..fill..with...00:00:00:00:00:00............................


functions.py....................
import requests
import re
from bs4 import BeautifulSoup

class TechnicolorRouter:
    def __init__(self, ip: str, username: str, password: str):
        self.base_url = f"http://{ip}"
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.csrf_token = None
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html,application/xhtml+xml",
        })

    def get_csrf_token(self):
        url = f"{self.base_url}/"
        resp = self.session.get(url)
        resp.raise_for_status()
        match = re.search(r'name="CSRFValue"\s+value=(\d+)', resp.text)
        if not match:
            raise Exception("CSRF token not found")
        self.csrf_token = match.group(1)
        return self.csrf_token

    def login(self):
        csrf_token = self.get_csrf_token()
        login_url = f"{self.base_url}/goform/login"
        payload = {
            "CSRFValue": csrf_token,
            "loginUsername": self.username,
            "loginPassword": self.password,
            "logoffUser": "0"
        }
        resp = self.session.post(login_url, data=payload)

        if "There is already 1 user connected" in resp.text:
            print("[*] Forcing login...")
            payload["logoffUser"] = "1"
            resp = self.session.post(login_url, data=payload)

        if "Given username and/or password is/are wrong" in resp.text:
            raise Exception("Wrong credentials.")

        if "Please enter username and password" in resp.text:
            raise Exception("Router rejected login. Possibly rate-limited or expired.")

        print("[+] Logged in successfully.")
        print(f"[DEBUG] CSRF Token: {self.csrf_token}")
        print(f"[DEBUG] Session Cookies: {self.session.cookies.get_dict()}")
        return self.session, csrf_token

    def logout(self):
        if not self.session:
            raise Exception("Session not initialized")
        logout_url = f"{self.base_url}/logout.asp?sessionID={self.csrf_token}"
        self.session.get(logout_url)
        self.session.close()
        print("[+] Logged out.")

    def get_system_info(self):
        url = f"{self.base_url}/RgSwInfo.asp"
        resp = self.session.get(url)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')

        info = {
            "Hardware Version": self._extract_table_data(soup, "Hardware Version"),
            "Software Version": self._extract_table_data(soup, "Software Version"),
            "MAC Address": self._extract_table_data(soup, "Cable Modem MAC Address"),
            "Serial Number": self._extract_table_data(soup, "Cable Modem Serial Number"),
            "System Up Time": self._extract_table_data(soup, "System Up Time"),
            "Network Access": self._extract_network_access(soup)
        }
        return info

    def _extract_table_data(self, soup, label):
        row = soup.find(string=re.compile(label))
        if row:
            td = row.find_parent("tr").find_all("td")[1]
            return td.get_text(strip=True) or "N/A"
        return "N/A"

    def _extract_network_access(self, soup):
        row = soup.find(string=re.compile("Network Access"))
        if row:
            td = row.find_parent("tr").find_all("td")[1]
            script_text = td.find_all_next("script", string=re.compile("i18n"))
            return "Allowed" if script_text else td.get_text(strip=True)
        return "N/A"

    def get_connected_devices_2g(self):
        """
        Fetches and parses connected clients on the 2.4GHz WLAN from wlanAccess.asp.
        Returns a list of dictionaries with device info.
        """
        url = f"{self.base_url}/wlanAccess.asp"
        resp = self.session.get(url)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")
        connected_clients_table = soup.find_all("table")[-1]  # Last table contains clients
        rows = connected_clients_table.find_all("tr")[1:]  # Skip the header row

        devices = []
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 6:
                devices.append({
                    "MAC Address": cols[0].text.strip(),
                    "Age (s)": cols[1].text.strip(),
                    "RSSI (dBm)": cols[2].text.strip(),
                    "Type": cols[3].text.strip(),
                    "IP Address": cols[4].text.strip(),
                    "Host Name": cols[5].text.strip()
                })

        return devices
    def get_connected_devices_5g(self):
        """
        Fetches and parses connected clients on the 5GHz WLAN from wlanAccess.asp?5G.
        Returns a list of dictionaries with device info.
        """
        url = f"{self.base_url}/wlanAccess.asp?5G"
        try:
            resp = self.session.get(url)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching the wlanAccess page for 5GHz: {e}")
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        connected_clients_table = soup.find_all("table")[-1]  # Last table contains clients
        rows = connected_clients_table.find_all("tr")[1:]  # Skip the header row

        devices = []
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 6:
                devices.append({
                    "MAC Address": cols[0].text.strip(),
                    "Age (s)": cols[1].text.strip(),
                    "RSSI (dBm)": cols[2].text.strip(),
                    "Type": cols[3].text.strip(),
                    "IP Address": cols[4].text.strip(),
                    "Host Name": cols[5].text.strip()
                })
            else:
                print(f"[!] Invalid row data: {row}")

        return devices


main.py..........................
import os
import time
import argparse
from dotenv import load_dotenv
from technicolor.functions import TechnicolorRouter

# Load environment variables from .env file
load_dotenv()

def main():
    parser = argparse.ArgumentParser(
        description="📡 Technicolor Router CLI Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 main.py --info
    → Logs into the router, fetches and displays system info, and logs out.
  python3 main.py --connected-2g
    → Fetches and displays connected devices on the 2.4GHz WLAN.
  python3 main.py --connected-5g
    → Fetches and displays connected devices on the 5GHz WLAN.
  python3 main.py --connected-all
    → Fetches and displays all connected devices on both 2.4GHz and 5GHz WLANs.

Environment Variables (.env file):
  ROUTER_IP        Router IP address (e.g. 192.168.0.1)
  ROUTER_USERNAME  Router admin username (optional, may be blank)
  ROUTER_PASSWORD  Router admin password
        """
    )

    parser.add_argument(
        "--info",
        action="store_true",
        help="Fetch and display system information from the router."
    )

    parser.add_argument(
        "--connected-2g",
        action="store_true",
        help="Fetch and display connected devices on the 2.4GHz WLAN."
    )

    parser.add_argument(
        "--connected-5g",
        action="store_true",
        help="Fetch and display connected devices on the 5GHz WLAN."
    )

    parser.add_argument(
        "--connected-all",
        action="store_true",
        help="Fetch and display all connected devices on both 2.4GHz and 5GHz WLANs."
    )

    args = parser.parse_args()

    ip = os.getenv("ROUTER_IP")
    username = os.getenv("ROUTER_USERNAME", "")
    password = os.getenv("ROUTER_PASSWORD")

    if not ip or not password:
        print("\n[!] Missing ROUTER_IP or ROUTER_PASSWORD in .env file.")
        print("[!] Please ensure .env is configured properly.\n")
        exit(1)

    router = TechnicolorRouter(ip, username, password)

    session, token = None, None
    attempts = 0
    max_retries = 3

    while attempts < max_retries:
        try:
            session, token = router.login()
            break
        except Exception as e:
            if "Wrong credentials" in str(e):
                print("\n[!] Wrong credentials. Please check your .env file.\n")
                exit(1)

            print(f"\n[*] Connection error ({attempts + 1}/{max_retries}), retrying...\n")
            attempts += 1
            time.sleep(2)

    if session and token:
        if args.info:
            print("\n[+] System Information:\n")
            info = router.get_system_info()
            for key, value in info.items():
                print(f"  {key}: {value}")
            print()

        if args.connected_2g:
            print("\n[+] Connected Devices on 2.4GHz:\n")
            devices_2g = router.get_connected_devices_2g()
            if devices_2g:
                for device in devices_2g:
                    print(f"  MAC Address: {device['MAC Address']}, IP: {device['IP Address']}, Host: {device['Host Name']}")
            else:
                print("  No devices connected on 2.4GHz.")

        if args.connected_5g:
            print("\n[+] Connected Devices on 5GHz:\n")
            devices_5g = router.get_connected_devices_5g()
            if devices_5g:
                for device in devices_5g:
                    print(f"  MAC Address: {device['MAC Address']}, IP: {device['IP Address']}, Host: {device['Host Name']}")
            else:
                print("  No devices connected on 5GHz.")

        if args.connected_all:
            print("\n[+] All Connected Devices on 2.4GHz and 5GHz:\n")
            devices_2g = router.get_connected_devices_2g()
            devices_5g = router.get_connected_devices_5g()

            all_devices = devices_2g + devices_5g  # Combine both device lists

            if all_devices:
                for device in all_devices:
                    print(f"  MAC Address: {device['MAC Address']}, IP: {device['IP Address']}, Host: {device['Host Name']}")
            else:
                print("  No devices connected on either 2.4GHz or 5GHz.")

        router.logout()

if __name__ == "__main__":
    main()


...............................................................................
move...connected-all..to..functions.py....and....use...this..to..get..all...the...mac..addresses...extract..then..generate..payload....python3 main.py --connected-all
[+] Logged in successfully.
[DEBUG] CSRF Token: 88840998
[DEBUG] Session Cookies: {}

[+] All Connected Devices on 2.4GHz and 5GHz:

  MAC Address: B2:7C:A3:A0:07:9A, IP: 192.168.0.65, Host: TECNO-SPARK-10C
  MAC Address: 52:49:F8:58:1B:30, IP: 192.168.0.59, Host: M-KOPA-M10
  MAC Address: EE:9E:D1:DE:4B:0F, IP: 192.168.0.11, Host:
  MAC Address: A4:F0:5E:B0:87:31, IP: 192.168.0.37, Host: OPPO-Reno-2
  MAC Address: E6:34:25:1C:E0:70, IP: 192.168.0.21, Host: android-6f51e331341b5907
  MAC Address: B2:FE:4F:0A:5B:E1, IP: 192.168.0.54, Host:
  MAC Address: 7C:E9:D3:F4:12:1A, IP: 192.168.0.27, Host: Deseo
  MAC Address: 20:26:81:F6:C8:AA, IP: 192.168.0.32, Host:
  MAC Address: 8E:B9:68:F9:41:E6, IP: 192.168.0.52, Host: realme-Note-50
  MAC Address: 92:83:31:5D:45:38, IP: 192.168.0.84, Host: Galaxy-A03-Core
  MAC Address: 64:80:99:E3:19:8A, IP: 192.168.0.96, Host:
[+] Logged out.
