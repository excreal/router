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
        url = f"{self.base_url}/wlanAccess.asp"
        resp = self.session.get(url)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")
        connected_clients_table = soup.find_all("table")[-1]
        rows = connected_clients_table.find_all("tr")[1:]

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
        url = f"{self.base_url}/wlanAccess.asp?5G"
        try:
            resp = self.session.get(url)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching the wlanAccess page for 5GHz: {e}")
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        connected_clients_table = soup.find_all("table")[-1]
        rows = connected_clients_table.find_all("tr")[1:]

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

    def set_mac_filter(self, mac_addresses, whitelist=None):
        if whitelist is None:
            whitelist = []

        whitelist = [mac.upper() for mac in whitelist]
        filtered_macs = [mac for mac in mac_addresses if mac.upper() not in whitelist]
        filtered_macs = filtered_macs[:20]

        url = f"{self.base_url}/RgMacFiltering.asp"
        resp = self.session.get(url)
        resp.raise_for_status()

        match = re.search(r'name="CSRFValue"\s+value=(\d+)', resp.text)
        if not match:
            print("[!] Could not find CSRF token for MAC filtering")
            return False

        csrf_token = match.group(1)
        payload = {"CSRFValue": csrf_token}

        for i in range(20):
            if i < len(filtered_macs):
                mac = filtered_macs[i].replace(':', '').replace('-', '').upper()
                for j in range(6):
                    idx = str(i + 1).zfill(2)
                    field = f"MacAddressFilter{idx}MA{j}"
                    payload[field] = mac[j * 2:j * 2 + 2] if j * 2 + 2 <= len(mac) else "00"
            else:
                for j in range(6):
                    idx = str(i + 1).zfill(2)
                    field = f"MacAddressFilter{idx}MA{j}"
                    payload[field] = "00"

        post_url = f"{self.base_url}/goform/RgMacFiltering"
        try:
            resp = self.session.post(post_url, data=payload)
            if resp.status_code == 200:
                print(f"[+] MAC filtering updated successfully with {len(filtered_macs)} devices")
                return True
            else:
                print(f"[!] Failed to update MAC filtering. Status code: {resp.status_code}")
                return False
        except Exception as e:
            print(f"[!] Exception while setting MAC filters: {e}")
            return False

    def get_connected_devices_all(self):
        devices_2g = self.get_connected_devices_2g()
        devices_5g = self.get_connected_devices_5g()
        return devices_2g + devices_5g

    def clear_mac_filters(self):
        url = f"{self.base_url}/RgMacFiltering.asp"
        resp = self.session.get(url)
        resp.raise_for_status()

        match = re.search(r'name="CSRFValue"\s+value=(\d+)', resp.text)
        if not match:
            print("[!] Could not find CSRF token for MAC filtering")
            return False

        csrf_token = match.group(1)
        payload = {"CSRFValue": csrf_token}

        for i in range(20):
            idx = str(i + 1).zfill(2)
            for j in range(6):
                field = f"MacAddressFilter{idx}MA{j}"
                payload[field] = "00"

        post_url = f"{self.base_url}/goform/RgMacFiltering"
        try:
            resp = self.session.post(post_url, data=payload)
            if resp.status_code == 200:
                print(f"[+] All MAC filters cleared successfully")
                return True
            else:
                print(f"[!] Failed to clear MAC filters. Status code: {resp.status_code}")
                return False
        except Exception as e:
            print(f"[!] Exception while clearing MAC filters: {e}")
            return False
