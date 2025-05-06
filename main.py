import os
import time
import argparse
from dotenv import load_dotenv
from technicolor.functions import TechnicolorRouter

# Load environment variables from .env file
load_dotenv()

"""
Extended functionality for Technicolor Router CLI Tool to block devices
on 2.4GHz and 5GHz networks except those in a whitelist.
"""

# First, let's add the MAC filtering function to functions.py
# -------------------------------------------------------------

# Add these functions to the TechnicolorRouter class in functions.py:

def get_connected_devices_all(self):
    """
    Fetches and returns all connected devices on both 2.4GHz and 5GHz WLANs.
    Returns a list of dictionaries with device info.
    """
    devices_2g = self.get_connected_devices_2g()
    devices_5g = self.get_connected_devices_5g()
    return devices_2g + devices_5g

def set_mac_filter(self, mac_addresses, whitelist=None):
    """
    Sets the MAC filter for the router.

    Args:
        mac_addresses: List of MAC addresses to add to the filter
        whitelist: List of MAC addresses to exclude from filtering

    Returns:
        Success status (boolean)
    """
    if whitelist is None:
        whitelist = []

    # Convert whitelist MACs to uppercase for consistent comparison
    whitelist = [mac.upper() for mac in whitelist]

    # Filter out whitelisted MACs
    filtered_macs = [mac for mac in mac_addresses if mac.upper() not in whitelist]

    # Ensure we have at most 20 MACs to filter
    filtered_macs = filtered_macs[:20]

    # Get CSRF token for the POST request
    url = f"{self.base_url}/RgMacFiltering.asp"
    resp = self.session.get(url)
    resp.raise_for_status()

    match = re.search(r'name="CSRFValue"\s+value=(\d+)', resp.text)
    if not match:
        print("[!] Could not find CSRF token for MAC filtering")
        return False

    csrf_token = match.group(1)

    # Prepare the payload
    payload = {
        "CSRFValue": csrf_token
    }

    # Format MAC addresses for the form (split each octet)
    for i in range(20):
        if i < len(filtered_macs):
            mac = filtered_macs[i].replace(':', '').replace('-', '')
            mac = mac.upper()  # Ensure uppercase

            # Add each octet to the payload
            for j in range(6):
                idx = str(i + 1).zfill(2)  # Pad with leading zero if needed
                field = f"MacAddressFilter{idx}MA{j}"
                payload[field] = mac[j*2:j*2+2] if j*2+2 <= len(mac) else "00"
        else:
            # Fill remaining slots with zeros
            for j in range(6):
                idx = str(i + 1).zfill(2)
                field = f"MacAddressFilter{idx}MA{j}"
                payload[field] = "00"

    # POST the payload to update MAC filtering
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


# Now, let's update the main.py file
# ----------------------------------

# Add these imports to main.py:
# import os
# import time
# import argparse
# from dotenv import load_dotenv
# from technicolor.functions import TechnicolorRouter

# Update the main function to include the new arguments and functionality:

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
  python3 main.py --block-24g
    → Blocks all devices on 2.4GHz except those in whitelist.
  python3 main.py --block-5g
    → Blocks all devices on 5GHz except those in whitelist.
  python3 main.py --unblock-all
    → Removes all MAC filters (unblocks all devices).

Environment Variables (.env file):
  ROUTER_IP        Router IP address (e.g. 192.168.0.1)
  ROUTER_USERNAME  Router admin username (optional, may be blank)
  ROUTER_PASSWORD  Router admin password
  WHITELIST_MACS   Comma-separated list of MAC addresses to whitelist
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

    parser.add_argument(
        "--block-24g",
        action="store_true",
        help="Block all devices on 2.4GHz except those in whitelist."
    )

    parser.add_argument(
        "--block-5g",
        action="store_true",
        help="Block all devices on 5GHz except those in whitelist."
    )

    parser.add_argument(
        "--unblock-all",
        action="store_true",
        help="Remove all MAC filters (unblock all devices)."
    )

    args = parser.parse_args()

    ip = os.getenv("ROUTER_IP")
    username = os.getenv("ROUTER_USERNAME", "")
    password = os.getenv("ROUTER_PASSWORD")
    whitelist = os.getenv("WHITELIST_MACS", "").split(",")
    whitelist = [mac.strip() for mac in whitelist if mac.strip()]

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
            all_devices = router.get_connected_devices_all()

            if all_devices:
                for device in all_devices:
                    print(f"  MAC Address: {device['MAC Address']}, IP: {device['IP Address']}, Host: {device['Host Name']}")
            else:
                print("  No devices connected on either 2.4GHz or 5GHz.")

        if args.block_24g:
            print("\n[+] Blocking devices on 2.4GHz (except whitelist):\n")
            # Get devices on 2.4GHz
            devices_2g = router.get_connected_devices_2g()

            if devices_2g:
                # Extract MAC addresses
                mac_addresses = [device['MAC Address'] for device in devices_2g]

                print(f"  Found {len(mac_addresses)} devices on 2.4GHz network")
                print(f"  Whitelist contains {len(whitelist)} MAC addresses")

                for mac in mac_addresses:
                    in_whitelist = mac.upper() in [w.upper() for w in whitelist]
                    status = "WHITELISTED" if in_whitelist else "WILL BLOCK"
                    print(f"  MAC: {mac} - {status}")

                # Set MAC filtering
                success = router.set_mac_filter(mac_addresses, whitelist)
                if success:
                    print("\n[+] Successfully applied MAC filtering for 2.4GHz devices")
                else:
                    print("\n[!] Failed to apply MAC filtering")
            else:
                print("  No devices connected on 2.4GHz.")

        if args.block_5g:
            print("\n[+] Blocking devices on 5GHz (except whitelist):\n")
            # Get devices on 5GHz
            devices_5g = router.get_connected_devices_5g()

            if devices_5g:
                # Extract MAC addresses
                mac_addresses = [device['MAC Address'] for device in devices_5g]

                print(f"  Found {len(mac_addresses)} devices on 5GHz network")
                print(f"  Whitelist contains {len(whitelist)} MAC addresses")

                for mac in mac_addresses:
                    in_whitelist = mac.upper() in [w.upper() for w in whitelist]
                    status = "WHITELISTED" if in_whitelist else "WILL BLOCK"
                    print(f"  MAC: {mac} - {status}")

                # Set MAC filtering
                success = router.set_mac_filter(mac_addresses, whitelist)
                if success:
                    print("\n[+] Successfully applied MAC filtering for 5GHz devices")
                else:
                    print("\n[!] Failed to apply MAC filtering")
            else:
                print("  No devices connected on 5GHz.")

        if args.unblock_all:
            print("\n[+] Removing all MAC filters (unblocking all devices):\n")
            success = router.clear_mac_filters()
            if success:
                print("\n[+] Successfully removed all MAC filters")
            else:
                print("\n[!] Failed to remove MAC filters")

        router.logout()

if __name__ == "__main__":
    main()
