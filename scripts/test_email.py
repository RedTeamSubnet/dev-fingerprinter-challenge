# -*- coding: utf-8 -*-
import sys
import os
import argparse
import random
import json
import getpass
from collections import defaultdict
from pydantic import SecretStr

# Add src to python path to allow imports from api
sys.path.append(os.path.join(os.getcwd(), "src"))

# Set default configs dir for local testing if not set
if "DFP_API_PATHS_CONFIGS_DIR" not in os.environ:
    os.environ["DFP_API_PATHS_CONFIGS_DIR"] = os.path.join(os.getcwd(), "templates/configs")

try:
    from api.config import config
    from api.helpers.email import EmailHelper
    from api.endpoints.challenge.dfp import DFPManager
    from api.core.configs.challenge import DeviceConfig
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you are running this script from the project root directory.")
    sys.exit(1)

def mask_email(email: str) -> str:
    """Mask email address for privacy in logs."""
    if not email or "@" not in email:
        return email
    try:
        user, domain = email.split("@")
        if len(user) > 2:
            user = f"{user[:1]}***{user[-1:]}"
        else:
            user = "***"
        return f"{user}@{domain}"
    except Exception:
        return "***@***"

def load_devices_from_file(file_path):
    print(f"Loading devices from {file_path}...")
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        
        devices = []
        for item in data:
            # Parse into DeviceConfig (which inherits from DevicePM)
            devices.append(DeviceConfig(**item))
        return devices
    except Exception as e:
        print(f"Error loading devices from file: {e}")
        return []

def test_email_batch(devices=None, override_email=None, sender_email=None, smtp_user=None, smtp_password=None, smtp_host=None, smtp_port=None):
    _smtp_host = smtp_host if smtp_host else config.challenge.smtp_host
    _smtp_port = smtp_port if smtp_port else config.challenge.smtp_port
    _smtp_user = smtp_user if smtp_user else config.challenge.smtp_user
    
    # Secure password handling
    if smtp_password:
        _smtp_password = SecretStr(smtp_password)
    elif config.challenge.smtp_password and config.challenge.smtp_password.get_secret_value():
        _smtp_password = config.challenge.smtp_password
    else:
        # Prompt user if no password found in args or config
        pwd_input = getpass.getpass("Enter SMTP Password: ")
        _smtp_password = SecretStr(pwd_input)

    _sender_email = sender_email if sender_email else config.challenge.email_sender

    print(f"Initializing EmailHelper with host: {_smtp_host} (User: {_smtp_user}, Sender: {mask_email(_sender_email)})...")
    
    try:
        helper = EmailHelper(
            smtp_host=_smtp_host,
            smtp_port=_smtp_port,
            smtp_user=_smtp_user,
            smtp_password=_smtp_password,
            email_sender=_sender_email,
        )
    except Exception as e:
        print(f"Failed to initialize EmailHelper: {e}")
        return

    # Use config devices if no external devices provided
    current_devices = devices if devices else config.challenge.devices

    if not current_devices:
        print("No devices found in configuration or provided file.")
        print("Please provide a devices.json file or ensure config.challenge.devices is populated.")
        return

    # If override_email is provided and we are using config devices (devices was None), 
    # we apply it here to ensure grouping.
    if override_email and devices is None:
        masked_override = mask_email(override_email)
        print(f"Redirecting all config devices to: {masked_override}")
        current_devices = [d.model_copy(update={"email": override_email}) for d in current_devices]

    print(f"Found {len(current_devices)} devices.")

    # Initialize DFPManager
    # fp_js is required by __init__ but not used for this email test
    dfp_manager = DFPManager(fp_js="console.log('test')")
    
    print("Generating targets (forcing n_repeat=1 to match production)...")
    try:
        dfp_manager.generate_targets(
            devices=current_devices,
            n_repeat=1,
            random_seed=config.challenge.random_seed,
        )
    except Exception as e:
        print(f"Error generating targets: {e}")
        return

    # Group targets by email
    targets_by_email = defaultdict(list)
    BROWSERS = ["chrome", "brave", "firefox"]
    
    # Consistency map: device_id -> assigned_browser
    # This ensures that each physical device (by ID) gets exactly one browser choice.
    device_browser_map = {}

    print("Grouping targets and assigning browsers...")
    for _i, _target_device in enumerate(dfp_manager.target_devices):
        # Check if we already assigned a browser to this specific device ID
        dev_id = _target_device.id
        if dev_id not in device_browser_map:
            device_browser_map[dev_id] = random.choice(BROWSERS)
        
        # Apply the consistent browser choice
        _target_device.browser = device_browser_map[dev_id]

        _web_endpoint = "/_web"
        _web_base_url = str(config.challenge.proxy_exter_base_url).rstrip("/")
        _web_url = f"{_web_base_url}{_web_endpoint}?order_id={_i}"
        
        targets_by_email[_target_device.email].append({
            "device": _target_device,
            "url": _web_url,
            "index": _i
        })

    # Send batched emails
    print(f"Sending emails to {len(targets_by_email)} recipients...")
    for email, items in targets_by_email.items():
        # Shuffle items to ensure random order in email (CRITICAL REQUIREMENT)
        random.shuffle(items)
        
        # Format: device_model-with-hyphens browser
        subjects = [f"{item['device'].device_model.replace(' ', '-')} {item['device'].browser}" for item in items]
        combined_subject = ", ".join(subjects)
        
        # Use a single space instead of empty string to avoid spam filters
        combined_body = " "

        recipient = override_email if override_email else email
        masked_recipient = mask_email(recipient)
        
        print(f"\nProcessing email for: ")
        print(f"  Subject: {combined_subject}")
        print(f"  Items count: {len(items)}")
        
        try:
            success = helper.send(
                to=recipient,
                subject=combined_subject,
                body=combined_body
            )

            if success:
                print("  -> Sent successfully!")
            else:
                print("  -> Failed to send.")
        except Exception as e:
            print(f"  -> Error sending: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send batch test emails using devices.json or config.")
    parser.add_argument("email", nargs="?", help="Override all recipient emails with this address for testing")
    parser.add_argument("--devices", "-d", help="Path to devices.json file")
    parser.add_argument("--to", help="Override all recipient emails with this address for testing (alias for positional arg)")
    parser.add_argument("--sender", help="Override 'From' address")
    parser.add_argument("--smtp-user", help="Override SMTP username")
    parser.add_argument("--smtp-password", help="Override SMTP password")
    parser.add_argument("--smtp-host", help="Override SMTP host")
    parser.add_argument("--smtp-port", type=int, help="Override SMTP port")
    
    args = parser.parse_args()
    
    override_email = args.to if args.to else args.email
    loaded_devices = None
    
    # Priority 1: Command line argument
    if args.devices:
        if os.path.exists(args.devices):
            loaded_devices = load_devices_from_file(args.devices)
        else:
            print(f"Warning: File {args.devices} not found.")

    # Priority 2: devices.json in current directory (if not loaded yet)
    if not loaded_devices and os.path.exists("devices.json"):
        loaded_devices = load_devices_from_file("devices.json")
    
    # Priority 3: devices.json in templates/configs (common location)
    if not loaded_devices:
        possible_path = os.path.join("templates", "configs", "devices.json")
        if os.path.exists(possible_path):
             loaded_devices = load_devices_from_file(possible_path)

    # Apply override to devices list if provided, to ensure they all group into one email
    if override_email and loaded_devices:
        masked = mask_email(override_email)
        print(f"Redirecting all devices to: {masked}")
        new_devices = []
        for d in loaded_devices:
            # Create a copy with the new email
            new_devices.append(d.model_copy(update={"email": override_email}))
        loaded_devices = new_devices

    test_email_batch(
        loaded_devices, 
        override_email=override_email,
        sender_email=args.sender,
        smtp_user=args.smtp_user,
        smtp_password=args.smtp_password,
        smtp_host=args.smtp_host,
        smtp_port=args.smtp_port
    )
