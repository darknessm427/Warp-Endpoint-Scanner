import base64
import datetime
import json
import os
import random
import time
import requests
import nacl.public
import nacl.utils
import nacl.bindings
import subprocess
import platform
import concurrent.futures
from typing import List, Dict, Any, Tuple, Optional

# --- Constants ---
WARP_API_URL = "https://api.cloudflareclient.com/v0a4005/reg"
USER_AGENT = "insomnia/8.6.1"

PORTS = [
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
    987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476,
    3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
]
IPV4_PREFIXES = [
    "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",
    "162.159.192.", "162.159.193.", "162.159.195.",
]
IPV6_PREFIXES = [
    "2606:4700:d0::", "2606:4700:d1::",
]

CORE_INIT_PORT = 10800
CORE_DIR = "xray_core_temp_files"  # Directory for Xray temporary files
XRAY_CONFIG_FILE = os.path.join(CORE_DIR, "config.json")
# Xray log file paths (for debugging)
XRAY_LOG_STDOUT_FILE = os.path.join(CORE_DIR, "xray_stdout.log")
XRAY_LOG_STDERR_FILE = os.path.join(CORE_DIR, "xray_stderr.log")


if platform.system() == "Windows":
    XRAY_EXECUTABLE_PATH = "./xray.exe"
else:
    XRAY_EXECUTABLE_PATH = "./xray"

TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TRIES = 3
TEST_TIMEOUT_SECONDS = 2
MAX_CONCURRENT_TESTS = 20 
NUM_CANDIDATES_PER_TYPE_TARGET = 60 # Increased number of candidates

ScanResult = Tuple[str, float, float] # endpoint, avg_latency_ms, loss_rate_percent

def generate_wireguard_keypair() -> Tuple[str, str]:
    """Generates a WireGuard key pair."""
    private_key_bytes = bytearray(os.urandom(32))
    private_key_bytes[0] &= 248
    private_key_bytes[31] &= 127
    private_key_bytes[31] |= 64
    public_key_bytes = nacl.bindings.crypto_scalarmult_base(bytes(private_key_bytes))
    private_key_b64 = base64.b64encode(bytes(private_key_bytes)).decode('utf-8')
    public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
    return public_key_b64, private_key_b64

def fetch_warp_config_from_api(public_key_b64: str) -> Optional[Dict[str, Any]]:
    """Fetches WARP configuration from Cloudflare API."""
    payload = {
        "install_id": "", "fcm_token": "",
        "tos": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "type": "Android", "model": "PC", "locale": "en_US", "warp_enabled": True,
        "key": public_key_b64,
    }
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    try:
        response = requests.post(WARP_API_URL, json=payload, headers=headers, timeout=15)
        response.raise_for_status()
        print("Successfully fetched WARP config from API.")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching WARP config: {e}")
        return None

def extract_warp_parameters(config_data: Dict[str, Any], client_private_key_b64: str) -> Optional[Dict[str, Any]]:
    """Extracts necessary parameters for Xray from WARP configuration."""
    try:
        conf = config_data['config']
        client_ipv6 = conf['interface']['addresses']['v6']
        if not client_ipv6.endswith("/128"):
             client_ipv6 += "/128"

        client_id_b64 = conf['client_id']
        reserved_bytes = list(base64.b64decode(client_id_b64))
        
        if not conf['peers']:
            print("Error: No peers found in WARP config.")
            return None
        peer_public_key = conf['peers'][0]['public_key']

        params = {
            "PrivateKey": client_private_key_b64,
            "IPv6": client_ipv6,
            "Reserved": reserved_bytes,
            "PublicKey": peer_public_key
        }
        print(f"Successfully extracted WARP parameters (Client IPv6: {params['IPv6']}).")
        return params
    except (KeyError, IndexError) as e:
        print(f"Error extracting WARP parameters: Missing key or peer - {e}")
        return None

def get_warp_params_for_xray() -> Optional[Dict[str, Any]]:
    """Manages the entire process of obtaining WARP parameters."""
    client_public_key, client_private_key = generate_wireguard_keypair()
    print(f"Generated WireGuard Keys. Client Public Key: {client_public_key[:20]}...")
    
    config_data = fetch_warp_config_from_api(client_public_key)
    if not config_data:
        return None
    
    return extract_warp_parameters(config_data, client_private_key)

def generate_candidate_endpoints(num_ipv4: int, num_ipv6: int, existing_endpoints: Optional[set[str]] = None) -> List[str]:
    """Generates unique candidate IP:Port endpoints."""
    if existing_endpoints is None:
        existing_endpoints = set()
    
    endpoints: List[str] = []
    generated_ipv4_count = 0
    generated_ipv6_count = 0
    
    max_attempts_factor = 5 # To prevent infinite loops
    
    # Generate IPv4
    attempts_ipv4 = 0
    while generated_ipv4_count < num_ipv4 and attempts_ipv4 < num_ipv4 * max_attempts_factor:
        prefix = random.choice(IPV4_PREFIXES)
        ip_part = random.randint(0, 255)
        port = random.choice(PORTS)
        endpoint = f"{prefix}{ip_part}:{port}"
        if endpoint not in existing_endpoints:
            existing_endpoints.add(endpoint)
            endpoints.append(endpoint)
            generated_ipv4_count +=1
        attempts_ipv4 += 1
    
    # Generate IPv6
    attempts_ipv6 = 0
    # Temporary list for IPv6 to ensure correct count before extending main list
    temp_ipv6_endpoints: List[str] = []
    while generated_ipv6_count < num_ipv6 and attempts_ipv6 < num_ipv6 * max_attempts_factor:
        prefix = random.choice(IPV6_PREFIXES)
        hex_parts = [format(random.randint(0, 65535), 'x') for _ in range(4)]
        ip_part = f"{prefix}{':'.join(hex_parts)}"
        port = random.choice(PORTS)
        endpoint = f"[{ip_part}]:{port}"
        if endpoint not in existing_endpoints:
            existing_endpoints.add(endpoint)
            temp_ipv6_endpoints.append(endpoint)
            generated_ipv6_count +=1
        attempts_ipv6 += 1
    
    endpoints.extend(temp_ipv6_endpoints) # Add generated IPv6 endpoints to the main list

    if attempts_ipv4 >= num_ipv4 * max_attempts_factor or attempts_ipv6 >= num_ipv6 * max_attempts_factor :
        print("Warning: Reached max attempts for generating unique endpoints. Fewer may have been generated.")

    random.shuffle(endpoints) # Shuffle the final list for more random testing order
    print(f"{len(endpoints)} new unique candidate IP:Port endpoints generated (after shuffle).")
    return endpoints


def build_xray_config_json(candidate_endpoints: List[str], warp_params: Dict[str, Any]) -> Dict[str, Any]:
    """Creates the JSON configuration file for Xray."""
    inbounds = []
    outbounds = [{ "protocol": "freedom", "settings": {}, "tag": "direct" }]
    routing_rules = [{ "type": "field", "outboundTag": "direct", "protocol": ["dns"] }]

    for i, endpoint_addr_port in enumerate(candidate_endpoints):
        inbound_tag = f"http-in-{i+1}"
        outbound_tag = f"proxy-{i+1}"
        local_proxy_port = CORE_INIT_PORT + i

        inbounds.append({
            "listen": "127.0.0.1", "port": local_proxy_port, "protocol": "http",
            "tag": inbound_tag, "settings": {"timeout": 120}
        })

        outbounds.append({
            "protocol": "wireguard",
            "settings": {
                "secretKey": warp_params["PrivateKey"],
                "address": ["172.16.0.2/32", warp_params["IPv6"]],
                "peers": [{
                    "publicKey": warp_params["PublicKey"],
                    "endpoint": endpoint_addr_port,
                    "keepAlive": 25
                }],
                "mtu": 1280,
                "reserved": warp_params["Reserved"]
            },
            "tag": outbound_tag
        })

        routing_rules.append({
            "type": "field", "inboundTag": [inbound_tag], "outboundTag": outbound_tag
        })
    
    # Xray's own access and error log paths (for debugging)
    xray_log_config_access = os.path.join(CORE_DIR, "access.log") 
    xray_log_config_error = os.path.join(CORE_DIR, "error.log")   

    return {
        "log": {"access": xray_log_config_access, "error": xray_log_config_error, "loglevel": "info"}, # Changed loglevel to info
        "dns": {"servers": ["1.1.1.1", "8.8.8.8", "1.0.0.1"]}, # Added more DNS servers
        "inbounds": inbounds, "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": routing_rules}
    }

def test_single_proxy(original_endpoint: str, proxy_address: str, target_url: str, num_tries: int, timeout: int) -> Optional[ScanResult]:
    """Tests a single proxy and returns (original_endpoint, avg_latency_ms, loss_rate_percent) or None."""
    success_count = 0
    latencies: List[float] = []

    for i in range(num_tries):
        start_time = time.monotonic()
        try:
            response = requests.head(
                target_url,
                proxies={"http": proxy_address, "https": proxy_address},
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            latency_ms = (time.monotonic() - start_time) * 1000
            if response.status_code == 204:
                success_count += 1
                latencies.append(latency_ms)
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException:
            pass
        if i < num_tries - 1:
             time.sleep(0.2)

    if not latencies:
        return None
    
    avg_latency = sum(latencies) / len(latencies)
    loss_rate = (num_tries - success_count) / num_tries * 100.0
    return original_endpoint, avg_latency, loss_rate


def main():
    if not os.path.exists(XRAY_EXECUTABLE_PATH):
        print(f"Error: Xray executable not found at '{XRAY_EXECUTABLE_PATH}'.")
        print("Please download Xray and place it in the correct path or update the XRAY_EXECUTABLE_PATH variable.")
        return

    os.makedirs(CORE_DIR, exist_ok=True)

    print("1. Fetching WARP parameters...")
    warp_params = get_warp_params_for_xray()
    if not warp_params:
        print("Failed to fetch WARP parameters. Exiting.")
        return
    
    print(f"Received WARP IPv6 parameter: {warp_params.get('IPv6')}") # Print received IPv6 for checking

    print("\n2. Generating and testing IP endpoints...")
    all_tested_results: List[ScanResult] = []
    generated_candidates_set: set[str] = set()
    
    initial_candidates_ipv4 = NUM_CANDIDATES_PER_TYPE_TARGET 
    initial_candidates_ipv6 = NUM_CANDIDATES_PER_TYPE_TARGET
    
    print(f"Generating {initial_candidates_ipv4} initial IPv4 and {initial_candidates_ipv6} initial IPv6 candidates...")
    # Generate IPv4 and IPv6 candidates separately then combine
    ipv4_candidates = generate_candidate_endpoints(initial_candidates_ipv4, 0, generated_candidates_set)
    ipv6_candidates = generate_candidate_endpoints(0, initial_candidates_ipv6, generated_candidates_set)
    candidate_endpoints = ipv4_candidates + ipv6_candidates
    random.shuffle(candidate_endpoints) # Shuffle final list for better test distribution

    if not candidate_endpoints:
        print("No candidate endpoints were generated. Exiting.")
        return

    print(f"\n3. Building Xray configuration for {len(candidate_endpoints)} endpoints...")
    xray_json_config = build_xray_config_json(candidate_endpoints, warp_params)
    try:
        with open(XRAY_CONFIG_FILE, "w") as f:
            json.dump(xray_json_config, f, indent=2)
        print(f"Xray configuration written to {XRAY_CONFIG_FILE}.")
    except IOError as e:
        print(f"Error writing Xray configuration file: {e}")
        return

    print("\n4. Starting Xray core...")
    xray_process: Optional[subprocess.Popen] = None
    
    try:
        # Open log files before starting Xray process
        with open(XRAY_LOG_STDOUT_FILE, "wb") as stdout_f, open(XRAY_LOG_STDERR_FILE, "wb") as stderr_f:
            xray_process = subprocess.Popen(
                [XRAY_EXECUTABLE_PATH, "-c", XRAY_CONFIG_FILE],
                stdout=stdout_f, stderr=stderr_f # Redirect stdout and stderr to files
            )
        print(f"Xray process started with PID: {xray_process.pid}. Waiting for initialization...")
        time.sleep(6) # Increased wait time for Xray to initialize
    except FileNotFoundError:
        print(f"Error: Xray executable not found at '{XRAY_EXECUTABLE_PATH}'.")
        return
    except Exception as e:
        print(f"Error starting Xray: {e}")
        if xray_process: xray_process.kill()
        return

    print(f"\n5. Testing {len(candidate_endpoints)} endpoints with max {MAX_CONCURRENT_TESTS} concurrent tests...")
    
    tasks_completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TESTS) as executor:
        future_to_endpoint_test = {}
        for i, original_endpoint_candidate in enumerate(candidate_endpoints):
            local_proxy_port = CORE_INIT_PORT + i
            proxy_url_for_test = f"http://127.0.0.1:{local_proxy_port}"
            future = executor.submit(test_single_proxy, original_endpoint_candidate, proxy_url_for_test, TEST_URL, TEST_TRIES, TEST_TIMEOUT_SECONDS)
            future_to_endpoint_test[future] = original_endpoint_candidate

        for future in concurrent.futures.as_completed(future_to_endpoint_test):
            original_endpoint_tested = future_to_endpoint_test[future]
            try:
                result: Optional[ScanResult] = future.result()
                if result:
                    all_tested_results.append(result)
            except Exception as exc:
                print(f"    Error during test for {original_endpoint_tested}: {exc}")
            tasks_completed +=1
            # Print progress at reasonable intervals
            if tasks_completed % (len(candidate_endpoints) // 20 or 1) == 0 or tasks_completed == len(candidate_endpoints):
                 print(f"   Test progress: {tasks_completed}/{len(candidate_endpoints)} completed.")


    print("\n6. Stopping Xray core...")
    if xray_process:
        xray_process.terminate()
        try:
            xray_process.wait(timeout=10)
            print("Xray process terminated.")
        except subprocess.TimeoutExpired:
            print("Xray process did not terminate in time, killing...")
            xray_process.kill()
            xray_process.wait()
            print("Xray process killed.")

    print("\n7. Processing and saving results to README.md...")
    
    ipv4_results = [r for r in all_tested_results if "." in r[0].split(":", 1)[0] and "[" not in r[0].split(":", 1)[0]]
    ipv6_results = [r for r in all_tested_results if "[" in r[0].split(":", 1)[0]]

    # Sort by latency (ascending, -1 treated as infinity), then by loss rate (ascending)
    ipv4_results.sort(key=lambda x: (x[1] if x[1] != -1 else float('inf'), x[2]))
    ipv6_results.sort(key=lambda x: (x[1] if x[1] != -1 else float('inf'), x[2]))

    readme_content = ["# Daily WARP Endpoint Test Results"]
    readme_content.append(f"\nLast updated on: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    
    num_to_output = 10

    readme_content.append("## Top IPv4 Endpoints")
    valid_ipv4_results = [r for r in ipv4_results if r[1] != -1][:num_to_output]
    if valid_ipv4_results:
        if len(valid_ipv4_results) < num_to_output:
            readme_content.append(f"\n*Note: Fewer than {num_to_output} suitable IPv4 endpoints were found (found: {len(valid_ipv4_results)}).*\n")
        readme_content.append("\n| Endpoint | Loss Rate (%) | Avg. Latency (ms) |")
        readme_content.append("|---|---|---|")
        for res in valid_ipv4_results:
            readme_content.append(f"| `{res[0]}` | {res[2]:.2f} | {res[1]:.2f} |")
    else:
        readme_content.append("\n*No suitable IPv4 endpoints were found.*\n")

    readme_content.append("\n## Top IPv6 Endpoints")
    valid_ipv6_results = [r for r in ipv6_results if r[1] != -1][:num_to_output]
    if valid_ipv6_results:
        if len(valid_ipv6_results) < num_to_output:
            readme_content.append(f"\n*Note: Fewer than {num_to_output} suitable IPv6 endpoints were found (found: {len(valid_ipv6_results)}).*\n")
        readme_content.append("\n| Endpoint | Loss Rate (%) | Avg. Latency (ms) |")
        readme_content.append("|---|---|---|")
        for res in valid_ipv6_results:
            readme_content.append(f"| `{res[0]}` | {res[2]:.2f} | {res[1]:.2f} |")
    else:
        readme_content.append("\n*No suitable IPv6 endpoints were found.*\n")

    output_filename_md = "README.md"
    try:
        with open(output_filename_md, "w", encoding='utf-8') as f: # Ensure UTF-8 encoding for README
            for line in readme_content:
                f.write(line + "\n")
        print(f"\nResults successfully written to {output_filename_md}.")
        print(f"Total working IPv4 endpoints found (before final filter): {len([r for r in ipv4_results if r[1]!=-1])}")
        print(f"Total working IPv6 endpoints found (before final filter): {len([r for r in ipv6_results if r[1]!=-1])}")

    except IOError as e:
        print(f"Error writing README.md file: {e}")

    # Clean up temporary config file (logs are kept for inspection in CI)
    try:
        if os.path.exists(XRAY_CONFIG_FILE): os.remove(XRAY_CONFIG_FILE)
        # Keep the CORE_DIR if it contains logs, otherwise remove if empty
        # if os.path.exists(CORE_DIR) and not any(fname.endswith(('.log', '.dat')) for fname in os.listdir(CORE_DIR)):
        #     if not os.listdir(CORE_DIR): # Double check if empty after potential log file removal (if logic changes)
        #          os.rmdir(CORE_DIR)
        # elif os.path.exists(CORE_DIR):
        #      print(f"Directory {CORE_DIR} contains logs and was not removed.")
    except OSError as e:
        print(f"Error cleaning up temporary config file: {e}")

if __name__ == "__main__":
    main()
