#!/usr/bin/env python3
"""
KuCoin RT Detection Tool
Measure ping-pong round trip time excluding handshake latency
"""
import json
import time
import base64
import hashlib
import hmac
import threading
import socket
import ssl
import getpass
import queue
import os
import csv
from urllib.parse import quote
from tabulate import tabulate
import numpy as np
import websocket
import dns.resolver
import certifi
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import uuid


class WebSocketLatencyMeasurer:
    def __init__(self):
        self.config = {}
        self.results = {}
        self.domain_to_ips = {}
        self.is_testing = False
        self.results_lock = threading.Lock()
        self.task_queue = queue.Queue()
        self.use_numpy = True
        self.numpy_dtype = np.float64
        # Data storage related attributes
        self.first_ping_time = None
        self.csv_file_path = None
        self.csv_writer = None
        self.csv_file = None
        self.ping_data_buffer = []  # Buffer for data
        self.buffer_lock = threading.Lock()
        self.buffer_size = 100  # Write every 100 entries
        self.total_pings_written = 0  # Total written ping count
        self.config['enable_storage'] = False
        self.thread_local_buffers = {}
        self.local_buffer_size = 10
    def setup_data_storage(self):
        """Setup data storage"""
        if self.first_ping_time is None:
            self.first_ping_time = int(time.time())
        storage_dir = "ping_data"
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)
        timestamp_str = datetime.fromtimestamp(self.first_ping_time).strftime('%Y%m%d_%H%M%S')
        self.csv_file_path = os.path.join(storage_dir, f"ping_{timestamp_str}.csv")
        print(f"\nData storage file: {self.csv_file_path}")
    def write_csv_header(self):
        """Write CSV header"""
        if self.csv_file_path and not os.path.exists(self.csv_file_path):
            try:
                with open(self.csv_file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    header = [
                        'ping-id', 
                        'send-timestamp', 
                        'receive-timestamp',
                        'server-pong-timestamp',
                        'rtt(ms)', 
                        'success', 
                        'failure-reason'
                    ]
                    writer.writerow(header)
            except Exception as e:
                print(f"Failed to write CSV header: {e}")
    def add_ping_data_to_buffer(self, ping_data):
        """Add ping data to buffer, batch write when threshold reached"""
        with self.buffer_lock:
            self.ping_data_buffer.append(ping_data)
            if len(self.ping_data_buffer) >= self.buffer_size:
                self.flush_buffer_to_csv()
    def flush_buffer_to_csv(self):
        """Write buffer data to CSV file"""
        if not self.ping_data_buffer:
            return
        try:
            file_exists = os.path.exists(self.csv_file_path)
            with open(self.csv_file_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if not file_exists:
                    header = [
                        'ping-id', 
                        'send-timestamp', 
                        'receive-timestamp',
                        'pong-internal-timestamp',
                        'rtt(ms)', 
                        'success', 
                        'failure-reason'
                    ]
                    writer.writerow(header)
                for data in self.ping_data_buffer:
                    writer.writerow([
                        data.get('ping_id', ''),
                        data.get('send_timestamp', ''),
                        data.get('receive_timestamp', ''),
                        data.get('pong_timestamp', ''),
                        data.get('rtt_ms', ''),
                        data.get('success', ''),
                        data.get('failure_reason', '')
                    ])
            written_count = len(self.ping_data_buffer)
            self.total_pings_written += written_count
            self.ping_data_buffer.clear()
        except Exception as e:
            print(f"Failed to write CSV file: {e}")
    def finalize_data_storage(self):
        """Finalize data storage, ensure all data is written"""
        with self.buffer_lock:
            for thread_id, local_buffer in self.thread_local_buffers.items():
                if local_buffer:
                    self.ping_data_buffer.extend(local_buffer)
        if self.ping_data_buffer:
            print(f"Writing final {len(self.ping_data_buffer)} data entries...")
            self.flush_buffer_to_csv()
        if self.csv_file_path and os.path.exists(self.csv_file_path):
            print(f"\nDetailed data available in file:")
            print(f"  - File path: {self.csv_file_path}")
    def resolve_domain_to_ips(self, domain):
        """Resolve domain to IP addresses with timeout handling"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            answers = resolver.resolve(domain, 'A')
            ip_list = [ip.address for ip in answers]
            print(f"Resolved {domain} to IPs: {', '.join(ip_list)}")
            return ip_list
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
            print(f"DNS resolution issue for {domain}: {e}")
            return []
    def _validate_positive_int(self, value, name, default, min_val=1, max_val=None):
        """validate positive integer input"""
        try:
            num = int(value)
        except ValueError:
            print(f"Invalid input for {name}. Using default: {default}")
            return default
        if num < min_val:
            print(f"{name} ({num}) cannot be less than {min_val}. Using minimum: {min_val}")
            return min_val
        if max_val is not None and num > max_val:
            print(f"{name} ({num}) cannot exceed {max_val}. Using maximum: {max_val}")
            return max_val
        return num
    def get_user_config(self, is_retry=False):
        """Get user configuration"""
        print("=" * 50)
        print("KuCoin RT Detection Tool")
        print("=" * 50)
        if is_retry:
            clear_previous = input("\nClear previous domains? (y/n, default n): ").strip().lower()
            if clear_previous == 'y':
                self.domain_to_ips = {}
                print("Previous domains cleared.")
            use_previous_api = input("Use previous API configuration? (y/n, default y): ").strip().lower()
            if use_previous_api == 'n':
                self.config['apikey'] = getpass.getpass("Enter API Key: ").strip()
                self.config['secret'] = getpass.getpass("Enter API Secret: ").strip()
                self.config['passphrase'] = getpass.getpass("Enter Passphrase: ").strip()
            else:
                print("Using previous API configuration")
        else:
            self.domain_to_ips = {}
            self.config['apikey'] = getpass.getpass("Enter API Key: ").strip()
            self.config['secret'] = getpass.getpass("Enter API Secret: ").strip()
            self.config['passphrase'] = getpass.getpass("Enter Passphrase: ").strip()
        print("\nEnter domains to test (one per line, empty line to finish):")
        domains = []
        while True:
            domain = input().strip()
            if not domain:
                break
            domains.append(domain)
        if is_retry and not domains:
            prev_domains = self.config.get('domains', [])
            if not prev_domains:
                print("Error: No previous domains to reuse.")
                return False
            print(f"No new domains entered. Continue with previous domains: {prev_domains}?")
            confirm = input("Continue? (y/n, default n): ").strip().lower()
            if confirm != 'y':
                print("Cancelled. Please enter new domains.")
                return False
            domains = prev_domains
        if not domains:
            print("Error: At least one domain is required")
            return False
        self.config['domains'] = domains
        print("\nResolving domains to IP addresses...")
        all_ips = []
        for domain in domains:
            ips = self.resolve_domain_to_ips(domain)
            if ips:
                self.domain_to_ips[domain] = ips
                all_ips.extend(ips)
        if not all_ips:
            print("Error: No IP addresses resolved")
            return False
        try:
            if not is_retry:
                ping_input = input("\nPing count per IP (default 1000): ") or "1000"
                self.config['ping_count'] = self._validate_positive_int(ping_input, "Ping count", 1000, min_val=1)
                max_workers_input = input("Maximum concurrent threads (default 10, max 16): ") or "10"
                self.config['max_workers'] = self._validate_positive_int(
                    max_workers_input, "Thread count", 10, min_val=1, max_val=16
                )
                timeout_input = input("Timeout in seconds (default 2): ") or "2"
                self.config['timeout'] = float(timeout_input) if float(timeout_input) > 0 else 2.0
                interval_input = input("Interval between pings in seconds (default 0.01): ") or "0.01"
                self.config['interval'] = float(interval_input) if float(interval_input) > 0 else 0.01
                store_csv = input("Store ping data to CSV file? (y/n, default n): ").strip().lower()
                self.config['enable_storage'] = (store_csv == 'y')
            else:
                use_previous_params = input("\nUse previous parameters? (y/n, default y): ").strip().lower()
                if use_previous_params == 'n':
                    ping_input = input("\nPing count per IP (default 1000): ") or "1000"
                    self.config['ping_count'] = self._validate_positive_int(ping_input, "Ping count", 1000, min_val=1)
                    max_workers_input = input("Maximum concurrent threads (default 10, max 16): ") or "10"
                    self.config['max_workers'] = self._validate_positive_int(
                        max_workers_input, "Thread count", 10, min_val=1, max_val=16
                    )
                    timeout_input = input("Timeout in seconds (default 2): ") or "2"
                    self.config['timeout'] = float(timeout_input) if float(timeout_input) > 0 else 2.0
                    interval_input = input("Interval between pings in seconds (default 0.01): ") or "0.01"
                    self.config['interval'] = float(interval_input) if float(interval_input) > 0 else 0.01
                    store_csv = input("Store ping data to CSV file? (y/n, default n): ").strip().lower()
                    self.config['enable_storage'] = (store_csv == 'y')
                else:
                    print(f"Using previous: {self.config.get('ping_count', 1000)} pings, "
                          f"{self.config.get('max_workers', 10)} workers, "
                          f"{self.config.get('timeout', 2)}s timeout, {self.config.get('interval', 0.01)}s interval")
                    store_csv = input("Store ping data to CSV file? (y/n, default n): ").strip().lower()
                    self.config['enable_storage'] = (store_csv == 'y')
        except ValueError:
            print("Error: Invalid input")
            return False
        MAX_SAFE_TOTAL_PINGS = 150000
        total_ips = sum(len(ips) for ips in self.domain_to_ips.values())
        total_pings = total_ips * self.config['ping_count']
        estimated_mb = (total_pings * 24) / (1024 * 1024)
        print(f"\nEstimated number of ping-pong requests: {total_pings:,}")
        if total_pings > MAX_SAFE_TOTAL_PINGS:
            print("May lead to high memory usage and instability.")
            choice = input("Continue? (y or n) [default n]:").strip().lower()
            if choice != 'y':
                print("Please reconfigure parameters to reduce total pings.")
                return False
        return True
    def sign(self, plain: str, key: str) -> str:
        """Generate HMAC-SHA256 signature"""
        hm = hmac.new(key.encode(), plain.encode(), hashlib.sha256)
        return base64.b64encode(hm.digest()).decode()
    def create_websocket_url(self, host):
        """Create WebSocket connection URL with authentication"""
        timestamp = str(int(time.time() * 1000))
        url_path = f"apikey={self.config['apikey']}&timestamp={timestamp}"
        original = f"{self.config['apikey']}{timestamp}"
        sign_value = quote(self.sign(original, self.config['secret']))
        passphrase_sign = quote(self.sign(self.config['passphrase'], self.config['secret']))
        return f"wss://{host}/v1/private?{url_path}&sign={sign_value}&passphrase={passphrase_sign}"
    def establish_connection(self, ip_address, original_domain, timeout=10):
        """Establish WebSocket connection and complete authentication handshake"""
        try:
            ws_url = self.create_websocket_url(ip_address)
            headers = {"Host": original_domain}
            sslopt = {
                "cert_reqs": ssl.CERT_REQUIRED,
                "check_hostname": False,
                "ca_certs": certifi.where()
            }
            ws = websocket.create_connection(
                ws_url, 
                timeout=timeout, 
                header=headers,
                sslopt=sslopt
            )
            ws.settimeout(timeout)
            auth_response = ws.recv()
            session_info = self.sign(auth_response, self.config['secret'])
            ws.send(session_info)
            welcome_msg = ws.recv()
            return ws, None
        except Exception as e:
            return None, f"Connection failed: {str(e)}"
    def clear_websocket_buffer(self, ws, timeout=0.3):
        """Clear WebSocket receive buffer"""
        cleared = 0
        try:
            original_timeout = ws.gettimeout()
            ws.settimeout(timeout)
            while True:
                try:
                    ws.recv()
                    cleared += 1
                except (websocket.WebSocketTimeoutException, socket.timeout):
                    break
                except Exception:
                    break
            ws.settimeout(original_timeout)
        except Exception:
            pass
        return cleared
    def measure_ping_pong(self, ws, ip_address, test_num, timeout=2):
        """Measure single ping-pong round trip time and store data if enabled"""
        unique_suffix = uuid.uuid4().hex[:8]
        ping_id = f"{ip_address}_{unique_suffix}"
        send_time = time.time_ns()
        send_timestamp_ms = int(time.time() * 1000)
        is_warmup = test_num == "warmup"
        try:
            ping_msg = {"id": ping_id, "op": "ping"}
            ws.send(json.dumps(ping_msg))
            start_wait = time.time()
            while time.time() - start_wait < timeout:
                try:
                    response = ws.recv()
                    data = json.loads(response)
                    if data.get('id') == ping_id and data.get('op') == 'pong':
                        receive_time = time.time_ns()
                        receive_timestamp_ms = int(time.time() * 1000)
                        rtt_ms = (receive_time - send_time) / 1_000_000
                        pong_timestamp = data.get('timestamp', '')
                        if self.config.get('enable_storage', False) and not is_warmup:
                            ping_data = {
                                'ping_id': ping_id,
                                'send_timestamp': send_timestamp_ms,
                                'receive_timestamp': receive_timestamp_ms,
                                'pong_timestamp': pong_timestamp,
                                'rtt_ms': f"{rtt_ms:.3f}",
                                'success': 'yes',
                                'failure_reason': ''
                            }
                            thread_id = threading.current_thread().ident
                            if thread_id not in self.thread_local_buffers:
                                self.thread_local_buffers[thread_id] = []
                            local_buffer = self.thread_local_buffers[thread_id]
                            local_buffer.append(ping_data)
                            if len(local_buffer) >= self.local_buffer_size:
                                with self.buffer_lock:
                                    self.ping_data_buffer.extend(local_buffer)
                                    if len(self.ping_data_buffer) >= self.buffer_size:
                                        self.flush_buffer_to_csv()
                                local_buffer.clear()
                        return rtt_ms, ping_id, 'success'
                except json.JSONDecodeError:
                    continue
                except Exception:
                    break
            if self.config.get('enable_storage', False):
                ping_data = {
                    'ping_id': ping_id,
                    'send_timestamp': send_timestamp_ms,
                    'receive_timestamp': '',
                    'pong_timestamp': '',
                    'rtt_ms': '',
                    'success': 'no',
                    'failure_reason': 'timeout'
                }
                self.add_ping_data_to_buffer(ping_data)
            return float('inf'), ping_id, 'timeout'
        except Exception as e:
            error_msg = str(e)
            if self.config.get('enable_storage', False):
                ping_data = {
                    'ping_id': ping_id,
                    'send_timestamp': send_timestamp_ms,
                    'receive_timestamp': '',
                    'pong_timestamp': '',
                    'rtt_ms': '',
                    'success': 'no',
                    'failure_reason': f'error: {error_msg}'
                }
                self.add_ping_data_to_buffer(ping_data)
            return float('inf'), ping_id, f'error: {error_msg}'
    def test_single_ip_concurrent(self, ip_address, original_domain, ping_count=1000, timeout=2, interval=0.01):
        """Test single IP with high volume ping measurements (concurrent-friendly)"""
        rtt_array = np.full(ping_count, np.nan, dtype=np.float64)
        success_count = 0
        failure_reason = None
        ws = None
        try:
            if self.config.get('enable_storage', False) and self.first_ping_time is None:
                self.first_ping_time = int(time.time())
                self.setup_data_storage()
                self.write_csv_header()
            ws, connection_error = self.establish_connection(ip_address, original_domain, timeout=10)
            if not ws:
                failure_reason = connection_error
                print(f"IP {ip_address} connection failed: {connection_error}")
                return {
                    'ip_address': ip_address,
                    'original_domain': original_domain,
                    'avg_latency': float('inf'),
                    'p99_latency': float('inf'),
                    'max_latency': float('inf'),
                    'success_rate': 0,
                    'success_count': 0,
                    'total_count': 0,
                    'latencies': np.array([], dtype=np.float64),
                    'failure_reason': failure_reason
                }
            cleared = self.clear_websocket_buffer(ws)
            if cleared == 0:
                warm_up_result, _, _ = self.measure_ping_pong(ws, ip_address, "warmup", timeout=1)
                self.clear_websocket_buffer(ws, timeout=0.1)
            ws.settimeout(timeout)
            batch_size = 100
            total_batches = ping_count // batch_size + (1 if ping_count % batch_size > 0 else 0)
            for batch in range(total_batches):
                if not self.is_testing:
                    break
                batch_start = batch * batch_size
                batch_end = min(batch_start + batch_size, ping_count)
                batch_size_current = batch_end - batch_start
                print(f"  IP {ip_address}: Running batch {batch+1}/{total_batches} ({batch_size_current} pings)...")
                for i in range(batch_start, batch_end):
                    rtt_ms, ping_id, status = self.measure_ping_pong(ws, ip_address, i, timeout)
                    if status == 'success':
                        rtt_array[success_count] = rtt_ms
                        success_count += 1
                        if success_count % 100 == 0:
                            print(f"  IP {ip_address}: {success_count}/{ping_count} successful")
                    else:
                        if not failure_reason:
                            failure_reason = f"Failed at ping {i+1}: {status}"
                    if i < batch_end - 1 and self.is_testing:
                        time.sleep(interval)
                print(f"  IP {ip_address}: Batch {batch+1}/{total_batches} completed ({batch_end}/{ping_count} pings)")
            if ws:
                ws.close()
        except Exception as e:
            failure_reason = str(e)
            if ws:
                try:
                    ws.close()
                except:
                    pass
        if success_count > 0:
            valid_latencies = rtt_array[:success_count]
            avg_rtt = np.nanmean(valid_latencies)
            p99_rtt = np.nanpercentile(valid_latencies, 99)
            max_rtt = np.nanmax(valid_latencies)
            success_rate = (success_count / ping_count) * 100
            result = {
                'ip_address': ip_address,
                'original_domain': original_domain,
                'avg_latency': avg_rtt,
                'p99_latency': p99_rtt,
                'max_latency': max_rtt,
                'success_rate': success_rate,
                'success_count': success_count,
                'total_count': ping_count,
                'latencies': valid_latencies,
                'failure_reason': None
            }
            print(f"IP {ip_address} test completed: "
                  f"Avg {avg_rtt:.3f}ms, P99 {p99_rtt:.3f}ms, Success {success_rate:.1f}% ({success_count}/{ping_count})")
            return result
        else:
            result = {
                'ip_address': ip_address,
                'original_domain': original_domain,
                'avg_latency': float('inf'),
                'p99_latency': float('inf'),
                'max_latency': float('inf'),
                'success_rate': 0,
                'success_count': 0,
                'total_count': 0,
                'latencies': np.array([], dtype=np.float64),
                'failure_reason': failure_reason or "No successful measurements"
            }
            print(f"IP {ip_address} test failed")
            return result
    def worker_task(self, task_info):
        """Worker task for thread pool"""
        ip_address = task_info['ip_address']
        domain = task_info['domain']
        result = self.test_single_ip_concurrent(
            ip_address=ip_address,
            original_domain=domain,
            ping_count=self.config['ping_count'],
            timeout=self.config['timeout'],
            interval=self.config['interval']
        )
        with self.results_lock:
            self.results[ip_address] = result
        return result
    def display_results(self):
        """Display test results"""
        print("\n" + "=" * 80)
        print("RTT Test Results (by IP Address)")
        print("=" * 80)
        if not self.results:
            print("No successful test results")
            return
        total_ips = len(self.results)
        successful_ips = len([ip for ip, result in self.results.items() if result['success_rate'] > 0])
        failed_ips = total_ips - successful_ips
        print(f"\nTest Summary:")
        print(f"  Total IPs tested: {total_ips}")
        print(f"  Successfully connected IPs: {successful_ips}")
        print(f"  Failed: {failed_ips}")
        print(f"  Total successful pings: {sum(result['success_count'] for result in self.results.values()):,}")
        table_data = []
        for ip_address, result in self.results.items():
            if result['success_rate'] > 0:
                latencies = result['latencies']
                p50 = np.nanpercentile(latencies, 50) if latencies.size > 0 else float('nan')
                p90 = np.nanpercentile(latencies, 90) if latencies.size > 0 else float('nan')
                p95 = np.nanpercentile(latencies, 95) if latencies.size > 0 else float('nan')
                p99 = np.nanpercentile(latencies, 99) if latencies.size > 0 else float('nan')
                table_data.append([
                    ip_address,
                    result['original_domain'],
                    f"{result['avg_latency']:.3f}ms",
                    f"{p50:.3f}ms",
                    f"{p90:.3f}ms",
                    f"{p95:.3f}ms",
                    f"{p99:.3f}ms",
                    f"{result['success_rate']:.1f}%",
                    f"{result['success_count']}/{result['total_count']}"
                ])
            else:
                fail_reason = result.get('failure_reason', 'Unknown error')
                short_reason = (fail_reason[:20] + '...') if len(fail_reason) > 20 else fail_reason
                table_data.append([
                    ip_address,
                    result['original_domain'],
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "0.0%",
                    "0/0",
                    short_reason
                ])
        headers = ["IP Address", "Domain", "Avg RTT", "P50 RTT", "P90 RTT", "P95 RTT", "P99 RTT", "Success Rate", "Pings"]
        failed_ips_with_reasons = {}
        for ip, result in self.results.items():
            failure_reason = result.get('failure_reason')
            if failure_reason and str(failure_reason).strip():
                failed_ips_with_reasons[ip] = failure_reason
        if failed_ips_with_reasons:
            print(f"\nFailure reasons:")
            for ip, reason in failed_ips_with_reasons.items():
                print(f"  {ip}: {reason}")
            headers.append("Failure Reason")
        print("\nDetailed Results:")
        print(tabulate(table_data, headers=headers, tablefmt="grid", stralign="center"))
        successful_results = {k: v for k, v in self.results.items() if v['success_rate'] > 0}
        if not successful_results:
            print("\nAll tests failed, please check network connection")
            return
    def run_tests(self, is_retry=False):
        """Run all tests with thread pool"""
        self.results = {}
        if not self.get_user_config(is_retry):
            return
        self.is_testing = True
        tasks = []
        for domain, ips in self.domain_to_ips.items():
            for ip_address in ips:
                tasks.append({
                    'ip_address': ip_address,
                    'domain': domain
                })
        print(f"\nStarting RTT testing...")
        print(f"Total IP addresses: {len(tasks)}")
        print(f"Tests per IP: {self.config['ping_count']}")
        print(f"Maximum concurrent threads: {self.config['max_workers']}")
        print(f"Timeout: {self.config['timeout']}s")
        print(f"Interval: {self.config['interval']}s")
        print("-" * 50)
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
            future_to_task = {
                executor.submit(self.worker_task, task): task 
                for task in tasks
            }
            completed = 0
            for future in as_completed(future_to_task):
                completed += 1
                task = future_to_task[future]
                try:
                    result = future.result()
                    print(f"Completed {completed}/{len(tasks)}: IP {task['ip_address']}")
                except Exception as e:
                    print(f"Error testing IP {task['ip_address']}: {e}")
        self.is_testing = False
        total_time = time.time() - start_time
        self.display_results()
        if self.config.get('enable_storage', False):
            self.finalize_data_storage()
    def run(self):
        """Run the tool"""
        try:
            self.run_tests(is_retry=False)
            while True:
                choice = input("\nTest again? (y/n): ").strip().lower()
                if choice == 'y':
                    print("\n" + "="*50)
                    print("NEW TEST SESSION")
                    print("="*50)
                    self.run_tests(is_retry=True)
                elif choice == 'n':
                    print("\n" + "="*50)
                    print("Thank you for using KuCoin RT Detection Tool!")
                    print("="*50)
                    break
                else:
                    print("Please enter y or n")
        except KeyboardInterrupt:
            print("\nTest interrupted")
            self.is_testing = False
            if self.config.get('enable_storage', False):
                self.finalize_data_storage()
        except Exception as e:
            print(f"Error: {e}")
            if self.config.get('enable_storage', False):
                self.finalize_data_storage()

def main():
    measurer = WebSocketLatencyMeasurer()
    measurer.run()

if __name__ == "__main__":
    main()
