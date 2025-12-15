# KuCoin RT Detection Tool

## Quick Start

### Step 1: Get the Files

Clone this repository or download as ZIP, then extract all files to the same directory:

- `kucoin_rt_detection_tool.py` 
- `requirements.txt` 
- `install.py` 
- `README.md` 

### Step 2: Install Dependencies

#### Windows
```cmd
python install.py
```

#### macOS/Linux
```bash
python3 install.py
```

### Step 3: Run the Tool

#### Windows
```cmd
python kucoin_rt_detection_tool.py
```

#### macOS/Linux
```bash
python3 kucoin_rt_detection_tool.py
```

### Step 4: What to Expect
When the tool starts, you'll see:

```text
==================================================
KuCoin RT Detection Tool
==================================================
Enter API Key: 
```

- Secure input: API credentials are hidden when typing
- Real-time progress: See each IP being tested
- Detailed results: Tables with performance metrics
- Data export: CSV files saved to ping_data/ folder

## Features & Details
**KuCoin RT Detection Tool** is a professional tool designed to measure ping-pong round trip time (RTT) for WebSocket connections. 
### Key Features

- **RTT Measurement**
- **Multi-IP Concurrent Testing**
- **Enterprise-Grade Security**
- **Comprehensive Analytics**
- **Smart Recommendations**

## Detailed Installation & Setup

### Step 1: Download Files
Extract all 4 files to the same directory:
- `web_socket_scout.py` (main tool)
- `requirements.txt` (dependencies)
- `install.py` (installer)
- `README.md` (this document)

### Step 2: Install Dependencies

#### Windows
```bash
# Open Command Prompt and run:
python install.py

# If python command not found, try:
py install.py
```

#### Linux
```bash
# Open Terminal and run:
python3 install.py

# If python3 not installed, first install it:
sudo apt update && sudo apt install python3 python3-pip
```

#### macOS
```bash
# Open Terminal and run:
python3 install.py

# If python3 not installed, install with Homebrew:
brew install python3
# Or download from: https://www.python.org/downloads/
```

### Step 3: Run the Tool

#### Windows
```cmd
python web_socket_scout.py
```

#### Linux/macOS
```bash
python3 web_socket_scout.py
```


## What to Expect

After successful installation, running the tool will show:
```
==================================================
KuCoin RT Detection Tool
==================================================
Enter API Key:
```

- **Secure input**: API credentials are hidden when typing
- **Real-time progress**: See each IP being tested
- **Detailed results**: Tables with performance metrics
- **Data export**: CSV files saved to `ping_data/`

**Follow the on-screen instructions to:**
1. Enter API credentials (input hidden)
2. Specify domains to test (one per line, empty line to finish)
3. Configure test parameters (count, timeout, interval)
4. View comprehensive performance results

---

## Output Format

**CSV Filename:** `ping_YYYYMMDD_HHMMSS.csv`

**Columns:**
- `ping-id`: Unique identifier for each ping
- `send-timestamp`: When ping was sent (ms)
- `receive-timestamp`: When pong was received (ms)
- `server-pong-timestamp`: Server timestamp from pong response
- `rtt(μs)`: Round-trip time in microseconds
- `success`: Whether the ping was successful
- `failure-reason`: Reason for failure

---

## FAQ & Support

**Q: The tool can't connect or fails to run?**
- Ensure all files are in the same directory
- Check your internet connection
- Make sure your API credentials are valid
- Check firewall or proxy settings

**Q: How do I update dependencies?**
- Re-run the install command: `python3 install.py` (macOS/Linux) or `python install.py` (Windows)

**Q: Where are results saved?**
- In the `ping_data/` folder as CSV files

