
# 🛡️ NetSentinel

NetSentinel is a powerful network security monitoring tool designed to detect and mitigate common threats like SYN floods, port scans, and brute-force attacks in real-time. With features like intelligent packet analysis and automated IP blocking, NetSentinel is your first line of defense against network intrusions.

---

## 🚀 Features

- **Real-Time Packet Analysis:** Monitors network traffic to identify suspicious activity.
- **Threat Detection:**
  - SYN flood attacks
  - Port scans
  - SSH brute-force attempts
- **Automated IP Blocking:** Temporarily blocks malicious IPs using `iptables`.
- **Customizable Thresholds:** Fine-tune detection sensitivity for different attack types.
- **Logging:** Comprehensive logs for auditing and troubleshooting.

---

## 📦 Requirements

Ensure the following dependencies are installed:

- Python 3.8+
- [PyShark](https://github.com/KimiNewt/pyshark)
- [Colorama](https://pypi.org/project/colorama/)
- TShark (required by PyShark)

Install the Python dependencies with:
```bash
pip install pyshark colorama
```

---

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/NetSentinel.git
   cd NetSentinel
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure TShark is installed on your system:
   ```bash
   sudo apt install tshark  # For Debian-based systems
   ```

---

## 🖥️ Usage

Run the script with the required network interface:

```bash
python netsentinel.py -i <network-interface>
```

Example:
```bash
python netsentinel.py -i eth0
```

### Command-line Options
- `-i, --interface`: Specify the network interface to monitor (e.g., `eth0`).

---

## 📝 Logging

NetSentinel logs all detected threats and actions to `netsentinel.log` in the current directory. This includes detailed information about potential attacks and blocked IPs.

---

## 🔐 Security Mechanisms

- **Blocking:** Malicious IPs are blocked for a configurable duration using `iptables`.
- **Unblocking:** IPs are automatically unblocked after their block duration expires.

---

## 🛡️ Example Output

```plaintext
[INFO] Starting NetSentinel on interface eth0...
[WARNING] Potential SYN flood detected from 192.168.1.101: 192.168.1.101 -> 192.168.1.102 [TCP]
[CRITICAL] Blocking IP address 192.168.1.101 for 60 seconds...
[INFO] Unblocked IP address 192.168.1.101
```

---

## 📖 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests to improve NetSentinel.

---

## 🌟 Acknowledgments

- Inspired by the need for robust network security.
- Powered by [PyShark](https://github.com/KimiNewt/pyshark) and Python.
