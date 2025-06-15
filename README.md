# Intrusion Detection System - IDS
---

## 📄 Final `README.md`

```markdown
# 🚨 Signature-Based Intrusion Detection System (IDS) in C++

A modular, efficient Intrusion Detection System developed in C++ that captures, inspects, and analyzes live network traffic using `libpcap`. It logs packet and payload data, provides IPv4/IPv6 support, and offers a framework for rule-based detection using customizable signatures.

---

## 📌 Key Features

- ✅ Live packet capture using `libpcap`
- ✅ IPv4 and IPv6 packet handling
- ✅ Ethernet, IP, and TCP header parsing
- ✅ Payload extraction and logging
- ✅ Modular logging system for packets and payloads
- ✅ Rule-based detection framework (via `signature.csv`)
- ✅ Graceful termination with `Ctrl+C`

---

## 🗂 Project Structure

```

├── main.cpp              # Main IDS implementation
├── signature.csv         # Signature rules file (CSV format)
├── packets.log           # Logs of full captured packets
├── payloads.log          # Logs of extracted TCP payloads
├── README.md             # Project documentation

````

---

## 🛠 Requirements

- OS: Linux
- C++11 or higher
- `libpcap` development library

### Install libpcap on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install libpcap-dev
````

---

## ⚙️ Compilation & Execution

### Build the program

```bash
g++ main.cpp -o ids -lpcap
```

### Run the IDS

```bash
sudo ./ids <interface>
```

Example:

```bash
sudo ./ids eth0
```

Use `ip a` or `ifconfig` to find available interfaces.

---

## 📄 Signature Rule Format (`signature.csv`)

Each rule should follow this format:

```csv
action,protocol,src_ip,src_port,dst_ip,dst_port,content,sid
alert,tcp,any,0,192.168.1.5,80,SYN flood,1001
alert,tcp,any,0,any,0,HTTP GET,1002
```

* `any`: wildcard for IPs and ports
* `content`: keyword to match in payload (optional)
* `sid`: unique rule ID

> Rules are matched against each packet’s IPs, ports, and payload.

---

## 🧪 Output Logs

* `packets.log`: Raw hex dump of each captured packet.
* `payloads.log`: TCP payloads (if any) extracted from each packet.
* Future: Alert logs on rule matches (e.g., `[ALERT] SYN flood detected`).

---

## 🔍 How Detection Works (Architecture)

* **Logger**: Logs all packets and payloads in hex.
* **NetworkConnection**: Handles opening/closing devices and setting BPF filters.
* **PacketAnalyzer**: Parses Ethernet, IP, and TCP headers. Extracts payload.
* **SignatureDetection** *(in progress)*: Compares each packet to user-defined rules.
* **Signal Handling**: Clean shutdown on `Ctrl+C`.

---

## 🔄 Future Enhancements

* [ ] Fully integrated signature detection with real-time alerting
* [ ] Alert file/email notifications
* [ ] Web dashboard to monitor alerts and traffic
* [ ] IPv6 TCP payload support
* [ ] DDoS/anomaly-based detection engine

---

## 👨‍💻 Developed by

**Vivek Reddy**
Cybersecurity Engineering Student
*"Sky is our limit; change the boundaries."*

---

## 📝 License

MIT License — Free for educational and non-commercial use.

```

---

### 🔧 Next Steps (if you want):

- Want me to **add this as a real file** in your project (`README.md`)?
- Want to **complete integration** of the rule matching & alerts?
- Need help setting this up on **GitHub or demo recording tips**?

Just say the word bro — I’ve got your back 💯
```
