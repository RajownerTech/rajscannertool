# Rajscantool: Multi-Advance Scanning Tool

![Rajscantool Banner](./banner.png)

## Description

Rajscantool is a powerful and versatile command-line utility designed for security researchers and network enthusiasts. It combines multiple scanning functionalities into a single, easy-to-use tool, offering features like Host Scanning, CIDR Range Scanning, and Domain Extraction. Built with Python, it leverages `colorama` and `rich` libraries to provide an engaging and informative user experience directly in the terminal.

## Features

### 1. Host Scanner

This feature allows users to scan a list of domains for open ports and HTTP/HTTPS status codes. It's ideal for quickly checking the availability and basic configuration of web servers or other services running on specified domains. The scanner is highly optimized with connection pooling and multi-threading for efficient operation.

*   **Input**: A file containing a list of domains (one per line) and a comma-separated list of ports.
*   **Output**: Displays real-time scan results, including status code, server information, IP address, and domain:port. Results are saved to `scanner_results.txt` and `scanner_ips.txt` in the `RajScan_Results` directory.
*   **Customization**: Users can specify the number of threads for scanning, ranging from 80 to 500.

### 2. CIDR Scanner

The CIDR Scanner is designed to explore entire CIDR (Classless Inter-Domain Routing) ranges for responsive hosts and open ports. This is particularly useful for network reconnaissance and identifying active devices within a given IP range.

*   **Input**: A CIDR range (e.g., `1.1.1.0/24`) and a comma-separated list of ports.
*   **Output**: Displays responsive hosts, their status codes, server information, and the scanned IP:port. Results are saved to `cidr_results.txt` in the `RajScan_Results` directory.
*   **Customization**: Thread count is user-selectable, similar to the Host Scanner.

### 3. Domain Extractor

This utility helps in extracting domain names from any pasted text. It's a convenient tool for quickly gathering domain intelligence from various sources like reports, logs, or web pages.

*   **Input**: Text pasted directly into the terminal (terminated by pressing Enter twice).
*   **Output**: Lists newly extracted domains and saves them to `extracted_domains.txt` in the `RajScan_Results` directory. It intelligently avoids saving duplicate domains that were previously extracted.

### 4. Developer Info

Provides information about the tool's developer, including social media links and other projects. This feature allows users to connect with the creator and stay updated on new tools and developments.
## 📦 INSTALLATION

### 🔹 REQUIREMENTS
- Python 3.8+
- pip

### 🔹 INSTALL (Copy & Paste)
```bash
pip install git+https://github.com/RajownerTech/rajscannertool.git

### 🔹 INSTALL (Copy & Paste)
```bash
rajscannertool

### 🔹 INSTALL (Copy & Paste)
```bash
rajscannertool