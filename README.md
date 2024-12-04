# VRV Security Python Intern Submission

## Project Overview

This project is a Python script for analyzing web server logs. It performs the following tasks:

1. **Count Requests per IP Address**: Tracks the number of requests made by each IP.
2. **Identify the Most Frequently Accessed Endpoint**: Finds the most accessed endpoints.
3. **Detect Suspicious Activity**: Identifies IPs with excessive failed login attempts.

The results are displayed in the terminal and saved to a CSV file.

## Features

- **Request Count per IP**: Displays the number of requests per IP address.
- **Most Accessed Endpoint**: Displays the most accessed endpoint.
- **Suspicious Activity Detection**: Flags IP addresses with more than a specified number of failed login attempts.

## Usage

1. Clone the repository:

    ```bash
    git clone https://github.com/yourusername/vrv-security-python-intern.git
    cd vrv-security-python-intern
    ```

2. Run the script:

    ```bash
    python log_analysis.py
    ```

The results will be displayed in the terminal and saved to a CSV file (`log_analysis_results.csv`).

## Customization

- **Failed Login Threshold**: The script flags IPs with more than 3 failed login attempts. You can modify this threshold in the script.

## License

This project is submitted as part of an internship assignment and does not have an official license.
---

**VRV Security Python Intern Submission**
