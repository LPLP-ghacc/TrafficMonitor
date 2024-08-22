# Network Traffic Monitor

Network Traffic Monitor is a Python application for capturing and analyzing network traffic. The application groups captured packets by the processes, making it easier to analyze the network activity of specific applications.

## Features

- Capture network packets on all available interfaces.
- Group packets by the processes using the ports.
- Display detailed information about each packet.
- Show raw packet data in hexadecimal format.

## Requirements

- Python 3.7+
- [Scapy](https://scapy.readthedocs.io/)
- [psutil](https://pypi.org/project/psutil/)
- Tkinter (part of the standard Python library)

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/YOUR_USERNAME/NetworkTrafficMonitor.git
    cd NetworkTrafficMonitor
    ```

2. Create a virtual environment:

    ```sh
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```

3. Install the required packages:

    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. Run the application:

    ```sh
    python app.py
    ```
