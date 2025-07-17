# My-SIEM: A Python Network Monitor

## What is a SIEM?
SIEM stands for **Security Information and Event Management**. It is a solution that helps organizations detect, analyze, and respond to security threats before they harm business operations. A SIEM tool collects log data from various sources, identifies activity that deviates from the norm, and takes appropriate action. For example, it can collect security data from network devices, servers, and applications, and present it all in a central dashboard.

This project is the first step in building a personal, lightweight SIEM.

### Future Goals
Our ambition is to develop this project into a fully-featured, professional SIEM tool. Future versions will aim to include more advanced threat detection, automated response capabilities, comprehensive reporting, and the integration of a robust firewall, making it a powerful asset for any security enthusiast or small organization.

## What It Does
This tool captures and analyzes network packets on a selected network interface. Its core functionality is to provide visibility and control over the traffic flowing to and from the machine it's running on.

- **PC Monitoring (Default Mode):** Out of the box, the application monitors all network traffic associated with the computer it is running on. By selecting a specific interface like `eth0` or `wlan0`, you can see all connections being made to and from your PC.

- **Router/Network Monitoring (Advanced):** The software is capable of monitoring an entire network's traffic (all devices connected to your router). However, this requires a specific hardware setup. To achieve this, you need a **managed** network switch that supports **port mirroring (or SPAN)**. You must configure the switch to send a copy of all traffic from the router's port to the port your computer is connected to. Once configured, you can select the corresponding interface in the dashboard to view all network activity.

## Project Structure
The repository is organized as follows:

- `agent/`: This directory contains all the core source code for the application, including the Python scripts (`app.py`, `analyzer.py`, etc.), web templates (`index.html`), and static files (`style.css`).
- `Dockerfile`: This file contains all the instructions to build the Docker image for the application, ensuring all dependencies and configurations are correct for easy deployment.
- `README.md`: This file, providing documentation and instructions for the project.

## Features
- **Live Packet Capture:** Uses Scapy to sniff network traffic in real time.
- **Dynamic Interface Selection:** Choose which network interface to monitor directly from the dashboard.
- **Comprehensive Logging:** All detected packets are logged to a local SQLite database (`logs.db`).
- **Rich Web Dashboard:** Built with Flask and Socket.IO, the dashboard features:
  - A live-updating log table with search and filtering.
  - Real-time charts for Protocol Distribution, Events Over Time, and Top Source IPs.
  - Light and Dark theme modes.
  - Ability to save session logs to a JSON file.

## Installation and Usage (Docker - Recommended)

Using Docker is the easiest way to run the application with all its dependencies managed.

### 1. Install Docker

First, ensure you have Docker installed on your Linux system. If not, you can install it by running:

```bash
sudo apt-get update
sudo apt-get install docker.io -y
sudo systemctl enable docker --now
```

Add your user to the `docker` group to run Docker commands without `sudo` (you will need to log out and log back in for this to take effect):

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Build the Docker Image

Navigate to the project directory and run the following command to build the image:

```bash
docker build -t python-siem .
```

### 3. Run the Docker Container

Run the application using this command. The flags are important for giving it the necessary network permissions:

```bash
docker run --rm -it -p 5000:5000 --net=host --cap-add=NET_ADMIN python-siem
```

- `--net=host`: Allows the container to access your host machine's network interfaces directly.
- `--cap-add=NET_ADMIN`: Grants the necessary privileges to capture network traffic.

### 4. Access the Dashboard

Open your web browser and navigate to **http://localhost:5000**.

## Dashboard Guide

Here’s how to use the controls on the dashboard:

- **Light/Dark Toggle:** Switches the UI between light and dark themes for your viewing preference.
- **Scan Target Dropdown:**
  - **Default (My PC):** A general-purpose mode for monitoring your local machine.
  - **eth0, lo, etc.:** Select a specific network interface to monitor. For monitoring external traffic (like pings from another PC), choose your main network card (e.g., `eth0`).
- **Manage Rules Button (⚙️):** Opens a pop-up window where you can dynamically add or remove rules.
- **Start Button (▶️):** Begins capturing network traffic on the selected interface. The dashboard will start showing live data.
- **Stop Button (⏹️):** Pauses the packet capture.
- **Clear Button (🗑️):** Deletes all logs from the current session, both from the database and the UI.
- **Save Button (💾):** Downloads all logs from the current session as a `siem_logs.json` file.
