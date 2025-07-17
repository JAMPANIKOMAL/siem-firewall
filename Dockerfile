# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# === NEW: Install system dependencies required by Scapy ===
RUN apt-get update && apt-get install -y libpcap-dev

# Copy the requirements file and install dependencies
COPY firewall/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code from the 'firewall' subdirectory
COPY firewall/ .

# Expose the port the app runs on
EXPOSE 5000

# Define the command to run your app
CMD ["python", "app.py"]