# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies, then clean up to keep the image small
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy the requirements file from the 'agent' subdirectory first
COPY agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code from the 'agent' subdirectory
COPY agent/ .

# Expose the port the app runs on
EXPOSE 5000

# Define the command to run your app
CMD ["python", "app.py"]