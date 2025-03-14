Network Vulnerability Scanner

The Network Vulnerability Scanner is a powerful tool designed to scan networks for vulnerabilities and provide actionable insights to enhance network security.

Features

  Scan for open ports and potential vulnerabilities.
  
  Generate a security risk score.
  
  User-friendly React-based interface.
  
  Dockerized environment for easy setup and deployment.

Prerequisites

  Ensure you have the following installed on your system:

    -Docker

    -Docker Compose

Setup Guide

1. Clone the Repository

  -git clone https://github.com/cookster00/network-project
  -cd network-project

2. Build and Run the Services

  - Use command "docker-compose up --build" or "docker compose up --build"

3. Access the Application

  -Open your browser and navigate to http://localhost:3000.

4. Perform a Network Scan

  -Enter the target IP address or domain in the input field.

  -Click the "Start Scan" button.

  -View the detailed results, including:

    -Open ports

    -Detected vulnerabilities

    -Security risk score

Stopping the Application

  To stop the application, either press Ctrl+C in the terminal or run:

  "docker-compose down" or "docker compose down"

Additional Notes

    -The backend runs on port 5000 and the frontend on port 3000.

    -Ensure you have the necessary authorization to scan the target network to avoid legal or ethical issues.

    -Regularly update the vulnerability database for accurate results.


Contributors
  Nathan Cook
  Nickolas Johnson
