# Network Vulnerability Scanner

The **Network Vulnerability Scanner** is a tool designed to scan networks for vulnerabilities and provide actionable insights to improve network security.

---

## How to Use

### 1. Prerequisites
- Ensure you have **Docker** and **Docker Compose** installed on your system.

### 2. Setup
1. Clone the repository:
   
bash
   git clone <repository-url>
   cd network-project

2. Build and start the services:
   
bash
   docker-compose up --build


### 3. Access the Application
- Open your browser and navigate to [http://localhost:3000](http://localhost:3000).

### 4. Perform a Scan
1. Enter the IP address of the network you want to scan in the input field.
2. Click the "Start Scan" button.
3. View the results, including vulnerabilities, open ports, and the overall security score.

---

## Stopping the Application
To stop the application, press Ctrl+C in the terminal where docker-compose is running, or run:
bash
docker-compose down


---

## Notes
- The backend runs on port 5000, and the frontend runs on port 3000.
- Ensure the target network allows scanning and that you have permission to perform scans. (improve this READme)
