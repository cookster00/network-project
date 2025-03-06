import React, { useState } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Dashboard from './Pages/Dashboard';

import './App.css';

function App() {
  const [ipAddress, setIpAddress] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanCompleted, setScanCompleted] = useState(false);

  const validateIpAddress = (ip) => {
    const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
  };

  const handleScan = async () => {
    if (!validateIpAddress(ipAddress)) {
      setError('Invalid IP address format, please try again.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Send a request to the backend to perform the scan
      const response = await axios.post('/scan', { ip: ipAddress });
      console.log(response.data);
      setResults(response.data.results);
      setScanCompleted(true);
    } catch (error) {
      console.error(error);
      setError('An error occurred while scanning. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="App">
      <h1>Network Vulnerability Scanner</h1>
      <input
        type="text"
        placeholder="Enter network IP address"
        value={ipAddress}
        onChange={(e) => setIpAddress(e.target.value)}
      />
      <button onClick={handleScan} disabled={loading}>
        {loading ? 'Scanning...' : 'Start Scan'}
      </button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <div className="results">
        {scanCompleted && results && (
          <div>
            <div className="result">
              <h2>FTP Scan</h2>
              <p><strong>Should be worried?:</strong> {results.ftp[0] ? 'Yes' : 'No'}</p>
              <p><strong>Details:</strong> {results.ftp[1] ? results.ftp[1] : 'No details available'}</p>
            </div>
            <div className="result">
              <h2>SMB Scan</h2>
              <p><strong>Should be worried?:</strong> {results.smb[0] ? 'Yes' : 'No'}</p>
              <p><strong>Details:</strong> {results.smb[1] ? results.smb[1] : 'No details available'}</p>
            </div>
            <div className="result">
              <h2>DNS Scan</h2>
              <p><strong>Should be worried?:</strong> {results.dns[0] ? 'Yes' : 'No'}</p>
              <p><strong>Details:</strong> {results.dns[1] ? results.dns[1] : 'No details available'}</p>
            </div>
            <div className="result">
              <h2>SNMP Scan</h2>
              <p><strong>Should be worried?:</strong> {results.snmp[0] ? 'Yes' : 'No'}</p>
              <p><strong>Details:</strong> {results.snmp[1] ? results.snmp[1] : 'No details available'}</p>
            </div>
            <div className="result">
              <h2>Vulnerabilities</h2>
              {results.vulns[0] ? (
                <ul>
                  {results.vulns[1].map((vuln, index) => (
                    <li key={index}>
                      <strong>Port:</strong> {vuln.port}, <strong>Service:</strong> {vuln.service}, <strong>Vulnerabilities:</strong>
                      <ul>
                      {Array.isArray(vuln.vulnerabilities) ? (
                          vuln.vulnerabilities.map((vulnerability, vulnIndex) => (
                            <li key={vulnIndex}>{vulnerability}</li>
                          ))
                        ) : (
                          <li>{vuln.vulnerabilities}</li>
                        )}
                      </ul>
                    </li>
                  ))}
                </ul>
              ) : (
                <p>{results.vulns[1]}</p>
              )}
            </div>
            <div className="result">
              <h2>Open Ports</h2>
              <ul>
                {results.ports.map((port, index) => (
                  <li key={index}>
                    <strong>Port:</strong> {port.port}, <strong>State:</strong> {port.state}, <strong>Service:</strong> {port.service}
                  </li>
                ))}
              </ul>
            </div>
            <div className="result">
              <h2>Overall Score</h2>
              <p><strong>Score:</strong> {results.score}</p>
            </div>
          </div>
        )}
      </div>
      <Router>
        <Routes>
          <Route path="/dashboard" element={<Dashboard />} />
        </Routes>
      </Router>
    </div>
  );
}

export default App;
