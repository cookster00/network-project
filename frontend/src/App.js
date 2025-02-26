import React, { useState } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Dashboard from './Pages/Dashboard';

import './App.css';

function App() {
  const [ipAddress, setIpAddress] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanCompleted, setScanCompleted] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    setError(null);

    try {
      // Send a request to the backend to perform the scan
      const response = await axios.post('/scan', { ip: ipAddress });
      console.log(response.data);
      setLoading(false);
      setResults(response.data.results);
      setScanCompleted(true);
    } catch (error) {
      console.error(error);
      setLoading(false);
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
        {scanCompleted && results.map((result, index) => (
          <div key={index} className="result">
            <p><strong>Host:</strong> {result.host}</p>
            <p><strong>State:</strong> {result.state}</p>
            {result.protocols.map((protocol, protoIndex) => (
              <div key={protoIndex} className="protocol">
                <p><strong>Protocol:</strong> {protocol.protocol}</p>
                <ul>
                  {protocol.ports.map((port, portIndex) => (
                    <li key={portIndex}>
                      <strong>Port:</strong> {port.port}, <strong>State:</strong> {port.state}, <strong>Service:</strong> {port.service}, <strong>Version:</strong> {port.version}
                      {port.vulnerabilities && Object.keys(port.vulnerabilities).length > 0 && (
                        <ul>
                          {Object.keys(port.vulnerabilities).map((vulnKey, vulnIndex) => (
                            <li key={vulnIndex}>
                              <strong>{vulnKey}:</strong> {port.vulnerabilities[vulnKey].title}
                              <p>{port.vulnerabilities[vulnKey].description}</p>
                              <a href={port.vulnerabilities[vulnKey].references[0]} target="_blank" rel="noopener noreferrer">More Info</a>
                            </li>
                          ))}
                        </ul>
                      )}
                      {port.smb_os_discovery && (
                        <div>
                          <strong>SMB OS Discovery:</strong>
                          <pre>{JSON.stringify(port.smb_os_discovery, null, 2)}</pre>
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        ))}
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
