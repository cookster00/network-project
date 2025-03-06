import React, { useState } from 'react';
import axios from 'axios';
import Navbar from './Components/Navbar';
import NetworkInfo from './Components/NetworkInfo';
import VulnerabilityList from './Components/VulnerabilityList';
import './App.css';

function App() {
  const [ipAddress, setIpAddress] = useState('');
  const [results, setResults] = useState(null);
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
      setResults(response.data.results);
      setScanCompleted(true);
    } catch (error) {
      console.error(error);
      setError('An error occurred while scanning. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const formatVulnerabilityData = (title, result) => {
    return {
      title,
      description: result[1],
      level: result[0] ? 'high' : 'low'
    };
  };

  return (
    <div className="App">
      <Navbar />
      <div className="content">
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
      </div>
      <NetworkInfo selectedNetwork={ipAddress} />
      <VulnerabilityList vulnerabilities={results ? [
        formatVulnerabilityData('FTP Scan', results.ftp),
        formatVulnerabilityData('SMB Scan', results.smb),
        formatVulnerabilityData('DNS Scan', results.dns),
        formatVulnerabilityData('SNMP Scan', results.snmp),
        ...results.vulns[1]
      ] : []} />
    </div>
  );
}

export default App;
