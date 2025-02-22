import React, { useState, useEffect } from 'react';
import axios from 'axios';
import logo from './logo.svg';
import './App.css';

function App() {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanCompleted, setScanCompleted] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    setError(null);

    try {
      // Get the client's IP address
      const ipResponse = await axios.get('https://api.ipify.org?format=json');
      const clientIp = ipResponse.data.ip;
    
      // Send the IP address to the backend
      const response = await axios.post('/scan', { ip: clientIp });
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
    <div>
      <h1>Network Vulnerability Scanner</h1>
      <button onClick={handleScan} disabled={loading}>
        {loading ? 'Scanning...' : 'Start Scan'}
      </button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <div>
        {scanCompleted && results.map((result, index) => (
          <div key={index}>
            <p>Host: {result.host}</p>
            <p>State: {result.state}</p>
            {result.protocols.map((protocol, protoIndex) => (
              <div key={protoIndex}>
                <p>Protocol: {protocol.protocol}</p>
                <ul>
                  {protocol.ports.map((port, portIndex) => (
                    <li key={portIndex}>
                      Port: {port.port}, State: {port.state}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;
