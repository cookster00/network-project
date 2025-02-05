import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Dashboard from '../Pages/Dashboard';
import './App.css';

function App() {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanCompleted, setScanCompleted] = useState(false);

  useEffect(() => {
    axios.get('/results')
      .then(response => setResults(response.data))
      .catch(error => {
        console.error(error);
        setError('Failed to load results.');
      });
  }, []);

  const handleScan = () => {
    setLoading(true);
    setError(null);
    axios.post('/scan')
      .then(response => {
        console.log(response.data);
        setLoading(false);
        setResults(response.data.results);
        setScanCompleted(true);
      })
      .catch(error => {
        console.error(error);
        setLoading(false);
        setError('An error occurred while scanning. Please try again.');
      });
  };

  return (
    <Router>
      <Routes>
        <Route path="/" element={
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
        } />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </Router>
  );
}

export default App;
