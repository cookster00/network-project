import React, { useState, useEffect } from 'react';
import axios from 'axios';
import logo from './logo.svg';
import './App.css';

function App() {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

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
      })
      .catch(error => {
        console.error(error);
        setLoading(false);
        setError('An error occurred while scanning. Please try again.');
      });
  };

  return (
    <div>
      <h1>Network Vulnerability Scanner</h1>
      <button onClick={handleScan} disabled={loading}>
        {loading ? 'Scanning...' : 'Start Scan'}
      </button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <div>
        {results.map((result, index) => (
          <div key={index}>
            <p>Host: {result.host}</p>
            <p>State: {result.state}</p>
            <p>Protocols: {result.protocols.join(', ')}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;
