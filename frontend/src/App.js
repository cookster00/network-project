import React, { useState } from 'react';
import axios from 'axios';
import Navbar from './Components/Navbar';
import NetworkInfo from './Components/NetworkInfo';
import VulnerabilityList from './Components/VulnerabilityList';
import './App.css';

function App() {
  const [ipAddress, setIpAddress] = useState('');
  const [scanInfo, setScanInfo] = useState(null);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanCompleted, setScanCompleted] = useState(false);
  const [scanStatusMessages, setScanStatusMessages] = useState([]);

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    setScanStatusMessages(['Starting scan...']);
    let localScanInfo = {};

    try {
      const updateScanStatus = (message) => {
        setScanStatusMessages((prevMessages) => [...prevMessages, message]);
      };

      updateScanStatus('Scanning for Anonymous FTP Access...');
      const ftpResponse = await axios.post('/ftp_scan', { ip: ipAddress });
      localScanInfo.ftp = ftpResponse.data.results;

      updateScanStatus('Scanning for Exposed SMB Shares...');
      const smbResponse = await axios.post('/smb_scan', { ip: ipAddress });
      localScanInfo.smb = smbResponse.data.results;

      updateScanStatus('Scanning for DNS zone transfer misconfiguration...');
      const dnsResponse = await axios.post('/dns_scan', { ip: ipAddress });
      localScanInfo.dns = dnsResponse.data.results;

      updateScanStatus('Scanning for outdated software and known vulnerabilities...');
      const vulnsResponse = await axios.post('/vulns_scan', { ip: ipAddress });
      localScanInfo.vulns = vulnsResponse.data.results;

      updateScanStatus('Scanning for SNMP misconfigurations...');
      const snmpResponse = await axios.post('/snmp_scan', { ip: ipAddress });
      localScanInfo.snmp = snmpResponse.data.results;

      updateScanStatus('Scanning for open ports...');
      const portsResponse = await axios.post('/port_scan', { ip: ipAddress });
      localScanInfo.ports = portsResponse.data.results;

      setScanInfo(localScanInfo);

      updateScanStatus('Calculating security score...');
      const scoreResponse = await axios.post('/get_score', {
        ftp: localScanInfo.ftp,
        smb: localScanInfo.smb,
        dns: localScanInfo.dns,
        vulns: localScanInfo.vulns,
        snmp: localScanInfo.snmp
      });
      setResults({ ...localScanInfo, score: scoreResponse.data.score });

      console.log('Scan Results:', {
        ftp: ftpResponse.data.results,
        smb: smbResponse.data.results,
        dns: dnsResponse.data.results,
        vulns: vulnsResponse.data.results,
        snmp: snmpResponse.data.results,
        ports: portsResponse.data.results,
        score: scoreResponse.data.score
      });

      setScanCompleted(true);
      updateScanStatus('Scan complete');
    } catch (error) {
      console.error(error);
      setError('An error occurred while scanning. Please try again.');
      const updateScanStatus = (message) => {
        setScanStatusMessages((prevMessages) => [...prevMessages, message]);
      };

      updateScanStatus('Scan failed');
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
      <NetworkInfo selectedNetwork={ipAddress} scanStatusMessages={scanStatusMessages} />
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
