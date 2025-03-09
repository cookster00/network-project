import React, { useState } from 'react';
import axios from 'axios';
import Navbar from './Components/Navbar';
import NetworkInfo from './Components/NetworkInfo';
import VulnerabilityList from './Components/VulnerabilityList';
import './App.css';

const formatVulnerabilityData = (title, result) => {
  let level = 'low';
  const vulnerabilities = result[1];

  if (Array.isArray(vulnerabilities)) {
    const nonEmptyVulns = vulnerabilities.filter(vuln => vuln.vulnerabilities !== 'No vulnerabilities found.');
    if (nonEmptyVulns.length >= 2) {
      level = 'high';
    } else if (nonEmptyVulns.length === 1) {
      level = 'medium';
    }
  }

  return {
    title,
    description: Array.isArray(vulnerabilities) ? vulnerabilities.map(vuln => `${vuln.port}: ${vuln.vulnerabilities}`).join('\n') : vulnerabilities,
    level
  };
};

function App() {
  const [ipAddress, setIpAddress] = useState('');
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
        {scanCompleted && results && (
          <div className="score-visualization">
            <h2>Network Security Score</h2>
            <p>{results.score}</p>
          </div>
        )}
      </div>
      <NetworkInfo selectedNetwork={ipAddress} scanStatusMessages={scanStatusMessages} vulnerabilities={results ? [
        formatVulnerabilityData('Anonymous FTP Access', results.ftp),
        formatVulnerabilityData('Exposed SMB Shares', results.smb),
        formatVulnerabilityData('DNS zone transfer misconfiguration', results.dns),
        formatVulnerabilityData('SNMP misconfigurations', results.snmp),
        formatVulnerabilityData('Outdated software and known vulnerabilities', results.vulns)
      ] : []} />
      <VulnerabilityList vulnerabilities={results ? [
        formatVulnerabilityData('Anonymous FTP Access', results.ftp),
        formatVulnerabilityData('Exposed SMB Shares', results.smb),
        formatVulnerabilityData('DNS zone transfer misconfiguration', results.dns),
        formatVulnerabilityData('SNMP misconfigurations', results.snmp),
        formatVulnerabilityData('Outdated software and known vulnerabilities', results.vulns)
      ] : []} />
    </div>
  );
}

export default App;