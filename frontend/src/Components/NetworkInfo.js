import React from 'react';
import './NetworkInfo.css'; // Assuming you will add some CSS for styling

const tips = {
  'Anonymous FTP Access': ['Turn off guest access for file sharing to keep your files safe.', 'Require strong passwords for users', 'Use SFTP (Secure File Transfer Protocol) instead of FTP to encrypt data.'],
  'Exposed SMB Shares': ['Make sure only trusted people can access shared files on your network.'],
  'DNS zone transfer misconfiguration': ['Configure DNS servers to restrict zone transfers to trusted IP addresses.'],
  'SNMP misconfigurations': ['Disable SNMP or configure it securely to prevent unauthorized access.'],
  'Outdated software and known vulnerabilities': ['Regularly update software to patch known vulnerabilities.']
};

const generalTip = 'Your network is safe!\n\nHere are some general tips: Keep your software updated, use strong passwords, and regularly monitor your network for suspicious activity.';

const NetworkInfo = ({ selectedNetwork, scanStatusMessages, vulnerabilities }) => {
  const getTips = () => {
    const redCards = vulnerabilities;
    if (redCards.length > 0) {
      return (
        <div>
          <p>Looks like we found some risks on your network! Here are a couple of tips to help.</p>
          <br />
          <br />
          {redCards.map((vuln, index) => (
            <div key={index} style={{ marginBottom: '20px' }}>
              <strong>{vuln.title}</strong>
              <ul>
                {tips[vuln.title].map((tip, tipIndex) => (
                  <li key={tipIndex}>{tip}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      );
    } else {
      return <p style={{ whiteSpace: 'pre-line' }}>{generalTip}</p>;
    }
  };

  return (
    <div className="network-info-container">
      <div className="network-info">
        <h2>Scan Terminal</h2>
        <div className="scan-status-messages">
          {scanStatusMessages.map((message, index) => (
            <p key={index}>{message}</p>
          ))}
        </div>
      </div>
      <div className="separator-line"></div>
      <div className="tips-section">
        <h2>Security Improvement Tips</h2>
        {vulnerabilities && vulnerabilities.length > 0 ? getTips() : null}
      </div>
    </div>
  );
};

export default NetworkInfo;