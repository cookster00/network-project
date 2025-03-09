import React from 'react';
import './NetworkInfo.css'; // Assuming you will add some CSS for styling

const tips = {
  'Anonymous FTP Access': 'Turn off guest access for file sharing to keep your files safe.',
  'Exposed SMB Shares': 'Make sure only trusted people can access shared files on your network.',
  'DNS zone transfer misconfiguration': 'Configure DNS servers to restrict zone transfers to trusted IP addresses.',
  'SNMP misconfigurations': 'Disable SNMP or configure it securely to prevent unauthorized access.',
  'Outdated software and known vulnerabilities': 'Regularly update software to patch known vulnerabilities.'
};

const generalTip = 'Your network is safe. Here are some general tips: Keep your software updated, use strong passwords, and regularly monitor your network for suspicious activity.';

const NetworkInfo = ({ selectedNetwork, scanStatusMessages, vulnerabilities }) => {
  const getTips = () => {
    const redCards = vulnerabilities.filter(vuln => vuln.level === 'high');
    if (redCards.length > 0) {
      return redCards.map((vuln, index) => (
        <p key={index}>{tips[vuln.title]}</p>
      ));
    } else {
      return <p>{generalTip}</p>;
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
        <h2>Tips</h2>
        {getTips()}
      </div>
    </div>
  );
};

export default NetworkInfo;