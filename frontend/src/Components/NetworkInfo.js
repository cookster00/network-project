import React from 'react';
import './NetworkInfo.css'; // Assuming you will add some CSS for styling

const tips = {
  'Anonymous FTP Access': ['Anonymous FTP access allows anyone to access your files without authentication.', 'Turn off guest access for file sharing to keep your files safe.', 'Require strong passwords for users', 'Use SFTP (Secure File Transfer Protocol) instead of FTP to encrypt data.'],
  'Exposed SMB Shares': ['Some shared files on your network can be accessed by unauthorized users.', 'Disable guest access and require strong passwords for users on the network', 'Look into SMB excryption to protect your data in transit.', 'If SMB is not needed, disable it in your settings.'],
  'DNS zone transfer misconfiguration': ['Improper DNS zone transfer configuration can expose your DNS records.', 'Configure DNS servers to restrict zone transfers to trusted servers.', 'Use DNSSEC to protect your DNS records from tampering.'],
  'SNMP misconfigurations': ['SNMP misconfigurations can allow unauthorized access to network devices and settings.', 'Look into your SNMP password and update it to be strong & unique.', 'Restrict SNMP access to trusted IP addresses.', 'Upgrade to SNMPv3 for more secure communication.'],
  'Outdated software and known vulnerabilities': ['Outdated software can have known vulnerabilities that can be exploited.', 'Regularly update softwares and apply security patches to protect your network.', 'Use a vulnerability scanner to identify and fix security issues proactively.', 'Disable or uninstall unused services.', 'Use a firewall to block unnecessary open ports.'],
};

const generalTip = 'Your network is safe!\n\nHere are some general tips: Keep your software updated, use strong passwords, and regularly monitor your network for suspicious activity.';

const NetworkInfo = ({ selectedNetwork, scanStatusMessages, vulnerabilities }) => {
  const getTips = () => {
    const redCards = vulnerabilities;
    if (redCards.length > 0) {
      return (
        <div>
          <p>Looks like we found some risks on your network! Here is a description of the risks plus a couple of tips to help mitigate them.</p>
          <br />
          <br />
          {redCards.map((vuln, index) => (
            <div key={index} style={{ marginBottom: '20px' }}>
              <strong>{vuln.title}</strong>
              <p>{tips[vuln.title][0]}</p> {/* Display the first item as the description */}
              <ul>
                {tips[vuln.title].slice(1).map((tip, tipIndex) => ( /* Display the remaining items as bullet points */
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