import React from 'react';
import './NetworkInfo.css'; // Assuming you will add some CSS for styling

const NetworkInfo = ({ selectedNetwork, scanStatusMessages }) => {
  // Placeholder data
  const networkInfo = {
    name: selectedNetwork,
    type: 'Wi-Fi',
    totalDevices: 12,
    ipAddress: '192.168.1.1'
  };

  return (
    <div className="network-info">
      <h2>Scan Terminal</h2>
      <div className="scan-status-messages">
        {scanStatusMessages.map((message, index) => (
          <p key={index}>{message}</p>
        ))}
      </div>
    </div>
  );
};

export default NetworkInfo;