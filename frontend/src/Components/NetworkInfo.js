import React from 'react';
import './NetworkInfo.css'; // Assuming you will add some CSS for styling

const NetworkInfo = ({ selectedNetwork }) => {
  // Placeholder data
  const networkInfo = {
    name: selectedNetwork,
    type: 'Wi-Fi',
    totalDevices: 12,
    ipAddress: '192.168.1.1'
  };

  return (
    <div className="network-info">
      <h2>Network Information</h2>
      <p><strong>Network Name:</strong> {networkInfo.name}</p>
      <p><strong>Network Type:</strong> {networkInfo.type}</p>
      <p><strong>Total Devices Connected:</strong> {networkInfo.totalDevices}</p>
      <p><strong>IP Address:</strong> {networkInfo.ipAddress}</p>
    </div>
  );
};

export default NetworkInfo;