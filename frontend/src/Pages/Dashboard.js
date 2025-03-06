import React, { useState } from 'react';
import NetworkInfo from '../Components/NetworkInfo';
import VulnerabilityList from '../Components/VulnerabilityList';

const Dashboard = () => {
  const [selectedNetwork, setSelectedNetwork] = useState('Home Wi-Fi');

  const handleNewScan = () => {
    const newNetworkIP = prompt('Enter new network IP address:');
    if (newNetworkIP) {
      setSelectedNetwork(newNetworkIP);
      // Trigger the scan here if needed
    }
  };

  return (
    <div>
      <NetworkInfo selectedNetwork={selectedNetwork} />
      <VulnerabilityList />
      {/* Rest of the dashboard content */}
    </div>
  );
};

export default Dashboard;