import React, { useState } from 'react';
import Navbar from '../Components/Navbar';
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
      <Navbar onNewScan={handleNewScan} />
      <NetworkInfo selectedNetwork={selectedNetwork} />
      <VulnerabilityList />
      {/* Rest of the dashboard content */}
    </div>
  );
};

export default Dashboard;