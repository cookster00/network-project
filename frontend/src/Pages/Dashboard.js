import React, { useState } from 'react';
import Navbar from '../Components/Navbar';

const Dashboard = () => {
  const [networks, setNetworks] = useState([
    { name: 'Home Wi-Fi', status: 'secure' },
    { name: 'Office Network', status: 'high-risk' },
    { name: 'Public Wi-Fi', status: 'secure' }
  ]);
  const [selectedNetwork, setSelectedNetwork] = useState(networks[0].name);

  const handleSelectNetwork = (networkName) => {
    setSelectedNetwork(networkName);
  };

  const handleAddNetwork = () => {
    const newNetworkName = prompt('Enter new network name:');
    if (newNetworkName) {
      setNetworks([...networks, { name: newNetworkName, status: 'secure' }]);
    }
  };

  return (
    <div>
      <Navbar
        networks={networks}
        selectedNetwork={selectedNetwork}
        onSelectNetwork={handleSelectNetwork}
        onAddNetwork={handleAddNetwork}
      />
      {/* Rest of the dashboard content */}
    </div>
  );
};

export default Dashboard;