import React from 'react';
import { FaShieldAlt, FaWifi, FaPlus } from 'react-icons/fa';
import './Navbar.css'; // Assuming you will add some CSS for styling

const Navbar = ({ networks, selectedNetwork, onSelectNetwork, onAddNetwork }) => {
  return (
    <nav className="navbar">
      {/* Left Section - Branding & Logo */}
      <div className="navbar-left" onClick={() => window.location.href = '/'}>
        <FaShieldAlt className="navbar-logo" />
        <span className="navbar-brand">NetScan</span>
      </div>

      {/* Middle Section - Network Selection Dropdown */}
      <div className="navbar-middle">
        <select
          className="network-dropdown"
          value={selectedNetwork}
          onChange={(e) => onSelectNetwork(e.target.value)}
        >
          {networks.map((network, index) => (
            <option key={index} value={network.name}>
              {network.name} {network.status === 'high-risk' ? '🔴' : '🟢'}
            </option>
          ))}
          <option value="add-new" onClick={onAddNetwork}>
            <FaPlus /> Add New Network
          </option>
        </select>
      </div>
    </nav>
  );
};

export default Navbar;