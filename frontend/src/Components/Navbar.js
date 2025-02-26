import React from 'react';
import './Navbar.css'; // Assuming you will add some CSS for styling

const Navbar = ({ onNewScan }) => {
  return (
    <nav className="navbar">
      {/* Left Section - Branding & Logo */}
      <div className="navbar-left" onClick={() => window.location.href = '/'}>
        <span className="navbar-logo">🔒</span> {/* Replace with a lock emoji or any other symbol */}
        <span className="navbar-brand">NetScan</span>
      </div>

      {/* Right Section - New Scan Button */}
      <div className="navbar-right">
        <button className="new-scan-button" onClick={onNewScan}>
          ➕ New Scan {/* Replace with a plus emoji or any other symbol */}
        </button>
      </div>
    </nav>
  );
};

export default Navbar;