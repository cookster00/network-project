import React from 'react';
import './Navbar.css'; // Assuming you will add some CSS for styling

const Navbar = () => {
  return (
    <nav className="navbar">
      {/* Left Section - Branding & Logo */}
      <div className="navbar-left" onClick={() => window.location.href = '/'}>
        <span className="navbar-logo">🔒</span> {/* Replace with a lock emoji or any other symbol */}
        <span className="navbar-brand">NetScan</span>
      </div>
    </nav>
  );
};

export default Navbar;