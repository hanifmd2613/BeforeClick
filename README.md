# beforeClick - Phishing Risk Analysis Tool

## 🔍 Project Overview

**beforeClick** is a comprehensive web-based tool designed to analyze potential phishing threats by examining URLs, website behavior, SSL certificates, and other security indicators. It generates a phishing risk score to help users make informed decisions before interacting with websites.

## 🎯 Problem Statement

Fake websites mimic banks, companies, and portals to steal user credentials. This tool helps students and security professionals:
- Analyze URLs for phishing characteristics
- Check website permissions requests
- Examine SSL/TLS certificate authenticity
- Scan cookies for tracking and malicious behavior
- Review terms & conditions for suspicious clauses

## 📋 Features

### 1. **Action Type Analysis** ⚡
- Input website URL for security assessment
- Select the type of action the website requests:
  - Share OTP / Credentials
  - Request Permission
  - Grant Permission
  - Financial Transaction
  - File Upload
  - Account Verification
  - Payment Information
- Add optional notes about suspicious behavior
- Get risk score and recommendations

### 2. **Permissions Analysis** 🔐
- Check what permissions websites are requesting
- Analyze risk levels for:
  - 📷 Camera Access
  - 🎤 Microphone Access
  - 📍 Location Access
  - 📁 File Access
  - 👥 Contacts Access
  - 📋 Clipboard Access
  - 🔔 Notification Access
  - 💾 Storage Access
- Detailed risk assessment for each permission

### 3. **Cookies Analysis** 🍪
- Paste cookie data from browser developer tools
- Detect:
  - Tracking cookies
  - Sensitive authentication data
  - Cross-site tracking capabilities
  - Excessive cookie usage
- Risk scoring for privacy concerns

### 4. **Terms & Conditions Scanning** 📋
- Input website URL for T&C location
- Paste full T&C document text
- Scan for suspicious clauses:
  - Data harvesting keywords
  - Liability waivers
  - Terms change notifications
  - Automatic recurring charges
- Flag unreasonable or missing policies

### 5. **SSL Certificate Analysis** 🔒
- Verify HTTPS connection status
- Input SSL certificate data for deep analysis
- Check for:
  - Expired certificates
  - Self-signed certificates
  - Domain mismatches
  - Weak encryption protocols
  - Certificate Authority validation
- TLS version verification

## 🎨 Unique Header Design

The application features:
- **Animated Logo**: Pulsing search icon in header
- **Gradient Background**: Modern purple-to-pink gradient
- **Real-time Risk Meter**: Live risk percentage display
- **Wave Animation**: Smooth CSS wave transition from header
- **Responsive Layout**: Adapts to all screen sizes

## 📊 Overall Risk Dashboard

- **Visual Risk Circle**: Animated SVG circle showing overall phishing risk
- **Risk Summary**: Quick stats on threat levels and recommendations
- **Color-Coded Indicators**: 
  - 🟢 Green (0-30%): Low Risk
  - 🟡 Yellow (31-60%): Medium Risk
  - 🔴 Red (61-100%): High Risk

## 🚀 Getting Started

### Prerequisites
- Any modern web browser (Chrome, Firefox, Safari, Edge)
- No installation or dependencies required
- Works offline

### Installation

1. **Clone or Download** the project files to your machine
2. **Open** `index.html` in your web browser
3. **Start analyzing** websites for phishing risks

### File Structure
```
beforeClick/
├── index.html      # Main HTML structure
├── styles.css      # All styling and animations
├── script.js       # Analysis logic and interactivity
└── README.md       # This file
```

## 📖 Usage Guide

### Step 1: Select Analysis Type
Click on one of the 5 tab buttons at the top:
- ⚡ Action Type
- 🔐 Permissions
- 🍪 Cookies
- 📋 Terms & Conditions
- 🔒 SSL Data

### Step 2: Input Website Information
Each tab requires different information:
- **URLs**: Full website address (e.g., https://example.com)
- **Text Data**: Cookie data, T&C text, certificate details

### Step 3: Select/Configure Options
Depending on the tab:
- Choose action types
- Check permission boxes
- Paste text data

### Step 4: Run Analysis
Click "Analyze [Section]" to generate risk assessment

### Step 5: Review Results
- View detailed risk breakdown
- Check threat classifications
- Read recommendations
- Monitor overall risk score

## 🔐 Risk Scoring Algorithm

### Risk Factors by Category

**Action Type (0-100)**
- Share OTP/Credentials: 85
- Financial Transaction: 90
- Payment Info: 95

**Permissions (High Risk)**
- Camera/Files: 85 points
- Microphone: 80 points
- Location/Contacts: 75/70 points

**Cookies**
- Tracking cookies: +45
- Sensitive data: +35
- Cross-site tracking: +30

**Terms & Conditions**
- Suspicious keywords: +10 each
- Data harvesting clauses: +15
- No refund policy: +20

**SSL Certificate**
- No HTTPS: 95
- Expired: 95
- Self-signed: 90
- Domain mismatch: 85

## 🎓 Educational Value

Perfect for:
- Cybersecurity students learning threat detection
- Information security training
- User awareness programs
- Security audits and assessments
- Personal digital safety

## 💡 Key Indicators of Phishing Websites

### URL Red Flags
- Not starting with HTTPS
- Using IP address instead of domain name
- Shortened URLs (bit.ly, tinyurl)
- Misspelled domains (amaZon.com vs amazon.com)

### Permission Red Flags
- Excessive permission requests
- Unusual permissions for service type
- Camera/Microphone access for non-media services

### SSL Red Flags
- Expired certificates
- Self-signed certificates
- Domain name mismatches
- Weak encryption (SSL 3.0, TLS 1.0)

### Behavioral Red Flags
- Urgent action required messages
- Requests for passwords or OTPs
- Suspicious T&C clauses
- Data harvesting keywords

## 🛡️ Best Practices

1. **Always Check HTTPS**: Ensure websites use secure HTTPS connection
2. **Verify Domain**: Compare with official website domain
3. **Review Permissions**: Be skeptical of unusual permission requests
4. **Read Terms**: Actually read T&C for suspicious language
5. **Check SSL Certificate**: Click the padlock icon to verify certificate
6. **Use Tools**: Use beforeClick to cross-verify suspicious websites
7. **Trust Your Instincts**: If something feels off, it probably is

## 🔄 Reset Functionality

Click "Reset All Analysis" to:
- Clear all input fields
- Hide all results
- Reset risk scores to 0%
- Return to home tab
- Start fresh analysis

## 📱 Responsive Design

The application works seamlessly on:
- 🖥️ Desktop computers
- 💻 Laptops
- 📱 Tablets
- 📱 Mobile phones

All features are touch-friendly and mobile-optimized.

## 🎨 Design Features

- **Modern Gradient UI**: Purple to pink color scheme
- **Smooth Animations**: Fade-in transitions and hover effects
- **Icon Integration**: Emoji icons for visual hierarchy
- **Accessible Design**: High contrast, readable fonts
- **Dark Mode Ready**: Can be easily extended
- **Clean Typography**: Professional sans-serif fonts

## 🚀 Future Enhancements

Potential additions:
- Live API integration with VirusTotal
- Real-time SSL certificate checking
- Database of known phishing domains
- Machine learning phishing detection
- Browser extension version
- Mobile app version
- Multi-language support
- Advanced threat intelligence feeds

## 📝 Technical Stack

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Architecture**: Single-page application (SPA)
- **Styling**: Custom CSS with gradients and animations
- **Interactivity**: Vanilla JavaScript (no frameworks)
- **Graphics**: SVG for risk circle visualization

## 🤝 Contributing

To improve beforeClick:
1. Test with various phishing scenarios
2. Report bugs and suggest features
3. Improve threat detection algorithms
4. Enhance UI/UX design
5. Add more language support

## ⚖️ Legal Disclaimer

This tool is designed for educational and security research purposes. Always:
- Verify information from official sources
- Contact organizations directly for verification
- Report phishing sites to appropriate authorities
- Use responsibly and ethically
- Do not use for unauthorized website analysis

## 📞 Support & Contact

For questions, suggestions, or security concerns:
- Review the code and contribute improvements
- Share feedback on detection algorithms
- Test with real-world phishing examples
- Report false positives/negatives

## 📄 License

This project is open-source and available for educational use.

---

### Stay Safe Online! 🔒

Remember: **Before you click**, check with **beforeClick**!

---

**Version**: 1.0  
**Last Updated**: February 2026  
**Created for**: Cybersecurity Education & Phishing Detection
