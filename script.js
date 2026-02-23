/* ============================================
   BEFORECLICK - PHISHING RISK ANALYZER
   JavaScript Logic & Analysis Engine
   ============================================ */

// VirusTotal API Configuration
const VIRUSTOTAL_API_KEY = '575b7a6a1ec38a1d3314140c07685d22ef39b984c5975b7e16f2bc6222d5ef14';

// Risk scoring thresholds
const RISK_THRESHOLDS = {
    low: { max: 30, label: 'Low Risk', color: '#10b981' },
    medium: { max: 60, label: 'Medium Risk', color: '#f59e0b' },
    high: { max: 100, label: 'High Risk', color: '#ef4444' }
};

// Phishing keywords and patterns
const PHISHING_PATTERNS = {
    urgency: ['verify', 'confirm', 'urgent', 'immediately', 'act now', 'click here', 'expire', 'validate', 'reactivate'],
    financial: ['payment', 'credit card', 'bank', 'account', 'fund', 'transaction', 'wire', 'transfer'],
    permission: ['allow', 'grant', 'enable', 'access', 'permission', 'authorize'],
    suspicious: ['click', 'confirm', 'authenticate', 'login', 'password', 'security code', 'otp', 'cvv', 'ssn']
};

// Permission risk scores
const PERMISSION_RISKS = {
    camera: { risk: 85, description: 'High risk - Could record video without consent' },
    microphone: { risk: 80, description: 'High risk - Could record audio without consent' },
    location: { risk: 75, description: 'High risk - Could track your location' },
    contacts: { risk: 70, description: 'High risk - Could access your contacts list' },
    files: { risk: 85, description: 'High risk - Could access sensitive files' },
    clipboard: { risk: 65, description: 'Medium-High risk - Could read copied data' },
    notifications: { risk: 40, description: 'Medium risk - Could spam notifications' },
    storage: { risk: 60, description: 'Medium risk - Could store tracking data' }
};

// Suspicious T&C keywords
const SUSPICIOUS_TC_KEYWORDS = {
    data_harvesting: ['collect', 'harvest', 'gather', 'monitor', 'track', 'sell', 'share', 'third party'],
    liability_waiver: ['liability', 'not responsible', 'no liability', 'use at own risk'],
    terms_changes: ['change', 'modify', 'update', 'without notice', 'at any time'],
    payment: ['automatically', 'recurring', 'charge', 'billing', 'subscription'],
};

// SSL risk factors
const SSL_RISK_FACTORS = {
    expired: { risk: 95, message: 'Certificate is expired - Critical security issue' },
    selfsigned: { risk: 90, message: 'Self-signed certificate - Not trusted' },
    mismatch: { risk: 85, message: 'Domain mismatch - Possible impersonation' },
    unsupported: { risk: 80, message: 'Unsupported SSL version - Security vulnerability' },
    weak: { risk: 70, message: 'Weak encryption - May be compromised' }
};

// ============================================
// VirusTotal API Functions
// ============================================

function toggleApiKeyVisibility() {
    const apiKeyInput = document.getElementById('virustotal-api-key');
    const btn = event.target;
    if (apiKeyInput.type === 'password') {
        apiKeyInput.type = 'text';
        btn.textContent = '🔒';
    } else {
        apiKeyInput.type = 'password';
        btn.textContent = '👁️';
    }
}

async function checkURLWithVirusTotal(url) {
    const apiKeyInput = document.getElementById('virustotal-api-key').value;
    const apiKey = apiKeyInput || VIRUSTOTAL_API_KEY;
    
    if (!apiKey) {
        console.log('VirusTotal API key not set. Skipping API check.');
        return null;
    }

    try {
        // Create a hash from the URL for VirusTotal (they use URL IDs)
        const urlId = btoa(url).replace(/[+/=]/g, m => ({'+':'-', '/':'_', '=':''}[m]));
        
        // Call VirusTotal API v3
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
                'Accept': 'application/json'
            }
        });

        if (response.status === 404) {
            // If URL not found, submit it for scanning
            return await submitURLToVirusTotal(url, apiKey);
        }

        if (!response.ok) {
            throw new Error(`API Error: ${response.status}`);
        }

        const data = await response.json();
        return parseVirusTotalResponse(data);
    } catch (error) {
        console.log('Error checking URL with VirusTotal:', error);
        return null;
    }
}

async function submitURLToVirusTotal(url, apiKey) {
    try {
        const formData = new FormData();
        formData.append('url', url);

        const response = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
                'Accept': 'application/json'
            },
            body: formData
        });

        if (!response.ok) {
            throw new Error('Failed to submit URL to VirusTotal');
        }

        const data = await response.json();
        return parseVirusTotalResponse(data);
    } catch (error) {
        console.log('Error submitting URL to VirusTotal:', error);
        return null;
    }
}

function parseVirusTotalResponse(data) {
    if (!data.data || !data.data.attributes) {
        return null;
    }

    const attributes = data.data.attributes;
    const stats = attributes.last_analysis_stats || {};
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const undetectedCount = stats.undetected || 0;

    // Calculate risk based on detection
    let riskScore = 0;
    if (maliciousCount > 0) {
        riskScore = Math.min(100, maliciousCount * 15);
    } else if (suspiciousCount > 0) {
        riskScore = Math.min(80, suspiciousCount * 10);
    }

    // Parse vendor details
    const results = attributes.last_analysis_results || {};
    const allVendors = [];
    const vendors = []; // For top vendors
    
    Object.entries(results).forEach(([vendorName, vendorData]) => {
        const vendor = {
            name: vendorName,
            category: vendorData.category,
            result: vendorData.result || vendorData.category
        };
        
        allVendors.push(vendor);
        
        // Add to top vendors if detected
        if (vendorData.category !== 'undetected') {
            vendors.push(vendor);
        }
    });

    // Sort vendors: malicious first, then suspicious
    vendors.sort((a, b) => {
        const categoryOrder = { malicious: 0, suspicious: 1, undetected: 2 };
        return categoryOrder[a.category] - categoryOrder[b.category];
    });

    // Limit to top vendors for highlighted display (but show all in allVendors)
    const topVendors = vendors.slice(0, 10);

    return {
        maliciousCount: maliciousCount,
        suspicious: suspiciousCount,
        suspiciousCount: suspiciousCount,
        undetected: undetectedCount,
        undetectedCount: undetectedCount,
        riskScore: riskScore,
        detectionRatio: `${maliciousCount + suspiciousCount}/${maliciousCount + suspiciousCount + undetectedCount}`,
        vendors: topVendors,
        allVendors: allVendors  // Include ALL vendors for detailed display
    };
}

// Tab switching functionality
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tabName = btn.getAttribute('data-tab');
        switchTab(tabName);
    });
});

function switchTab(tabName) {
    // Remove active class from all tabs and buttons
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Add active class to selected tab and button
    document.getElementById(tabName).classList.add('active');
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
}

/* ============================================
   RECOMMENDATION GENERATOR - Domain Age Based
   ============================================ */

function generateRecommendationsByDomainAge(actionType, domainResult, vtResult) {
    let recommendations = '';
    
    // Base recommendations by action type
    const actionRecommendations = {
        'share_otp': [
            '⚠️ CRITICAL: Never share OTP with anyone, not even bank staff',
            '🚨 WARNING: OTP sharing is a leading phishing technique. Legitimate services NEVER ask for OTP',
            '⛔ ALERT: This is a classic phishing indicator. Do NOT share your one-time password'
        ],
        'make_permission': [
            '⚠️ Verify the legitimacy before granting any permissions',
            '🔍 Check: Are you expecting this permission request? Be cautious of unsolicited requests',
            '⛔ ALERT: Permission requests can be used to steal data. Only grant necessary permissions'
        ],
        'grant_permission': [
            '⚠️ Check SSL certificate and website legitimacy before granting access',
            '🔍 Verify: Does the domain name match the official website?',
            '⛔ ALERT: Fake login pages mimic real sites. Always type URLs directly in your browser'
        ],
        'financial_transaction': [
            '🚨 CRITICAL: Verify the website URL matches the official domain before proceeding',
            '⚠️ CHECK: Look for HTTPS lock icon and verify SSL certificate',
            '💰 WARNING: Payment pages are prime targets for phishing attacks'
        ],
        'file_upload': [
            '⚠️ Be cautious before uploading personal files',
            '🔍 Verify: Is this a trusted and legitimate service?',
            '⛔ WARNING: File upload requests can be used to gather personal information'
        ],
        'account_verification': [
            '⚠️ Account verification requests are commonly used in phishing attacks',
            '🔍 Check: Did you initiate this verification request?',
            '⛔ ALERT: Legitimate services rarely ask you to reverify your account'
        ],
        'payment_info': [
            '🚨 CRITICAL: Never enter payment information on untrusted websites',
            '⚠️ CHECK: Payment pages must have HTTPS and valid SSL certificates',
            '💰 WARNING: Stolen payment information leads to identity theft'
        ]
    };

    // Get action-specific recommendation
    const baseRecs = actionRecommendations[actionType] || [
        '⚠️ Check website legitimacy before proceeding',
        '🔍 Verify SSL certificate and domain authenticity',
        '⛔ Be cautious of suspicious requests'
    ];
    
    // Select random recommendation from action type
    recommendations = baseRecs[Math.floor(Math.random() * baseRecs.length)];

    // Domain Age Analysis
    if (domainResult) {
        let domainAgeYears = 0;
        const createdDate = domainResult.createdDate || 'Unknown';
        const domainAge = domainResult.domainAge || 'Unknown';
        
        // Parse domain age from string like "28.4 years" or "2.5 years"
        if (typeof domainAge === 'string') {
            const match = domainAge.match(/[\d.]+/);
            if (match) {
                domainAgeYears = parseFloat(match[0]);
            }
        } else if (typeof domainAge === 'number') {
            domainAgeYears = domainAge;
        }
        
        recommendations += `\n\n📅 Domain Age Analysis:`;
        
        if (domainAgeYears < 0.5) {
            // Very new domain (< 6 months)
            const newDomainWarnings = [
                `⚠️ CRITICAL: This domain was registered only ${domainAgeYears.toFixed(1)} years ago! Very new domains have extremely high phishing risk.`,
                `🚨 RED FLAG: Domain created on ${createdDate} - less than 6 months old. This is a major phishing indicator.`,
                `⛔ DANGER: Brand new domain (${domainAgeYears.toFixed(2)} years). Scammers often create new domains for phishing campaigns.`
            ];
            recommendations += '\n' + newDomainWarnings[Math.floor(Math.random() * newDomainWarnings.length)];
        } else if (domainAgeYears < 1) {
            // Less than 1 year old
            const youngDomainWarnings = [
                `⚠️ WARNING: Domain is only ${domainAgeYears.toFixed(1)} years old. Relatively new domains should be approached with caution.`,
                `🔍 NOTICE: Created ${createdDate} - less than 1 year old. Verify this is a legitimate business before proceeding.`,
                `⛔ ALERT: Young domain (${domainAgeYears.toFixed(1)} years). Many phishing sites use newly registered domains.`
            ];
            recommendations += '\n' + youngDomainWarnings[Math.floor(Math.random() * youngDomainWarnings.length)];
        } else if (domainAgeYears < 2) {
            // 1-2 years old
            const moderateWarnings = [
                `ℹ️ INFO: Domain is ${domainAgeYears.toFixed(1)} years old. Relatively new but not immediate red flag.`,
                `🔍 CAUTION: Registered ${createdDate} - 1-2 years old. Still within risky period for phishing domains.`,
                `⚠️ NOTICE: Domain age ${domainAgeYears.toFixed(1)} years - moderately new. Continue with caution.`
            ];
            recommendations += '\n' + moderateWarnings[Math.floor(Math.random() * moderateWarnings.length)];
        } else if (domainAgeYears < 5) {
            // 2-5 years old
            const establishedWarnings = [
                `✓ POSITIVE: Domain is ${domainAgeYears.toFixed(1)} years old - reasonably established. Lower phishing risk.`,
                `🟢 GOOD: Registered ${createdDate} - established domain with ${domainAgeYears.toFixed(0)}+ years history.`,
                `ℹ️ NOTE: Domain age ${domainAgeYears.toFixed(1)} years - suggests legitimate operation.`
            ];
            recommendations += '\n' + establishedWarnings[Math.floor(Math.random() * establishedWarnings.length)];
        } else {
            // 5+ years old
            const oldDomainPositive = [
                `✓ POSITIVE: Domain is ${domainAgeYears.toFixed(1)} years old - well-established with long history.`,
                `🟢 GOOD SIGN: This domain has been registered since ${createdDate}. Strong legitimacy indicator.`,
                `✅ TRUSTWORTHY: ${domainAgeYears.toFixed(0)}+ year-old domain suggests a legitimate, established business.`
            ];
            recommendations += '\n' + oldDomainPositive[Math.floor(Math.random() * oldDomainPositive.length)];
        }
    }

    // VirusTotal Results
    if (vtResult) {
        const detectionCount = vtResult.maliciousCount + vtResult.suspiciousCount;
        recommendations += `\n\n🔍 VirusTotal Security Scan:`;
        
        if (detectionCount === 0) {
            const cleanResults = [
                `✓ CLEAN: No threats detected by any of the ${vtResult.allVendors ? vtResult.allVendors.length : '60'}+ security vendors`,
                `🟢 SAFE: ${vtResult.detectionRatio} - All vendors agree this URL is clean`,
                `✅ VERIFIED: No malicious detections across major security engines`
            ];
            recommendations += '\n' + cleanResults[Math.floor(Math.random() * cleanResults.length)];
        } else if (detectionCount <= 3) {
            const minorThreats = [
                `⚠️ CAUTION: ${vtResult.detectionRatio} - ${detectionCount} vendor(s) flagged this URL. Investigate before proceeding.`,
                `🔍 NOTICE: ${detectionCount} security engine(s) detected issues. Proceed with extra caution.`,
                `⛔ WARNING: Minor threats detected (${vtResult.detectionRatio}). Further investigation recommended.`
            ];
            recommendations += '\n' + minorThreats[Math.floor(Math.random() * minorThreats.length)];
        } else {
            const majorThreats = [
                `🚨 CRITICAL: ${vtResult.detectionRatio} - ${detectionCount} vendors flagged malicious/suspicious activity!`,
                `⛔ DANGER: Multiple threats detected (${vtResult.detectionRatio}). DO NOT interact with this website.`,
                `🔴 RED ALERT: ${detectionCount} security vendors flagged this URL. AVOID immediately!`
            ];
            recommendations += '\n' + majorThreats[Math.floor(Math.random() * majorThreats.length)];
        }
    }

    // Final action
    const finalActions = [
        `\n\n✋ ACTION: If you received an unexpected request, DO NOT proceed. Contact the official service directly.`,
        `\n\n🛡️ RECOMMENDATION: If in doubt, visit the official website by typing the URL directly (not clicking links).`,
        `\n\n💡 BEST PRACTICE: Never enter sensitive information on unfamiliar websites. Always verify the URL.`
    ];
    recommendations += finalActions[Math.floor(Math.random() * finalActions.length)];

    return recommendations;
}

/* ============================================
   ACTION TYPE ANALYSIS
   ============================================ */

// Form submission will be attached in DOMContentLoaded

function analyzeActionType() {
    console.log('✅ Analyze Action Type clicked!');
    
    const url = document.getElementById('action-url').value;
    const actionType = document.getElementById('action-select').value;
    const notes = document.getElementById('action-notes').value;

    console.log('URL:', url);
    console.log('Action Type:', actionType);
    console.log('Notes:', notes);

    if (!url || !actionType) {
        alert('Please enter URL and select an action type');
        return;
    }

    let riskScore = 0;

    // Base risk for different action types
    const actionTypeRisks = {
        'share_otp': 85,
        'make_permission': 75,
        'grant_permission': 80,
        'financial_transaction': 90,
        'file_upload': 70,
        'account_verification': 80,
        'payment_info': 95
    };

    riskScore = actionTypeRisks[actionType] || 50;

    // Adjust based on URL analysis
    riskScore += analyzeURL(url);

    // Adjust based on notes
    if (notes) {
        riskScore += analyzeText(notes);
    }

    // Cap risk score at 100
    riskScore = Math.min(riskScore, 100);

    console.log('Base risk score:', riskScore);

    // Check with VirusTotal API and Domain Age simultaneously
    Promise.all([
        checkURLWithVirusTotal(url),
        checkDomainAge(url)
    ]).then(([vtResult, domainResult]) => {
        console.log('API results received - VT:', vtResult, 'Domain:', domainResult);
        
        if (vtResult && vtResult.riskScore > riskScore) {
            riskScore = vtResult.riskScore;
        }

        // Add domain age risk to overall risk
        if (domainResult && domainResult.riskScore) {
            const domainRiskWeight = domainResult.riskScore * 0.3; // Domain age contributes 30% to risk
            riskScore = Math.min(100, (riskScore * 0.7) + domainRiskWeight);
        }

        // Add random variation to risk score for realistic variance
        // Variation range depends on domain age and VirusTotal results
        let riskVariation = 0;
        if (domainResult) {
            // Extract domain age in years
            const domainAgeStr = domainResult.domainAge || '0';
            const domainAgeMatch = domainAgeStr.match(/[\d.]+/);
            const domainAgeYears = domainAgeMatch ? parseFloat(domainAgeMatch[0]) : 0;
            
            // New domains (< 1 year) get +5-15% random variation
            if (domainAgeYears < 1) {
                riskVariation = Math.random() * 10 + 5;
            }
            // Young domains (1-3 years) get +2-10% random variation
            else if (domainAgeYears < 3) {
                riskVariation = Math.random() * 8 + 2;
            }
            // Older domains (3-7 years) get +1-5% random variation
            else if (domainAgeYears < 7) {
                riskVariation = Math.random() * 4 + 1;
            }
            // Very old domains (7+ years) get +0-3% random variation
            else {
                riskVariation = Math.random() * 3;
            }
        } else {
            // If no domain result, add moderate random variation
            riskVariation = Math.random() * 7 + 2;
        }
        
        riskScore = Math.min(100, riskScore + riskVariation);
        riskScore = Math.round(riskScore);

        console.log('🎲 Final risk score with randomization:', riskScore);

        // Generate recommendations based on domain age
        let recommendations = generateRecommendationsByDomainAge(actionType, domainResult, vtResult);

        console.log('📝 Calling displayActionResults with riskScore:', riskScore);
        console.log('📝 Recommendations preview:', recommendations.substring(0, 100));
        
        try {
            displayActionResults(riskScore, recommendations, vtResult);
            console.log('✅ displayActionResults executed successfully');
        } catch (displayError) {
            console.error('❌ Error in displayActionResults:', displayError);
            alert('❌ Error displaying results: ' + displayError.message);
            throw displayError;
        }
        
        updateOverallRisk(riskScore);
        
        // Show success message AFTER display
        alert(`✅ Analysis Complete!\n\n🎯 Risk Score: ${riskScore}%\n\nScroll down to see full recommendations.`);

        // Save analysis to Firebase
        if (isFirebaseReady) {
            const analysisData = {
                type: 'action-type',
                url: url,
                actionType: actionType,
                notes: notes,
                riskScore: riskScore,
                recommendations: recommendations,
                vtResult: vtResult,
                domainResult: domainResult,
                hackathon: document.getElementById('hackathon-selector').value || 'other'
            };
            
            saveAnalysisToFirebase(analysisData).then(docId => {
                if (docId) {
                    console.log('✅ Analysis saved to Firebase:', docId);
                }
            });
        }
    }).catch((error) => {
        console.error('❌ PROMISE CHAIN ERROR during analysis:', error);
        console.error('❌ Error name:', error.name);
        console.error('❌ Error message:', error.message);
        console.error('❌ Error stack:', error.stack);
        alert('❌ Error during analysis:\n\n' + error.message + '\n\nCheck console for details.');
    });
}

function displayActionResults(riskScore, recommendations, vtResult = null) {
    console.log('📊 displayActionResults called with riskScore:', riskScore);
    console.log('📊 recommendations length:', recommendations.length);
    console.log('📊 vtResult:', vtResult);
    
    try {
        const resultsContainer = document.getElementById('action-results');
        console.log('1️⃣ Results container element:', !!resultsContainer, 'element:', resultsContainer);
        
        if (!resultsContainer) {
            console.error('❌ Results container not found! Element ID: action-results');
            throw new Error('Results container element (id="action-results") not found in DOM');
        }

        console.log('2️⃣ Calculating risk level...');
        const riskLevel = getRiskLevel(riskScore);
        console.log('2️⃣ Risk level calculated:', riskLevel);

        let resultHTML = `${riskScore}% - ${riskLevel.label}`;
        if (vtResult) {
            resultHTML += ` | VirusTotal: ${vtResult.detectionRatio}`;
        }

        console.log('3️⃣ Result HTML:', resultHTML);
        const riskElement = document.getElementById('action-risk');
        console.log('3️⃣ Risk element found:', !!riskElement, 'element:', riskElement);
        
        if (riskElement) {
            riskElement.textContent = resultHTML;
            riskElement.style.color = riskLevel.color;
            console.log('3️⃣ Risk element updated with text:', riskElement.textContent);
        } else {
            console.error('❌ Risk element not found! Element ID: action-risk');
            throw new Error('Risk element (id="action-risk") not found in DOM');
        }
        
        // Format recommendations with line breaks preserved
        console.log('4️⃣ Formatting recommendations...');
        const recommendationsArray = recommendations.split('\n');
        console.log('4️⃣ Recommendations split into', recommendationsArray.length, 'lines');
        
        const recommendationsFormatted = recommendationsArray.map((line, idx) => {
            if (!line.trim()) {
                return `<div style="height: 8px;"></div>`;
            }
            return `<div style="margin: 8px 0; line-height: 1.6; color: #333; font-size: 14px;">${line}</div>`;
        }).join('');
        
        console.log('4️⃣ Recommendations formatted, length:', recommendationsFormatted.length);
        const recElement = document.getElementById('action-recommendations');
        console.log('4️⃣ Recommendations element found:', !!recElement, 'element:', recElement);
        
        if (recElement) {
            recElement.innerHTML = recommendationsFormatted;
            console.log('4️⃣ Recommendations element updated with HTML length:', recElement.innerHTML.length);
        } else {
            console.error('❌ Recommendations element not found! Element ID: action-recommendations');
            throw new Error('Recommendations element (id="action-recommendations") not found in DOM');
        }

        console.log('5️⃣ Removing hidden class...');
        const hadHiddenClass = resultsContainer.classList.contains('hidden');
        resultsContainer.classList.remove('hidden');
        console.log('5️⃣ Hidden class removed. Had hidden class:', hadHiddenClass, 'Now has:', resultsContainer.className);
        
        console.log('6️⃣ Setting inline styles with !important...');
        resultsContainer.style.cssText = `
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
            position: relative !important;
            z-index: 1000 !important;
            margin-top: 30px !important;
            margin-bottom: 30px !important;
            padding: 25px !important;
        `;
        
        console.log('✅ Final state - display:', resultsContainer.style.display, 'visibility:', resultsContainer.style.visibility, 'opacity:', resultsContainer.style.opacity);
        
        // Scroll to results after a short delay
        setTimeout(() => {
            console.log('📜 Attempting to scroll to results container...');
            try {
                resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                console.log('📜 Scroll successful');
            } catch (e) {
                console.error('❌ Scroll error:', e);
            }
        }, 100);
        
        console.log('✅ displayActionResults completed successfully');
        
    } catch (error) {
        console.error('❌ Error in displayActionResults:', error);
        console.error('❌ Error message:', error.message);
        console.error('❌ Error stack:', error.stack);
        alert('❌ Error displaying results: ' + error.message);
        throw error;
    }
}

// VirusTotal Auto-Check Function for Action Type Tab
function checkActionURLWithVirusTotal(url) {
    // Validate URL format
    if (!url || url.trim() === '') {
        document.getElementById('vt-results-action').classList.add('hidden');
        document.getElementById('domain-age-results').classList.add('hidden');
        return;
    }

    // Basic URL validation
    try {
        new URL(url);
    } catch (e) {
        console.log('Invalid URL format');
        document.getElementById('vt-results-action').classList.add('hidden');
        document.getElementById('domain-age-results').classList.add('hidden');
        return;
    }

    // Check both VirusTotal and Domain Age
    checkDomainAge(url);
    
    // Show loading state
    const resultsContainer = document.getElementById('vt-results-action');
    resultsContainer.classList.remove('hidden');
    
    document.getElementById('vt-malicious-action').textContent = '...';
    document.getElementById('vt-suspicious-action').textContent = '...';
    document.getElementById('vt-undetected-action').textContent = '...';
    document.getElementById('vt-ratio-action').textContent = '...';
    document.getElementById('vt-vendors-action').innerHTML = '<p style="text-align: center; color: var(--text-light);">Scanning...</p>';

    // Call VirusTotal API
    checkURLWithVirusTotal(url).then(vtResult => {
        if (vtResult) {
            // Update stat cards
            document.getElementById('vt-malicious-action').textContent = vtResult.maliciousCount;
            document.getElementById('vt-suspicious-action').textContent = vtResult.suspiciousCount;
            document.getElementById('vt-undetected-action').textContent = vtResult.undetectedCount;
            document.getElementById('vt-ratio-action').textContent = vtResult.detectionRatio;

            // Display vendors in VirusTotal website style
            if (vtResult.vendors && vtResult.vendors.length > 0) {
                let vendorsHTML = '<h4 style="margin-top: 15px; margin-bottom: 10px;">🔍 Detection Summary</h4>';
                vendorsHTML += '<div class="vt-vendor-list" style="display: flex; flex-direction: column; gap: 8px;">';
                
                // Group vendors by category
                const malicious = vtResult.vendors.filter(v => v.category === 'malicious');
                const suspicious = vtResult.vendors.filter(v => v.category === 'suspicious');
                
                if (malicious.length > 0) {
                    vendorsHTML += '<div style="padding: 10px; background: #ffebee; border-left: 4px solid #d32f2f; border-radius: 4px;">';
                    vendorsHTML += `<strong style="color: #d32f2f;">🔴 Malicious (${malicious.length})</strong>`;
                    malicious.forEach(vendor => {
                        vendorsHTML += `<div style="margin-left: 10px; margin-top: 5px; font-size: 13px; color: #555;">
                            <strong>${vendor.name}</strong>: ${vendor.result || vendor.category}
                        </div>`;
                    });
                    vendorsHTML += '</div>';
                }
                
                if (suspicious.length > 0) {
                    vendorsHTML += '<div style="padding: 10px; background: #fff3cd; border-left: 4px solid #ff9800; border-radius: 4px;">';
                    vendorsHTML += `<strong style="color: #ff9800;">⚠️ Suspicious (${suspicious.length})</strong>`;
                    suspicious.forEach(vendor => {
                        vendorsHTML += `<div style="margin-left: 10px; margin-top: 5px; font-size: 13px; color: #555;">
                            <strong>${vendor.name}</strong>: ${vendor.result || vendor.category}
                        </div>`;
                    });
                    vendorsHTML += '</div>';
                }
                
                // Show list of all vendors
                if (vtResult.allVendors && vtResult.allVendors.length > 0) {
                    vendorsHTML += '<div style="margin-top: 15px; padding: 10px; background: #f5f5f5; border-radius: 4px;">';
                    vendorsHTML += '<strong style="font-size: 13px;">All Scanning Engines:</strong>';
                    vendorsHTML += '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 8px; margin-top: 10px;">';
                    
                    vtResult.allVendors.forEach(vendor => {
                        let statusColor = '#4caf50';
                        let statusIcon = '✓';
                        
                        if (vendor.category === 'malicious') {
                            statusColor = '#d32f2f';
                            statusIcon = '✗';
                        } else if (vendor.category === 'suspicious') {
                            statusColor = '#ff9800';
                            statusIcon = '⚠';
                        }
                        
                        vendorsHTML += `<div style="padding: 8px; background: white; border: 1px solid #ddd; border-radius: 3px; font-size: 12px;">
                            <div style="color: ${statusColor}; font-weight: bold;">${statusIcon} ${vendor.name}</div>
                            <div style="color: #999; font-size: 11px; margin-top: 3px;">${vendor.result || 'Clean'}</div>
                        </div>`;
                    });
                    
                    vendorsHTML += '</div></div>';
                }
                
                vendorsHTML += '</div>';
                document.getElementById('vt-vendors-action').innerHTML = vendorsHTML;
            } else {
                document.getElementById('vt-vendors-action').innerHTML = '<div style="padding: 15px; background: #e8f5e9; border-left: 4px solid #4caf50; border-radius: 4px;"><strong style="color: #2e7d32;">✓ No threats detected by any vendors</strong></div>';
            }

            // Highlight results container
            resultsContainer.style.animation = 'none';
            setTimeout(() => {
                resultsContainer.style.animation = 'slideIn 0.3s ease-out';
            }, 10);
        } else {
            // Hide results if API call fails
            resultsContainer.classList.add('hidden');
            console.log('Could not fetch VirusTotal data');
        }
    }).catch(error => {
        console.error('Error during VirusTotal check:', error);
        resultsContainer.classList.add('hidden');
    });
}

// Domain Age Checker Function
/**
 * Check domain age for any tab - generic function for all tabs
 * @param {string} url - Website URL
 * @param {string} containerId - ID of the domain age results container
 */
function checkDomainAgeForTab(url, containerId) {
    if (!url || url.trim() === '') {
        document.getElementById(containerId).classList.add('hidden');
        return Promise.resolve(null);
    }

    try {
        new URL(url);
    } catch (e) {
        document.getElementById(containerId).classList.add('hidden');
        return Promise.resolve(null);
    }

    // Extract domain from URL
    const urlObj = new URL(url);
    const domain = urlObj.hostname.replace('www.', '');
    const tabName = containerId.split('-domain-')[0];

    // Show loading state
    const resultsContainer = document.getElementById(containerId);
    resultsContainer.classList.remove('hidden');
    
    document.getElementById(`${tabName}-domain-age-years`).textContent = '...';
    document.getElementById(`${tabName}-domain-created-date`).textContent = '...';
    document.getElementById(`${tabName}-domain-expiry-date`).textContent = '...';
    document.getElementById(`${tabName}-domain-registrar`).textContent = '...';

    return new Promise((resolve) => {
        // Use local Domain Info API server
        const localApiUrl = `http://127.0.0.1:8001/api/domain-info?domain=${domain}`;

        fetchDomainForTab(localApiUrl, domain, containerId)
            .then(result => {
                resolve(result);
            })
            .catch(() => {
                // Fallback if local server not available
                fetchDomainForTab('', domain, containerId)
                    .then(result => {
                        resolve(result);
                    })
                    .catch(() => {
                        resolve(null);
                    });
            });
    });
}

/**
 * Fetch domain info for tab display
 */
function fetchDomainForTab(apiUrl, domain, containerId) {
    return fetch(apiUrl, {
        headers: {
            'Accept': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        // Handle responses from our Python backend
        if (data && (data.created_date || data.status === 'success')) {
            const result = data;
            
            // Extract domain age
            let domainAge = result.domain_age_years || 'N/A';
            let ageDays = result.domain_age_days || 'Unknown';
            let createdDate = result.created_date || 'Unknown';
            let expiryDate = result.expiry_date || 'Unknown';
            let registrar = result.registrar || 'Unknown';

            // Format dates for display
            if (createdDate !== 'Unknown' && createdDate) {
                try {
                    createdDate = new Date(createdDate).toLocaleDateString('en-US', { 
                        year: 'numeric', 
                        month: 'long', 
                        day: 'numeric' 
                    });
                } catch (e) {
                    // Keep original format
                }
            }

            if (expiryDate !== 'Unknown' && expiryDate) {
                try {
                    expiryDate = new Date(expiryDate).toLocaleDateString('en-US', { 
                        year: 'numeric', 
                        month: 'long', 
                        day: 'numeric' 
                    });
                } catch (e) {
                    // Keep original format
                }
            }

            // Update all stat cards - extract tab name from containerId
            // containerId = "permissions-domain-age" -> tab = "permissions"
            const tabName = containerId.split('-domain-')[0];
            document.getElementById(`${tabName}-domain-age-years`).textContent = typeof domainAge === 'string' ? domainAge : `${domainAge} years`;
            document.getElementById(`${tabName}-domain-created-date`).textContent = createdDate;
            document.getElementById(`${tabName}-domain-expiry-date`).textContent = expiryDate;
            document.getElementById(`${tabName}-domain-registrar`).textContent = registrar;

            console.log(`✅ Domain age loaded for ${domain} in ${containerId}`);
            return { domainAge, ageDays, createdDate };
        }
        
        throw new Error('No data');
    })
    .catch(error => {
        console.error('Error fetching domain info:', error);
        // Hide container on error
        document.getElementById(containerId).classList.add('hidden');
        throw error;
    });
}

function checkDomainAge(url) {
    if (!url || url.trim() === '') {
        document.getElementById('domain-age-results').classList.add('hidden');
        return Promise.resolve(null);
    }

    try {
        new URL(url);
    } catch (e) {
        document.getElementById('domain-age-results').classList.add('hidden');
        return Promise.resolve(null);
    }

    // Extract domain from URL
    const urlObj = new URL(url);
    const domain = urlObj.hostname.replace('www.', '');

    // Show loading state
    const resultsContainer = document.getElementById('domain-age-results');
    resultsContainer.classList.remove('hidden');
    
    document.getElementById('domain-age-years').textContent = '...';
    document.getElementById('domain-created-date').textContent = '...';
    document.getElementById('domain-expiry-date').textContent = '...';
    document.getElementById('domain-registrar').textContent = '...';
    document.getElementById('domain-details').innerHTML = '<p style="text-align: center; color: var(--text-light);">🔍 Fetching domain information from WHOIS database...</p>';

    return new Promise((resolve) => {
        // Use local Domain Info API server
        const localApiUrl = `http://127.0.0.1:8001/api/domain-info?domain=${domain}`;

        fetchDomainFromApi(localApiUrl, domain, resultsContainer)
            .then(result => {
                resolve(result);
            })
            .catch(() => {
                // Try alternative APIs if local server is not available
                const apis = [
                    `https://www.whoisjsonapi.com/api/v1/whois?domain=${domain}`,
                    `https://whois.api.hostinger.com/v1/whois?domain=${domain}`
                ];

                fetchDomainFromApi(apis[0], domain, resultsContainer)
                    .then(result => {
                        resolve(result);
                    })
                    .catch(() => {
                        fetchDomainFromApi(apis[1], domain, resultsContainer)
                            .then(result => {
                                resolve(result);
                            })
                            .catch(() => {
                                // Use fallback method
                                fetchDomainAgeAlternative(domain, resultsContainer);
                                resolve(null);
                            });
                    });
            });
    });
}

function fetchDomainFromApi(apiUrl, domain, resultsContainer) {
    return fetch(apiUrl, {
        headers: {
            'Accept': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        // Handle responses from our Python backend and other WHOIS APIs
        if (data && (data.result || data.data || data.whois || data.created_date || data.status === 'success')) {
            const result = data.result || data.data || data.whois || data;
            
            // Extract domain age from backend or calculate it
            let domainAge = result.domain_age_years || 'N/A';
            let ageDays = result.domain_age_days || 'Unknown';
            let createdDate = result.created_date || result.creation_date || 'Unknown';
            let expiryDate = result.expiry_date || result.expiration_date || result.registry_expiry_date || 'Unknown';
            let registrar = result.registrar || result.registrar_name || 'Unknown';

            // If we have days but not years, calculate years
            if (domainAge === 'N/A' && ageDays !== 'Unknown') {
                try {
                    const ageYears = (ageDays / 365).toFixed(1);
                    domainAge = `${ageYears} years`;
                } catch (e) {
                    // Keep original value
                }
            }

            // Calculate age in years if we have created date
            if (typeof domainAge === 'string' && domainAge === 'N/A' && createdDate !== 'Unknown') {
                try {
                    const created = new Date(createdDate);
                    const now = new Date();
                    const ageMs = now - created;
                    ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
                    const ageYears = (ageDays / 365).toFixed(1);
                    domainAge = `${ageYears} years`;
                } catch (e) {
                    // Keep original format
                }
            }

            // Format dates for display
            if (createdDate !== 'Unknown' && createdDate) {
                try {
                    createdDate = new Date(createdDate).toLocaleDateString('en-US', { 
                        year: 'numeric', 
                        month: 'long', 
                        day: 'numeric' 
                    });
                } catch (e) {
                    // Keep original format if parsing fails
                }
            }

            if (expiryDate !== 'Unknown' && expiryDate) {
                try {
                    expiryDate = new Date(expiryDate).toLocaleDateString('en-US', { 
                        year: 'numeric', 
                        month: 'long', 
                        day: 'numeric' 
                    });
                } catch (e) {
                    // Keep original format if parsing fails
                }
            }

            // Update stat cards
            document.getElementById('domain-age-years').textContent = domainAge;
            document.getElementById('domain-created-date').textContent = createdDate;
            document.getElementById('domain-expiry-date').textContent = expiryDate;
            document.getElementById('domain-registrar').textContent = registrar;

            // Build details HTML
            let detailsHTML = '<h4>📊 Domain Risk Assessment</h4>';
            
            let riskBadge = '';
            let riskText = '';
            let riskScore = 0;
            
            if (typeof ageDays === 'number') {
                if (ageDays < 30) {
                    riskBadge = '<span class="domain-risk-badge new-domain">⚠️ Very New Domain (High Risk)</span>';
                    riskText = 'This domain was registered less than 30 days ago. Very new domains have significantly higher phishing risk.';
                    riskScore = 80;
                } else if (ageDays < 90) {
                    riskBadge = '<span class="domain-risk-badge new-domain">⚠️ Very New Domain (High Risk)</span>';
                    riskText = 'This domain was registered less than 90 days ago. New domains have higher phishing risk.';
                    riskScore = 75;
                } else if (ageDays < 365) {
                    riskBadge = '<span class="domain-risk-badge new-domain">⚠️ New Domain (Medium Risk)</span>';
                    riskText = 'This domain is less than a year old. Monitor carefully for suspicious activity.';
                    riskScore = 50;
                } else if (ageDays < 1825) {
                    riskBadge = '<span class="domain-risk-badge established-domain">✓ Moderately Established (Low Risk)</span>';
                    riskText = 'This is a moderately established domain with 1-5 years history.';
                    riskScore = 25;
                } else {
                    riskBadge = '<span class="domain-risk-badge established-domain">✓ Well-Established Domain (Very Low Risk)</span>';
                    riskText = 'This is a well-established domain with 5+ years history. Lower phishing risk.';
                    riskScore = 10;
                }
            }

            // Additional details
            let moreDetailsHTML = '<div class="domain-detail-item">';
            moreDetailsHTML += `<span class="domain-detail-label">Domain</span>`;
            moreDetailsHTML += `<span class="domain-detail-value">${domain}</span>`;
            moreDetailsHTML += '</div>';
            
            if (result.nameservers && result.nameservers.length > 0) {
                const ns = Array.isArray(result.nameservers) ? result.nameservers.slice(0, 2).join(', ') : result.nameservers;
                moreDetailsHTML += `<div class="domain-detail-item">`;
                moreDetailsHTML += `<span class="domain-detail-label">Nameservers</span>`;
                moreDetailsHTML += `<span class="domain-detail-value">${ns}</span>`;
                moreDetailsHTML += `</div>`;
            }

            moreDetailsHTML += `<div class="domain-detail-item">`;
            moreDetailsHTML += `<span class="domain-detail-label">Risk Status</span>`;
            moreDetailsHTML += `<span class="domain-detail-value">${riskBadge}</span>`;
            moreDetailsHTML += `</div>`;

            moreDetailsHTML += `<div class="domain-detail-item" style="border-bottom: none; padding-top: 15px;">`;
            moreDetailsHTML += `<span class="domain-detail-label" style="min-width: auto;">Analysis</span>`;
            moreDetailsHTML += `<span class="domain-detail-value" style="text-align: left;">${riskText}</span>`;
            moreDetailsHTML += `</div>`;

            detailsHTML += moreDetailsHTML;
            document.getElementById('domain-details').innerHTML = detailsHTML;

            // Highlight results container
            resultsContainer.style.animation = 'none';
            setTimeout(() => {
                resultsContainer.style.animation = 'slideIn 0.3s ease-out';
            }, 10);

            return { domainAge, createdDate, expiryDate, registrar, riskScore };
        } else {
            throw new Error('Invalid response format');
        }
    });
}

// Alternative domain age checker using estimated data
function fetchDomainAgeAlternative(domain, resultsContainer) {
    // Using a simpler estimation method
    document.getElementById('domain-age-years').textContent = 'Data Unavailable';
    document.getElementById('domain-created-date').textContent = 'Check with registrar';
    document.getElementById('domain-expiry-date').textContent = 'Check with registrar';
    document.getElementById('domain-registrar').textContent = 'Use WHOIS lookup';

    let detailsHTML = '<h4>💡 How to Check Domain Age</h4>';
    detailsHTML += `<div class="domain-detail-item">
        <span class="domain-detail-label">Domain</span>
        <span class="domain-detail-value">${domain}</span>
    </div>`;
    
    detailsHTML += `<div class="domain-detail-item">
        <span class="domain-detail-label" style="min-width: auto;">Step 1</span>
        <span class="domain-detail-value">Visit <strong>whatsmydns.net</strong> for instant lookup</span>
    </div>`;
    
    detailsHTML += `<div class="domain-detail-item">
        <span class="domain-detail-label" style="min-width: auto;">Step 2</span>
        <span class="domain-detail-value">Use <strong>whois</strong> command in terminal</span>
    </div>`;

    document.getElementById('domain-details').innerHTML = detailsHTML;
}

// Helper function to mask email
function maskEmail(email) {
    if (!email) return 'N/A';
    const [name, domain] = email.split('@');
    return name.substring(0, 2) + '*'.repeat(name.length - 2) + '@' + domain;
}

/* ============================================
   PERMISSIONS ANALYSIS
   ============================================ */

document.querySelector('#permissions form').addEventListener('submit', (e) => {
    e.preventDefault();
    analyzePermissions();
});

function analyzePermissions() {
    const url = document.getElementById('permissions-url').value;
    const selectedPermissions = Array.from(document.querySelectorAll('.perm-check:checked'))
        .map(el => el.dataset.permission);

    if (!url) {
        alert('Please enter the website URL');
        return;
    }

    if (selectedPermissions.length === 0) {
        alert('Please select at least one permission');
        return;
    }

    let totalRisk = 0;
    const risksHTML = [];

    selectedPermissions.forEach(permission => {
        const riskInfo = PERMISSION_RISKS[permission];
        totalRisk += riskInfo.risk;

        const riskLevel = getRiskLevel(riskInfo.risk);
        risksHTML.push(`
            <div class="risk-item ${riskLevel.label.toLowerCase().replace(' ', '-')}">
                <div class="risk-item-title">${permission.toUpperCase()}</div>
                <div class="risk-item-description">
                    Risk Score: ${riskInfo.risk}% | ${riskInfo.description}
                </div>
            </div>
        `);
    });

    const averageRisk = Math.round(totalRisk / selectedPermissions.length);

    document.getElementById('permissions-risk-items').innerHTML = risksHTML.join('');
    document.getElementById('permissions-results').classList.remove('hidden');
    document.getElementById('permissions-results').scrollIntoView({ behavior: 'smooth' });

    updateOverallRisk(averageRisk);
}

/* ============================================
   COOKIES ANALYSIS
   ============================================ */

document.querySelector('#cookies form').addEventListener('submit', (e) => {
    e.preventDefault();
    analyzeCookies();
});

function analyzeCookies() {
    const cookiesText = document.getElementById('cookies-text').value;

    if (!cookiesText.trim()) {
        alert('Please paste cookie data');
        return;
    }

    let riskScore = 0;
    const risksHTML = [];

    // Analyze cookies for tracking
    const hasTracking = /tracking|analytics|facebook|google|doubleclick/i.test(cookiesText);
    if (hasTracking) {
        riskScore += 45;
        risksHTML.push(`
            <div class="risk-item medium">
                <div class="risk-item-title">Tracking Cookies Detected</div>
                <div class="risk-item-description">
                    The site uses tracking cookies for analytics and advertising. Your browsing behavior may be monitored.
                </div>
            </div>
        `);
    }

    // Check for session hijacking risks
    const hasSensitiveData = /session|token|auth|credential|password/i.test(cookiesText);
    if (hasSensitiveData) {
        riskScore += 35;
        risksHTML.push(`
            <div class="risk-item high">
                <div class="risk-item-title">Sensitive Data in Cookies</div>
                <div class="risk-item-description">
                    Cookies contain sensitive authentication tokens. Ensure connection is HTTPS protected.
                </div>
            </div>
        `);
    }

    // Check for cross-site tracking
    const hasCrossSite = /Domain=/i.test(cookiesText);
    if (hasCrossSite) {
        riskScore += 30;
        risksHTML.push(`
            <div class="risk-item medium">
                <div class="risk-item-title">Cross-site Tracking Capability</div>
                <div class="risk-item-description">
                    Cookies allow tracking across multiple websites. Affects privacy.
                </div>
            </div>
        `);
    }

    // Check cookie count
    const cookieCount = (cookiesText.match(/=/g) || []).length;
    if (cookieCount > 20) {
        riskScore += 25;
        risksHTML.push(`
            <div class="risk-item medium">
                <div class="risk-item-title">Excessive Cookies (${cookieCount})</div>
                <div class="risk-item-description">
                    Large number of cookies may impact privacy and performance.
                </div>
            </div>
        `);
    }

    if (risksHTML.length === 0) {
        risksHTML.push(`
            <div class="risk-item low">
                <div class="risk-item-title">No Major Issues Detected</div>
                <div class="risk-item-description">
                    Cookies appear standard, but always monitor website behavior.
                </div>
            </div>
        `);
        riskScore = 20;
    }

    riskScore = Math.min(riskScore, 100);
    document.getElementById('cookies-risk-items').innerHTML = risksHTML.join('');
    document.getElementById('cookies-results').classList.remove('hidden');
    document.getElementById('cookies-results').scrollIntoView({ behavior: 'smooth' });

    updateOverallRisk(riskScore);
}

/* ============================================
   TERMS & CONDITIONS ANALYSIS
   ============================================ */

document.querySelector('#terms form').addEventListener('submit', (e) => {
    e.preventDefault();
    analyzeTermsAndConditions();
});

function analyzeTermsAndConditions() {
    const url = document.getElementById('terms-url').value;
    const termsText = document.getElementById('terms-text').value;

    if (!termsText.trim()) {
        alert('Please paste Terms & Conditions text');
        return;
    }

    let riskScore = 0;
    const risksHTML = [];
    const textLower = termsText.toLowerCase();

    // Check for suspicious clauses
    Object.entries(SUSPICIOUS_TC_KEYWORDS).forEach(([category, keywords]) => {
        let foundKeywords = [];
        keywords.forEach(keyword => {
            if (textLower.includes(keyword)) {
                foundKeywords.push(keyword);
                riskScore += 10;
            }
        });

        if (foundKeywords.length > 0) {
            let categoryLabel = category.replace(/_/g, ' ').toUpperCase();
            risksHTML.push(`
                <div class="risk-item medium">
                    <div class="risk-item-title">${categoryLabel}</div>
                    <div class="risk-item-description">
                        Found keywords: ${foundKeywords.join(', ')}
                    </div>
                </div>
            `);
        }
    });

    // Check for unreasonable terms
    if (textLower.includes('no refund') || textLower.includes('no guarantee')) {
        riskScore += 20;
        risksHTML.push(`
            <div class="risk-item medium">
                <div class="risk-item-title">No Refund Policy</div>
                <div class="risk-item-description">
                    Terms explicitly deny refunds or guarantees - typical of phishing sites.
                </div>
            </div>
        `);
    }

    // Check document length
    if (termsText.length < 500) {
        riskScore += 25;
        risksHTML.push(`
            <div class="risk-item medium">
                <div class="risk-item-title">Unusually Short T&C</div>
                <div class="risk-item-description">
                    Legitimate T&C documents are typically longer (500+ words).
                </div>
            </div>
        `);
    }

    if (risksHTML.length === 0) {
        risksHTML.push(`
            <div class="risk-item low">
                <div class="risk-item-title">Standard Terms Detected</div>
                <div class="risk-item-description">
                    No obvious red flags found, but always read carefully.
                </div>
            </div>
        `);
        riskScore = 20;
    }

    riskScore = Math.min(riskScore, 100);
    document.getElementById('terms-risk-items').innerHTML = risksHTML.join('');
    document.getElementById('terms-results').classList.remove('hidden');
    document.getElementById('terms-results').scrollIntoView({ behavior: 'smooth' });

    updateOverallRisk(riskScore);
}

/* ============================================
   SSL CERTIFICATE ANALYSIS
   ============================================ */

document.querySelector('#ssl form').addEventListener('submit', (e) => {
    e.preventDefault();
    analyzeSSL();
});

function analyzeSSL() {
    const url = document.getElementById('ssl-url').value;
    const certData = document.getElementById('ssl-cert').value;

    if (!url) {
        alert('Please enter the website URL');
        return;
    }

    let riskScore = 0;
    const risksHTML = [];

    // Basic URL validation
    if (!url.startsWith('https://')) {
        riskScore = 95;
        document.getElementById('ssl-status').textContent = '❌ NOT SECURE';
        document.getElementById('ssl-status').style.color = '#ef4444';
        risksHTML.push(`
            <div class="risk-item high">
                <div class="risk-item-title">No HTTPS Protocol</div>
                <div class="risk-item-description">
                    Website does not use HTTPS. Data is transmitted without encryption. CRITICAL RISK.
                </div>
            </div>
        `);
    } else {
        document.getElementById('ssl-status').textContent = '✓ SECURE CONNECTION';
        document.getElementById('ssl-status').style.color = '#10b981';
        riskScore = 20;
    }

    // Analyze certificate data if provided
    if (certData) {
        const certLower = certData.toLowerCase();

        if (certLower.includes('expired')) {
            riskScore = 95;
            risksHTML.push(`
                <div class="risk-item high">
                    <div class="risk-item-title">Expired Certificate</div>
                    <div class="risk-item-description">
                        SSL certificate has expired. Connection cannot be trusted.
                    </div>
                </div>
            `);
        }

        if (certLower.includes('self-signed')) {
            riskScore += 50;
            risksHTML.push(`
                <div class="risk-item high">
                    <div class="risk-item-title">Self-Signed Certificate</div>
                    <div class="risk-item-description">
                        Certificate is not issued by trusted authority. Major red flag for phishing.
                    </div>
                </div>
            `);
        }

        if (certLower.includes('mismatch') || certLower.includes('domain')) {
            riskScore += 40;
            risksHTML.push(`
                <div class="risk-item high">
                    <div class="risk-item-title">Domain Mismatch</div>
                    <div class="risk-item-description">
                        Certificate domain doesn't match website URL. Possible domain impersonation.
                    </div>
                </div>
            `);
        }

        if (certLower.includes('ssl 3.0') || certLower.includes('tls 1.0')) {
            riskScore += 35;
            risksHTML.push(`
                <div class="risk-item medium">
                    <div class="risk-item-title">Weak SSL/TLS Version</div>
                    <div class="risk-item-description">
                        Uses outdated SSL/TLS version. Use TLS 1.2 or higher.
                    </div>
                </div>
            `);
        }

        // Set certificate authority
        if (certLower.includes('let')) {
            document.getElementById('ssl-ca').textContent = "Let's Encrypt (Free)";
        } else if (certLower.includes('symantec') || certLower.includes('verisign')) {
            document.getElementById('ssl-ca').textContent = 'Symantec/VeriSign (Trusted)';
        } else {
            document.getElementById('ssl-ca').textContent = 'Unknown CA';
        }

        // Set protocol version
        if (certLower.includes('tls 1.3')) {
            document.getElementById('ssl-protocol').textContent = 'TLS 1.3 (Latest)';
        } else if (certLower.includes('tls 1.2')) {
            document.getElementById('ssl-protocol').textContent = 'TLS 1.2 (Good)';
        } else {
            document.getElementById('ssl-protocol').textContent = 'Legacy/Unknown';
        }
    } else {
        document.getElementById('ssl-ca').textContent = 'Enter certificate data to analyze';
        document.getElementById('ssl-protocol').textContent = 'Enter certificate data to analyze';
        
        if (riskScore < 50) {
            risksHTML.push(`
                <div class="risk-item low">
                    <div class="risk-item-title">HTTPS Connection Active</div>
                    <div class="risk-item-description">
                        Website uses secure connection. Paste certificate details for detailed analysis.
                    </div>
                </div>
            `);
        }
    }

    riskScore = Math.min(riskScore, 100);

    if (risksHTML.length === 0) {
        risksHTML.push(`
            <div class="risk-item low">
                <div class="risk-item-title">Certificate Analysis Complete</div>
                <div class="risk-item-description">
                    No major SSL issues detected.
                </div>
            </div>
        `);
    }

    document.getElementById('ssl-risk-items').innerHTML = risksHTML.join('');
    document.getElementById('ssl-results').classList.remove('hidden');
    document.getElementById('ssl-results').scrollIntoView({ behavior: 'smooth' });

    updateOverallRisk(riskScore);
}

/* ============================================
   HELPER FUNCTIONS
   ============================================ */

function analyzeURL(url) {
    let riskScore = 0;
    const urlLower = url.toLowerCase();

    // Check for suspicious URL patterns
    if (!url.startsWith('https')) {
        riskScore += 30;
    }

    if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(url)) {
        riskScore += 40; // IP address instead of domain
    }

    if (url.includes('bit.ly') || url.includes('tinyurl')) {
        riskScore += 35; // Shortened URL
    }

    if (/dashboard|login|verify|confirm|update/i.test(url)) {
        riskScore += 25; // Suspicious path
    }

    return riskScore;
}

function analyzeText(text) {
    let riskScore = 0;
    const textLower = text.toLowerCase();

    Object.values(PHISHING_PATTERNS).forEach(keywords => {
        keywords.forEach(keyword => {
            if (textLower.includes(keyword)) {
                riskScore += 5;
            }
        });
    });

    return Math.min(riskScore, 40);
}

function getRiskLevel(score) {
    if (score <= RISK_THRESHOLDS.low.max) {
        return RISK_THRESHOLDS.low;
    } else if (score <= RISK_THRESHOLDS.medium.max) {
        return RISK_THRESHOLDS.medium;
    } else {
        return RISK_THRESHOLDS.high;
    }
}

function updateOverallRisk(newRisk = 0) {
    const currentPercentage = parseInt(document.getElementById('overallRiskPercentage').textContent);
    const averageRisk = Math.round((currentPercentage + newRisk) / 2);

    const riskLevel = getRiskLevel(averageRisk);

    // Update percentage
    document.getElementById('overallRiskPercentage').textContent = averageRisk + '%';
    document.getElementById('headerRiskValue').textContent = averageRisk + '%';

    // Update header risk bar
    const riskBar = document.getElementById('headerRiskBar');
    riskBar.style.width = averageRisk + '%';

    // Update risk circle
    const circle = document.getElementById('riskCircle');
    const circumference = 2 * Math.PI * 45;
    const offset = circumference - (averageRisk / 100) * circumference;
    circle.style.strokeDashoffset = offset;
    circle.style.stroke = riskLevel.color;

    // Update risk level text
    document.getElementById('riskLevel').textContent = riskLevel.label;
    document.getElementById('riskLevel').style.color = riskLevel.color;

    // Update threat count
    const threatCount = document.querySelectorAll('.risk-item').length;
    document.getElementById('threatCount').textContent = threatCount + ' Threats Detected';

    // Update recommendation
    let recommendation = '';
    if (averageRisk <= 30) {
        recommendation = '✅ Website appears relatively safe, but exercise caution.';
    } else if (averageRisk <= 60) {
        recommendation = '⚠️ Moderate risk detected. Verify before sharing any information.';
    } else {
        recommendation = '🚨 HIGH RISK! Do not proceed. Check for phishing signs.';
    }
    document.getElementById('riskRecommendation').textContent = recommendation;
}

function resetAllAnalysis() {
    // Clear all form inputs
    document.querySelectorAll('input[type="text"], input[type="url"], textarea, select').forEach(input => {
        input.value = '';
    });
    
    document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
        checkbox.checked = false;
    });

    // Hide all results
    document.querySelectorAll('.results-container').forEach(container => {
        container.classList.add('hidden');
    });

    // Reset overall risk
    document.getElementById('overallRiskPercentage').textContent = '0%';
    document.getElementById('headerRiskValue').textContent = '0%';
    document.getElementById('riskLevel').textContent = 'No Analysis';
    document.getElementById('threatCount').textContent = '0 Threats Detected';
    document.getElementById('riskRecommendation').textContent = 'Analyze a website to get recommendations';

    // Reset risk circle
    const circle = document.getElementById('riskCircle');
    circle.style.strokeDashoffset = '282.74';
    circle.style.stroke = '#6366f1';

    // Reset header risk bar
    document.getElementById('headerRiskBar').style.width = '0%';

    // Switch back to first tab
    switchTab('action-type');

    alert('All analysis has been reset!');
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    console.log('🎯 DOMContentLoaded event fired!');
    
    // Wait a moment for all elements to be fully rendered
    setTimeout(() => {
        console.log('⏰ 500ms timeout completed, attaching event listeners...');
        
        // Attach form submission listener - try multiple selectors
        const actionTypeForm = document.getElementById('action-type-form');
        const analyzeButton = document.querySelector('.btn-analyze');
        
        console.log('✅ actionTypeForm found by ID:', !!actionTypeForm);
        console.log('✅ analyzeButton found:', !!analyzeButton);
        
        if (actionTypeForm) {
            console.log('📝 Attaching form submit event listener...');
            actionTypeForm.addEventListener('submit', (e) => {
                console.log('🔴 FORM SUBMITTED! Preventing default...');
                e.preventDefault();
                console.log('🔴 Calling analyzeActionType()...');
                analyzeActionType();
            });
        } else {
            console.error('❌ Form not found!');
        }
        
        // Also add direct click handler to button as backup
        if (analyzeButton) {
            console.log('📝 Attaching button click event listener...');
            analyzeButton.addEventListener('click', (e) => {
                console.log('🔵 BUTTON CLICKED! Preventing default...');
                e.preventDefault();
                e.stopPropagation();
                console.log('🔵 Calling analyzeActionType()...');
                analyzeActionType();
                return false;
            });
        } else {
            console.error('❌ Analyze button not found!');
        }
        
        console.log('✅ Event listeners attached successfully');
    }, 500);  // Wait 500ms for DOM to be fully ready

    // Populate VirusTotal API key
    const apiKeyInput = document.getElementById('virustotal-api-key');
    if (apiKeyInput && VIRUSTOTAL_API_KEY) {
        apiKeyInput.value = VIRUSTOTAL_API_KEY;
    }

    // Add SVG gradient for circle
    const svg = document.querySelector('.circle-svg');
    if (svg && !document.getElementById('circleGradient')) {
        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        const gradient = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
        gradient.id = 'circleGradient';
        gradient.setAttribute('x1', '0%');
        gradient.setAttribute('y1', '0%');
        gradient.setAttribute('x2', '100%');
        gradient.setAttribute('y2', '100%');

        const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop1.setAttribute('offset', '0%');
        stop1.setAttribute('stop-color', '#10b981');

        const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop2.setAttribute('offset', '50%');
        stop2.setAttribute('stop-color', '#f59e0b');

        const stop3 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop3.setAttribute('offset', '100%');
        stop3.setAttribute('stop-color', '#ef4444');

        gradient.appendChild(stop1);
        gradient.appendChild(stop2);
        gradient.appendChild(stop3);
        defs.appendChild(gradient);
        svg.insertBefore(defs, svg.firstChild);
    }

    // Load analysis history when page loads
    loadAnalysisHistory();

    console.log('✅ beforeClick Phishing Risk Analyzer loaded successfully!');
});

/**
 * Load and display analysis history from Firebase
 */
async function loadAnalysisHistory() {
    if (!isFirebaseReady) {
        console.log('Waiting for Firebase...');
        await waitForFirebase();
        if (!isFirebaseReady) {
            console.warn('Firebase not available');
            return;
        }
    }

    const historyList = document.getElementById('history-list');
    
    // Show loading state
    historyList.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-light);">🔄 Loading analysis history...</div>';

    try {
        const analyses = await getAnalysesFromFirebase(50);
        
        if (analyses.length === 0) {
            historyList.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-light);"><p>📭 No analysis history yet</p><p style="font-size: 0.9em; margin-top: 10px;">Your analyses will appear here once you start analyzing websites</p></div>';
            document.getElementById('btn-clear-history').style.display = 'none';
            return;
        }

        // Build history display
        let historyHTML = '<div class="history-items">';
        
        analyses.forEach(analysis => {
            const date = analysis.date || new Date(analysis.timestamp);
            const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
            const riskLevel = getRiskLevel(analysis.riskScore);
            
            historyHTML += `
                <div class="history-item" style="border-left: 4px solid ${riskLevel.color}; padding: 15px; margin-bottom: 10px; background: rgba(0,0,0,0.02); border-radius: 4px;">
                    <div style="display: flex; justify-content: space-between; align-items: start;">
                        <div style="flex: 1;">
                            <h4 style="margin: 0 0 8px 0; color: #333;">
                                ${analysis.url || analysis.domain || 'Unknown'}
                            </h4>
                            <p style="margin: 0 0 8px 0; font-size: 0.85em; color: var(--text-light);">
                                ${formattedDate}
                            </p>
                            ${analysis.type === 'action-type' ? `
                                <p style="margin: 0 0 8px 0; font-size: 0.9em; color: #555;">
                                    Action: <strong>${analysis.actionType || 'N/A'}</strong>
                                </p>
                                ${analysis.hackathon && analysis.hackathon !== 'other' ? `
                                    <p style="margin: 0 0 8px 0; font-size: 0.9em; color: #555;">
                                        Event: <strong>${analysis.hackathon}</strong>
                                    </p>
                                ` : ''}
                            ` : ''}
                        </div>
                        <div style="text-align: right; margin-left: 15px;">
                            <div style="font-size: 1.5em; font-weight: bold; color: ${riskLevel.color};">
                                ${analysis.riskScore}%
                            </div>
                            <div style="font-size: 0.8em; color: var(--text-light); margin-top: 4px;">
                                ${riskLevel.label}
                            </div>
                        </div>
                    </div>
                    <div style="margin-top: 10px; display: flex; gap: 8px;">
                        <button class="btn-small" onclick="viewAnalysisDetail('${analysis.id}')" style="flex: 1; padding: 6px 12px; background: var(--primary-color); color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9em;">
                            📋 View Details
                        </button>
                        <button class="btn-small-danger" onclick="deleteAnalysisHistory('${analysis.id}')" style="flex: 1; padding: 6px 12px; background: #ef4444; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9em;">
                            🗑️ Delete
                        </button>
                    </div>
                </div>
            `;
        });
        
        historyHTML += '</div>';
        historyList.innerHTML = historyHTML;
        
        // Show clear all button if there are analyses
        if (analyses.length > 0) {
            document.getElementById('btn-clear-history').style.display = 'inline-block';
        }
        
        console.log('✅ Displayed', analyses.length, 'analyses');
        
    } catch (error) {
        console.error('Error loading history:', error);
        historyList.innerHTML = '<div style="text-align: center; padding: 40px; color: #ef4444;"><p>❌ Error loading analysis history</p><p style="font-size: 0.9em; margin-top: 10px;">' + error.message + '</p></div>';
    }
}

/**
 * View detailed analysis from history
 */
async function viewAnalysisDetail(docId) {
    try {
        const analysis = await getAnalysisFromFirebase(docId);
        
        if (!analysis) {
            alert('Analysis not found');
            return;
        }
        
        // Switch to action-type tab to show the analysis
        switchTab('action-type');
        
        // Fill in the form with the analysis data
        if (analysis.url) document.getElementById('action-url').value = analysis.url;
        if (analysis.actionType) document.getElementById('action-select').value = analysis.actionType;
        if (analysis.notes) document.getElementById('action-notes').value = analysis.notes;
        if (analysis.hackathon) document.getElementById('hackathon-selector').value = analysis.hackathon;
        
        // Display the results
        displayActionResults(analysis.riskScore, analysis.recommendations, analysis.vtResult);
        updateOverallRisk(analysis.riskScore);
        
        // Scroll to results
        setTimeout(() => {
            document.getElementById('action-results').scrollIntoView({ behavior: 'smooth' });
        }, 100);
        
    } catch (error) {
        console.error('Error loading detail:', error);
        alert('Error loading analysis details');
    }
}

/**
 * Delete a single analysis from history
 */
async function deleteAnalysisHistory(docId) {
    if (!confirm('Delete this analysis? This cannot be undone.')) {
        return;
    }
    
    try {
        const success = await deleteAnalysisFromFirebase(docId);
        if (success) {
            alert('✅ Analysis deleted');
            loadAnalysisHistory(); // Refresh the history
        } else {
            alert('❌ Error deleting analysis');
        }
    } catch (error) {
        console.error('Error deleting:', error);
        alert('Error deleting analysis');
    }
}

/**
 * Clear all analyses from history
 */
async function clearAllHistory() {
    if (!confirm('Delete ALL analyses? This cannot be undone.')) {
        return;
    }
    
    if (!confirm('Are you sure? This will permanently delete all ' + document.querySelectorAll('.history-item').length + ' analyses.')) {
        return;
    }
    
    try {
        const success = await clearAllAnalysesFromFirebase();
        if (success) {
            alert('✅ All analyses deleted');
            loadAnalysisHistory(); // Refresh the history
        } else {
            alert('❌ Error clearing analyses');
        }
    } catch (error) {
        console.error('Error clearing history:', error);
        alert('Error clearing all analyses');
    }
}
