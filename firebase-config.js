/**
 * Firebase Configuration & Initialization
 * Cloud Storage for BeforeClick Analysis Results
 */

// Firebase Configuration
const firebaseConfig = {
    apiKey: "AIzaSyAEihBvQzKEPcAMW3aBRlX_InNYvkSj4Fo",
    authDomain: "beforeclick.firebaseapp.com",
    projectId: "beforeclick",
    storageBucket: "beforeclick.firebasestorage.app",
    messagingSenderId: "956948820168",
    appId: "1:956948820168:web:3e11290a6699693ae2f5fd",
    measurementId: "G-HPD8T0EESC"
};

// Initialize Firebase
let db, auth;
let isFirebaseReady = false;

try {
    // Initialize Firebase App
    firebase.initializeApp(firebaseConfig);
    
    // Initialize Firestore Database
    db = firebase.firestore();
    
    // Initialize Authentication
    auth = firebase.auth();
    
    // Enable anonymous authentication
    auth.signInAnonymously().catch((error) => {
        if (error.code === 'auth/operation-not-allowed') {
            console.log('Anonymous Sign-in disabled. Setting up for basic Firestore access.');
        }
    });
    
    isFirebaseReady = true;
    console.log('✅ Firebase initialized successfully');
    
} catch (error) {
    console.error('❌ Firebase initialization failed:', error);
    isFirebaseReady = false;
}

/**
 * Save analysis result to Firestore
 */
async function saveAnalysisToFirebase(analysisData) {
    if (!isFirebaseReady) {
        console.warn('Firebase not ready');
        return null;
    }
    
    try {
        const timestamp = new Date();
        const docRef = await db.collection('analyses').add({
            ...analysisData,
            timestamp: timestamp,
            timestampMillis: timestamp.getTime(),
            userAgent: navigator.userAgent
        });
        
        console.log('✅ Analysis saved to Firebase:', docRef.id);
        return docRef.id;
    } catch (error) {
        console.error('❌ Error saving to Firebase:', error);
        return null;
    }
}

/**
 * Get all analyses from Firestore (limited to last 50)
 */
async function getAnalysesFromFirebase(limit = 50) {
    if (!isFirebaseReady) {
        console.warn('Firebase not ready');
        return [];
    }
    
    try {
        const snapshot = await db.collection('analyses')
            .orderBy('timestamp', 'desc')
            .limit(limit)
            .get();
        
        const analyses = [];
        snapshot.forEach(doc => {
            analyses.push({
                id: doc.id,
                ...doc.data(),
                date: new Date(doc.data().timestamp.toDate())
            });
        });
        
        console.log('✅ Retrieved', analyses.length, 'analyses from Firebase');
        return analyses;
    } catch (error) {
        console.error('❌ Error fetching from Firebase:', error);
        return [];
    }
}

/**
 * Delete single analysis from Firestore
 */
async function deleteAnalysisFromFirebase(docId) {
    if (!isFirebaseReady) {
        console.warn('Firebase not ready');
        return false;
    }
    
    try {
        await db.collection('analyses').doc(docId).delete();
        console.log('✅ Analysis deleted from Firebase');
        return true;
    } catch (error) {
        console.error('❌ Error deleting from Firebase:', error);
        return false;
    }
}

/**
 * Clear all analyses from Firestore
 */
async function clearAllAnalysesFromFirebase() {
    if (!isFirebaseReady) {
        console.warn('Firebase not ready');
        return false;
    }
    
    try {
        const snapshot = await db.collection('analyses').get();
        
        // Delete in batches (Firestore best practice)
        const batch = db.batch();
        snapshot.docs.forEach(doc => {
            batch.delete(doc.ref);
        });
        
        await batch.commit();
        console.log('✅ All analyses cleared from Firebase');
        return true;
    } catch (error) {
        console.error('❌ Error clearing Firebase:', error);
        return false;
    }
}

/**
 * Update analysis in Firestore
 */
async function updateAnalysisInFirebase(docId, updateData) {
    if (!isFirebaseReady) {
        console.warn('Firebase not ready');
        return false;
    }
    
    try {
        await db.collection('analyses').doc(docId).update({
            ...updateData,
            updatedAt: new Date()
        });
        
        console.log('✅ Analysis updated in Firebase');
        return true;
    } catch (error) {
        console.error('❌ Error updating Firebase:', error);
        return false;
    }
}

/**
 * Get analysis by ID from Firestore
 */
async function getAnalysisFromFirebase(docId) {
    if (!isFirebaseReady) {
        console.warn('Firebase not ready');
        return null;
    }
    
    try {
        const doc = await db.collection('analyses').doc(docId).get();
        
        if (doc.exists) {
            return {
                id: doc.id,
                ...doc.data()
            };
        } else {
            console.log('Analysis not found');
            return null;
        }
    } catch (error) {
        console.error('❌ Error fetching analysis from Firebase:', error);
        return null;
    }
}

/**
 * Wait for Firebase to be ready
 */
function waitForFirebase() {
    return new Promise((resolve) => {
        const checkReady = setInterval(() => {
            if (isFirebaseReady) {
                clearInterval(checkReady);
                resolve(true);
            }
        }, 100);
        
        // Timeout after 5 seconds
        setTimeout(() => {
            clearInterval(checkReady);
            resolve(false);
        }, 5000);
    });
}

console.log('🔧 Firebase configuration loaded');
