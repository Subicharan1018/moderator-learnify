// popup.js - Complete Chrome Extension Popup Script
(() => {
    'use strict';

    // Configuration
    const CONFIG = {
        backendUrl: 'http://localhost:3000',
        endpoints: {
            login: '/auth/login',
            signup: '/auth/signup',
            stats: '/user/stats',
            saveLink: '/save-link'
        }
    };

    // State management
    let currentUser = null;
    let isLoading = false;
    let currentTab = null;

    // DOM elements - with null checking
    const elements = {
        // Forms
        loginForm: document.getElementById('loginForm'),
        signupForm: document.getElementById('signupForm'),
        dashboard: document.getElementById('dashboard'),
        
        // Form elements
        loginFormElement: document.getElementById('loginFormElement'),
        signupFormElement: document.getElementById('signupFormElement'),
        
        // Buttons
        loginBtn: document.getElementById('loginBtn'),
        signupBtn: document.getElementById('signupBtn'),
        showSignupBtn: document.getElementById('showSignupBtn'),
        showLoginBtn: document.getElementById('showLoginBtn'),
        logoutBtn: document.getElementById('logoutBtn'),
        saveCurrentBtn: document.getElementById('saveCurrentBtn'),
        
        // Messages
        loginMessage: document.getElementById('loginMessage'),
        signupMessage: document.getElementById('signupMessage'),
        
        // Dashboard elements
        userEmail: document.getElementById('userEmail'),
        savedCount: document.getElementById('savedCount'),
        approvedCount: document.getElementById('approvedCount'),
        currentPageInfo: document.getElementById('currentPageInfo')
    };

    // Check if all critical elements exist
    const checkRequiredElements = () => {
        const required = ['loginForm', 'signupForm', 'dashboard', 'loginFormElement', 'signupFormElement'];
        const missing = required.filter(id => !elements[id]);
        
        if (missing.length > 0) {
            console.error('Missing required elements:', missing);
            return false;
        }
        return true;
    };

    // Utility functions
    const utils = {
        // Show message with type (error/success)
        showMessage: (element, message, type = 'error') => {
            if (!element) return;
            
            element.className = type;
            element.textContent = message;
            element.style.display = 'block';
            
            setTimeout(() => {
                element.style.display = 'none';
                element.className = '';
                element.textContent = '';
            }, 5000);
        },

        // Set loading state for button
        setLoading: (button, loading, loadingText = 'Loading...') => {
            if (!button) return;
            
            if (loading) {
                button.disabled = true;
                const span = button.querySelector('span');
                if (span) {
                    span.innerHTML = `<span class="loading"></span>${loadingText}`;
                } else {
                    button.innerHTML = `<span class="loading"></span>${loadingText}`;
                }
            } else {
                button.disabled = false;
                const span = button.querySelector('span');
                const originalText = button.getAttribute('data-original-text') || 'Submit';
                if (span) {
                    span.innerHTML = originalText;
                } else {
                    button.innerHTML = `<span>${originalText}</span>`;
                }
            }
        },

        // Validate email format
        validateEmail: (email) => {
            const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return re.test(email);
        },

        // Validate password strength
        validatePassword: (password) => {
            return password.length >= 6;
        },

        // Store original button text
        storeOriginalButtonText: (button) => {
            if (button && !button.getAttribute('data-original-text')) {
                const span = button.querySelector('span');
                const text = span ? span.textContent : button.textContent;
                button.setAttribute('data-original-text', text);
            }
        },

        // Format numbers
        formatNumber: (num) => {
            return parseInt(num).toLocaleString();
        },

        // Animate number counter
        animateCounter: (element, targetValue, duration = 1000) => {
            if (!element) return;
            
            const startValue = parseInt(element.textContent) || 0;
            const increment = (targetValue - startValue) / (duration / 16);
            let currentValue = startValue;
            
            const timer = setInterval(() => {
                currentValue += increment;
                if ((increment > 0 && currentValue >= targetValue) || 
                    (increment < 0 && currentValue <= targetValue)) {
                    currentValue = targetValue;
                    clearInterval(timer);
                }
                element.textContent = Math.floor(currentValue);
            }, 16);
        }
    };

    // Storage management
    const storage = {
        // Save user session
        saveSession: (userData) => {
            return new Promise((resolve, reject) => {
                try {
                    if (typeof chrome !== 'undefined' && chrome.storage) {
                        chrome.storage.local.set({ userSession: userData }, () => {
                            if (chrome.runtime.lastError) {
                                reject(chrome.runtime.lastError);
                            } else {
                                resolve();
                            }
                        });
                    } else {
                        // Fallback for testing
                        localStorage.setItem('userSession', JSON.stringify(userData));
                        resolve();
                    }
                } catch (error) {
                    reject(error);
                }
            });
        },

        // Get user session
        getSession: () => {
            return new Promise((resolve, reject) => {
                try {
                    if (typeof chrome !== 'undefined' && chrome.storage) {
                        chrome.storage.local.get(['userSession'], (result) => {
                            if (chrome.runtime.lastError) {
                                reject(chrome.runtime.lastError);
                            } else {
                                resolve(result.userSession || null);
                            }
                        });
                    } else {
                        // Fallback for testing
                        const session = localStorage.getItem('userSession');
                        resolve(session ? JSON.parse(session) : null);
                    }
                } catch (error) {
                    reject(error);
                }
            });
        },

        // Clear user session
        clearSession: () => {
            return new Promise((resolve, reject) => {
                try {
                    if (typeof chrome !== 'undefined' && chrome.storage) {
                        chrome.storage.local.remove(['userSession'], () => {
                            if (chrome.runtime.lastError) {
                                reject(chrome.runtime.lastError);
                            } else {
                                resolve();
                            }
                        });
                    } else {
                        // Fallback for testing
                        localStorage.removeItem('userSession');
                        resolve();
                    }
                } catch (error) {
                    reject(error);
                }
            });
        }
    };

    // API management
    const api = {
        // Make authenticated request
        request: async (endpoint, options = {}) => {
            try {
                const userSession = await storage.getSession();
                const headers = {
                    'Content-Type': 'application/json',
                    ...options.headers
                };

                if (userSession?.token) {
                    headers.Authorization = `Bearer ${userSession.token}`;
                }

                console.log(`Making API request to: ${CONFIG.backendUrl}${endpoint}`);

                const response = await fetch(`${CONFIG.backendUrl}${endpoint}`, {
                    ...options,
                    headers
                });

                let data;
                const contentType = response.headers.get('content-type');
                if (contentType?.includes('application/json')) {
                    data = await response.json();
                } else {
                    const text = await response.text();
                    console.log('Non-JSON response:', text);
                    throw new Error(`Unexpected response format: ${contentType}`);
                }

                if (!response.ok) {
                    throw new Error(data.message || data.error || `HTTP error! status: ${response.status}`);
                }

                return data;
            } catch (error) {
                console.error('API request failed:', error);
                throw error;
            }
        },

        // Login user
        login: async (email, password) => {
            return api.request(CONFIG.endpoints.login, {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
        },

        // Register user
        signup: async (name, email, password) => {
            return api.request(CONFIG.endpoints.signup, {
                method: 'POST',
                body: JSON.stringify({ name, email, password })
            });
        },

        // Get user stats
        getStats: async () => {
            return api.request(CONFIG.endpoints.stats);
        },

        // Save current video
        saveCurrentVideo: async (url) => {
            return api.request(CONFIG.endpoints.saveLink, {
                method: 'POST',
                body: JSON.stringify({ url })
            });
        }
    };

    // Navigation functions
    const navigation = {
        showLogin: () => {
            if (elements.loginForm) elements.loginForm.classList.add('active');
            if (elements.signupForm) elements.signupForm.classList.remove('active');
            if (elements.dashboard) elements.dashboard.classList.remove('active');
            if (elements.loginMessage) {
                elements.loginMessage.style.display = 'none';
                elements.loginMessage.textContent = '';
            }
        },

        showSignup: () => {
            if (elements.loginForm) elements.loginForm.classList.remove('active');
            if (elements.signupForm) elements.signupForm.classList.add('active');
            if (elements.dashboard) elements.dashboard.classList.remove('active');
            if (elements.signupMessage) {
                elements.signupMessage.style.display = 'none';
                elements.signupMessage.textContent = '';
            }
        },

        showDashboard: () => {
            if (elements.loginForm) elements.loginForm.classList.remove('active');
            if (elements.signupForm) elements.signupForm.classList.remove('active');
            if (elements.dashboard) elements.dashboard.classList.add('active');
            dashboard.loadStats();
            dashboard.updateCurrentPageInfo();
        }
    };

    // Authentication handlers
    const auth = {
        // Handle login
        login: async (formData) => {
            if (isLoading) return;
            
            try {
                isLoading = true;
                utils.setLoading(elements.loginBtn, true, 'Signing in...');

                const { email, password } = formData;

                // Validation
                if (!utils.validateEmail(email)) {
                    throw new Error('Please enter a valid email address');
                }

                if (!utils.validatePassword(password)) {
                    throw new Error('Password must be at least 6 characters long');
                }

                console.log('Attempting login for:', email);

                // API call
                const response = await api.login(email, password);
                
                console.log('Login response received:', response);

                // Handle different possible response structures
                let userData = null;
                let token = null;

                // Check for token in various locations
                if (response.token) {
                    token = response.token;
                    userData = response.user || { email };
                } else if (response.accessToken) {
                    token = response.accessToken;
                    userData = response.user || { email };
                } else if (response.access_token) {
                    token = response.access_token;
                    userData = response.user || { email };
                } else if (response.user?.token) {
                    token = response.user.token;
                    userData = response.user;
                } else if (response.data?.token) {
                    token = response.data.token;
                    userData = response.data.user || response.user || { email };
                } else if (response.jwt) {
                    token = response.jwt;
                    userData = response.user || { email };
                } else {
                    // If no explicit token, but response indicates success
                    if (response.success || response.status === 'success' || response.message?.includes('success')) {
                        token = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                        userData = response.user || response.data || { 
                            email: email,
                            id: response.id || response.userId || Date.now()
                        };
                        console.log('No explicit token found, creating session token:', token);
                    }
                }

                if (!token) {
                    console.error('Token extraction failed. Full response:', response);
                    throw new Error('No authentication token received from server.');
                }

                // Prepare user session data
                const sessionData = {
                    token: token,
                    email: userData.email || email,
                    name: userData.name || userData.fullName || userData.username || email.split('@')[0],
                    id: userData.id || userData._id || userData.userId,
                    ...userData
                };

                console.log('Saving session data:', sessionData);

                // Save session
                await storage.saveSession(sessionData);
                currentUser = sessionData;

                // Update UI
                if (elements.userEmail) {
                    elements.userEmail.textContent = `Welcome, ${sessionData.name}!`;
                }

                // Show success and redirect
                utils.showMessage(elements.loginMessage, 'Login successful!', 'success');
                
                setTimeout(() => {
                    navigation.showDashboard();
                }, 1000);

            } catch (error) {
                console.error('Login error:', error);
                
                let errorMessage = 'Login failed. Please try again.';
                
                if (error.message.includes('fetch')) {
                    errorMessage = 'Cannot connect to server. Please check if the server is running.';
                } else if (error.message.includes('token')) {
                    errorMessage = error.message;
                } else if (error.message.includes('401') || error.message.includes('unauthorized')) {
                    errorMessage = 'Invalid email or password.';
                } else if (error.message.includes('400')) {
                    errorMessage = 'Please check your email and password format.';
                } else if (error.message.includes('500')) {
                    errorMessage = 'Server error. Please try again later.';
                } else if (error.message) {
                    errorMessage = error.message;
                }
                
                utils.showMessage(elements.loginMessage, errorMessage, 'error');
            } finally {
                isLoading = false;
                utils.setLoading(elements.loginBtn, false);
            }
        },

        // Handle signup
        signup: async (formData) => {
            if (isLoading) return;
            
            try {
                isLoading = true;
                utils.setLoading(elements.signupBtn, true, 'Creating account...');

                const { name, email, password, confirmPassword } = formData;

                // Validation
                if (!name.trim()) {
                    throw new Error('Full name is required');
                }

                if (!utils.validateEmail(email)) {
                    throw new Error('Please enter a valid email address');
                }

                if (!utils.validatePassword(password)) {
                    throw new Error('Password must be at least 6 characters long');
                }

                if (password !== confirmPassword) {
                    throw new Error('Passwords do not match');
                }

                console.log('Attempting signup for:', email);

                // API call
                const response = await api.signup(name, email, password);
                
                console.log('Signup response received:', response);

                // Handle different possible response structures (same logic as login)
                let userData = null;
                let token = null;

                if (response.token) {
                    token = response.token;
                    userData = response.user || { email, name };
                } else if (response.accessToken) {
                    token = response.accessToken;
                    userData = response.user || { email, name };
                } else if (response.access_token) {
                    token = response.access_token;
                    userData = response.user || { email, name };
                } else if (response.user?.token) {
                    token = response.user.token;
                    userData = response.user;
                } else if (response.data?.token) {
                    token = response.data.token;
                    userData = response.data.user || response.user || { email, name };
                } else if (response.jwt) {
                    token = response.jwt;
                    userData = response.user || { email, name };
                } else {
                    if (response.success || response.status === 'success' || response.message?.includes('success')) {
                        token = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                        userData = response.user || response.data || { 
                            email: email,
                            name: name,
                            id: response.id || response.userId || Date.now()
                        };
                        console.log('No explicit token found, creating session token:', token);
                    }
                }

                if (!token) {
                    console.error('Token extraction failed. Full response:', response);
                    throw new Error('No authentication token received from server.');
                }

                // Prepare user session data
                const sessionData = {
                    token: token,
                    email: userData.email || email,
                    name: userData.name || userData.fullName || userData.username || name,
                    id: userData.id || userData._id || userData.userId,
                    ...userData
                };

                console.log('Saving session data:', sessionData);

                // Save session
                await storage.saveSession(sessionData);
                currentUser = sessionData;

                // Update UI
                if (elements.userEmail) {
                    elements.userEmail.textContent = `Welcome, ${sessionData.name}!`;
                }

                // Show success and redirect
                utils.showMessage(elements.signupMessage, 'Account created successfully!', 'success');
                
                setTimeout(() => {
                    navigation.showDashboard();
                }, 1000);

            } catch (error) {
                console.error('Signup error:', error);
                
                let errorMessage = 'Signup failed. Please try again.';
                
                if (error.message.includes('fetch')) {
                    errorMessage = 'Cannot connect to server. Please check if the server is running.';
                } else if (error.message.includes('token')) {
                    errorMessage = error.message;
                } else if (error.message.includes('409') || error.message.includes('already exists')) {
                    errorMessage = 'An account with this email already exists.';
                } else if (error.message.includes('400')) {
                    errorMessage = 'Please check your information and try again.';
                } else if (error.message.includes('500')) {
                    errorMessage = 'Server error. Please try again later.';
                } else if (error.message) {
                    errorMessage = error.message;
                }
                
                utils.showMessage(elements.signupMessage, errorMessage, 'error');
            } finally {
                isLoading = false;
                utils.setLoading(elements.signupBtn, false);
            }
        },

        // Handle logout
        logout: async () => {
            try {
                await storage.clearSession();
                currentUser = null;
                navigation.showLogin();
                
                // Reset forms
                if (elements.loginFormElement) elements.loginFormElement.reset();
                if (elements.signupFormElement) elements.signupFormElement.reset();
                
                // Clear messages
                if (elements.loginMessage) {
                    elements.loginMessage.style.display = 'none';
                    elements.loginMessage.textContent = '';
                }
                if (elements.signupMessage) {
                    elements.signupMessage.style.display = 'none';
                    elements.signupMessage.textContent = '';
                }
                
            } catch (error) {
                console.error('Logout error:', error);
            }
        }
    };

    // Dashboard functionality
    const dashboard = {
        // Load user stats
        loadStats: async () => {
            try {
                const response = await api.getStats();
                console.log('Stats response:', response);
                
                // Handle different response structures
                let savedCount = 0;
                let approvedCount = 0;

                if (response.savedCount !== undefined) {
                    savedCount = response.savedCount;
                    approvedCount = response.approvedCount || 0;
                } else if (response.data) {
                    savedCount = response.data.savedCount || 0;
                    approvedCount = response.data.approvedCount || 0;
                } else if (response.stats) {
                    savedCount = response.stats.savedCount || 0;
                    approvedCount = response.stats.approvedCount || 0;
                }

                utils.animateCounter(elements.savedCount, savedCount);
                utils.animateCounter(elements.approvedCount, approvedCount);
                
            } catch (error) {
                console.error('Failed to load stats:', error);
                if (elements.savedCount) elements.savedCount.textContent = '0';
                if (elements.approvedCount) elements.approvedCount.textContent = '0';
            }
        },

        // Update current page info
        updateCurrentPageInfo: async () => {
            try {
                if (typeof chrome !== 'undefined' && chrome.tabs) {
                    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
                    currentTab = tabs[0];
                    
                    if (currentTab?.url?.includes('youtube.com/watch')) {
                        elements.currentPageInfo.textContent = 'YouTube video detected! Click to save this video.';
                        if (elements.saveCurrentBtn) elements.saveCurrentBtn.disabled = false;
                    } else {
                        elements.currentPageInfo.textContent = 'Navigate to a YouTube video to save it';
                        if (elements.saveCurrentBtn) elements.saveCurrentBtn.disabled = true;
                    }
                } else {
                    elements.currentPageInfo.textContent = 'Navigate to a YouTube video to save it';
                    if (elements.saveCurrentBtn) elements.saveCurrentBtn.disabled = true;
                }
            } catch (error) {
                console.error('Failed to get current tab:', error);
                if (elements.currentPageInfo) {
                    elements.currentPageInfo.textContent = 'Navigate to a YouTube video to save it';
                }
                if (elements.saveCurrentBtn) elements.saveCurrentBtn.disabled = true;
            }
        },

        // Save current video
        saveCurrentVideo: async () => {
            if (isLoading || !currentTab?.url) return;
            
            try {
                isLoading = true;
                utils.setLoading(elements.saveCurrentBtn, true, 'Saving...');

                const response = await api.saveCurrentVideo(currentTab.url);
                console.log('Save video response:', response);
                
                // Handle different response structures
                const isSuccess = response && (
                    response.status === 'success' || 
                    response.success === true ||
                    response.message?.includes('success') ||
                    response.saved === true
                );

                if (isSuccess) {
                    if (elements.currentPageInfo) {
                        elements.currentPageInfo.textContent = 'Video saved successfully!';
                        elements.currentPageInfo.style.color = '#00ff00';
                        setTimeout(() => {
                            elements.currentPageInfo.style.color = '';
                        }, 3000);
                    }
                    dashboard.loadStats(); // Refresh stats
                } else {
                    throw new Error(response?.message || response?.error || 'Failed to save video');
                }

            } catch (error) {
                console.error('Failed to save video:', error);
                if (elements.currentPageInfo) {
                    elements.currentPageInfo.textContent = error.message;
                    elements.currentPageInfo.style.color = '#ff0000';
                    setTimeout(() => {
                        elements.currentPageInfo.style.color = '';
                        dashboard.updateCurrentPageInfo();
                    }, 3000);
                }
            } finally {
                isLoading = false;
                utils.setLoading(elements.saveCurrentBtn, false);
            }
        }
    };

    // Event listeners
    const setupEventListeners = () => {
        // Store original button texts
        Object.values(elements).forEach(element => {
            if (element?.tagName === 'BUTTON') {
                utils.storeOriginalButtonText(element);
            }
        });

        // Navigation buttons
        if (elements.showSignupBtn) {
            elements.showSignupBtn.addEventListener('click', navigation.showSignup);
        }
        if (elements.showLoginBtn) {
            elements.showLoginBtn.addEventListener('click', navigation.showLogin);
        }
        if (elements.logoutBtn) {
            elements.logoutBtn.addEventListener('click', auth.logout);
        }

        // Form submissions
        if (elements.loginFormElement) {
            elements.loginFormElement.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                await auth.login(Object.fromEntries(formData));
            });
        }

        if (elements.signupFormElement) {
            elements.signupFormElement.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                await auth.signup(Object.fromEntries(formData));
            });
        }

        // Dashboard actions
        if (elements.saveCurrentBtn) {
            elements.saveCurrentBtn.addEventListener('click', dashboard.saveCurrentVideo);
        }

        // Real-time password confirmation validation
        const confirmPasswordInput = document.getElementById('confirmPassword');
        const signupPasswordInput = document.getElementById('signupPassword');
        
        if (confirmPasswordInput && signupPasswordInput) {
            confirmPasswordInput.addEventListener('input', () => {
                if (confirmPasswordInput.value && confirmPasswordInput.value !== signupPasswordInput.value) {
                    confirmPasswordInput.setCustomValidity('Passwords do not match');
                } else {
                    confirmPasswordInput.setCustomValidity('');
                }
            });
        }
    };

    // Initialization
    const init = async () => {
        try {
            console.log('Initializing popup...');
            
            // Check if required elements exist
            if (!checkRequiredElements()) {
                console.error('Required elements missing. Cannot initialize.');
                return;
            }
            
            // Setup event listeners
            setupEventListeners();
            
            // Check existing session
            const userSession = await storage.getSession();
            console.log('Existing session:', userSession);
            
            if (userSession?.token) {
                currentUser = userSession;
                if (elements.userEmail) {
                    elements.userEmail.textContent = `Welcome, ${userSession.name || userSession.email}!`;
                }
                navigation.showDashboard();
            } else {
                navigation.showLogin();
            }
            
            console.log('Popup initialized successfully');
            
        } catch (error) {
            console.error('Initialization error:', error);
            navigation.showLogin();
        }
    };

    // Start the popup when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Handle popup visibility changes
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden && currentUser) {
            dashboard.updateCurrentPageInfo();
        }
    });

})();