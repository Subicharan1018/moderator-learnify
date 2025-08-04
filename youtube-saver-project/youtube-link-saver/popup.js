// popup.js - Optimized Chrome Extension Popup Script
(() => {
    'use strict';

    // Configuration
    const CONFIG = {
        backendUrl: 'http://localhost:3000',
        endpoints: {
            login: '/auth/login',
            signup: '/auth/signup',
            stats: '/user/stats',
            saveLink: '/save-link',
            checkVideo: '/user/videos/check'
        }
    };

    // State management
    let currentUser = null;
    let isLoading = false;
    let currentTab = null;
    let currentVideoSaved = false;

    // DOM elements
    const elements = {
        loginForm: document.getElementById('loginForm'),
        signupForm: document.getElementById('signupForm'),
        dashboard: document.getElementById('dashboard'),
        loginFormElement: document.getElementById('loginFormElement'),
        signupFormElement: document.getElementById('signupFormElement'),
        loginBtn: document.getElementById('loginBtn'),
        signupBtn: document.getElementById('signupBtn'),
        showSignupBtn: document.getElementById('showSignupBtn'),
        showLoginBtn: document.getElementById('showLoginBtn'),
        logoutBtn: document.getElementById('logoutBtn'),
        saveCurrentBtn: document.getElementById('saveCurrentBtn'),
        loginMessage: document.getElementById('loginMessage'),
        signupMessage: document.getElementById('signupMessage'),
        userEmail: document.getElementById('userEmail'),
        savedCount: document.getElementById('savedCount'),
        approvedCount: document.getElementById('approvedCount'),
        currentPageInfo: document.getElementById('currentPageInfo')
    };

    // Check if all critical elements exist
    const checkRequiredElements = () => {
        const required = ['loginForm', 'signupForm', 'dashboard', 'loginFormElement', 'signupFormElement'];
        const missing = required.filter(id => !elements[id]);
        return missing.length === 0;
    };

    // Utility functions
    const utils = {
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

        validateEmail: (email) => {
            const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return re.test(email);
        },

        validatePassword: (password) => {
            return password.length >= 6;
        },

        storeOriginalButtonText: (button) => {
            if (button && !button.getAttribute('data-original-text')) {
                const span = button.querySelector('span');
                const text = span ? span.textContent : button.textContent;
                button.setAttribute('data-original-text', text);
            }
        },

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
        },

        extractVideoId: (url) => {
            try {
                const urlObj = new URL(url);
                if (urlObj.hostname === 'youtu.be') {
                    return urlObj.pathname.slice(1);
                }
                return urlObj.searchParams.get('v');
            } catch {
                return null;
            }
        },

        isYouTubeVideoUrl: (url) => {
            try {
                const urlObj = new URL(url);
                return urlObj.hostname === 'www.youtube.com' && 
                       urlObj.pathname === '/watch' &&
                       urlObj.searchParams.has('v');
            } catch {
                return false;
            }
        }
    };

    // Storage management
    const storage = {
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
                        localStorage.setItem('userSession', JSON.stringify(userData));
                        resolve();
                    }
                } catch (error) {
                    reject(error);
                }
            });
        },

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
                        const session = localStorage.getItem('userSession');
                        resolve(session ? JSON.parse(session) : null);
                    }
                } catch (error) {
                    reject(error);
                }
            });
        },

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
                    throw new Error(`Unexpected response format: ${contentType}`);
                }

                if (!response.ok) {
                    throw new Error(data.message || data.error || `HTTP error! status: ${response.status}`);
                }

                return data;
            } catch (error) {
                throw error;
            }
        },

        login: async (email, password) => {
            return api.request(CONFIG.endpoints.login, {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
        },

        signup: async (name, email, password) => {
            return api.request(CONFIG.endpoints.signup, {
                method: 'POST',
                body: JSON.stringify({ name, email, password })
            });
        },

        getStats: async () => {
            return api.request(CONFIG.endpoints.stats);
        },

        saveCurrentVideo: async (url) => {
            return api.request(CONFIG.endpoints.saveLink, {
                method: 'POST',
                body: JSON.stringify({ url })
            });
        },

        checkVideoSaved: async (videoId) => {
            return api.request(`${CONFIG.endpoints.checkVideo}/${videoId}`);
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
        login: async (formData) => {
            if (isLoading) return;
            
            try {
                isLoading = true;
                utils.setLoading(elements.loginBtn, true, 'Signing in...');

                const { email, password } = formData;

                if (!utils.validateEmail(email)) {
                    throw new Error('Please enter a valid email address');
                }

                if (!utils.validatePassword(password)) {
                    throw new Error('Password must be at least 6 characters long');
                }

                const response = await api.login(email, password);
                
                let userData = null;
                let token = null;

                if (response.token) {
                    token = response.token;
                    userData = response.user || { email };
                } else if (response.user?.token) {
                    token = response.user.token;
                    userData = response.user;
                } else if (response.data?.token) {
                    token = response.data.token;
                    userData = response.data.user || response.user || { email };
                } else if (response.data?.user?.token) {
                    token = response.data.user.token;
                    userData = response.data.user;
                } else {
                    if (response.success || response.status === 'success') {
                        token = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                        userData = response.user || response.data || { 
                            email: email,
                            id: response.id || response.userId || Date.now()
                        };
                    }
                }

                if (!token) {
                    throw new Error('No authentication token received from server.');
                }

                const sessionData = {
                    token: token,
                    email: userData.email || email,
                    name: userData.name || userData.fullName || userData.username || email.split('@')[0],
                    id: userData.id || userData._id || userData.userId,
                    ...userData
                };

                await storage.saveSession(sessionData);
                currentUser = sessionData;

                if (elements.userEmail) {
                    elements.userEmail.textContent = `Welcome, ${sessionData.name}!`;
                }

                utils.showMessage(elements.loginMessage, 'Login successful!', 'success');
                
                setTimeout(() => {
                    navigation.showDashboard();
                }, 1000);

            } catch (error) {
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

        signup: async (formData) => {
            if (isLoading) return;
            
            try {
                isLoading = true;
                utils.setLoading(elements.signupBtn, true, 'Creating account...');

                const { name, email, password, confirmPassword } = formData;

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

                const response = await api.signup(name, email, password);
                
                let userData = null;
                let token = null;

                if (response.token) {
                    token = response.token;
                    userData = response.user || { email, name };
                } else if (response.user?.token) {
                    token = response.user.token;
                    userData = response.user;
                } else if (response.data?.token) {
                    token = response.data.token;
                    userData = response.data.user || response.user || { email, name };
                } else if (response.data?.user?.token) {
                    token = response.data.user.token;
                    userData = response.data.user;
                } else {
                    if (response.success || response.status === 'success') {
                        token = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                        userData = response.user || response.data || { 
                            email: email,
                            name: name,
                            id: response.id || response.userId || Date.now()
                        };
                    }
                }

                if (!token) {
                    throw new Error('No authentication token received from server.');
                }

                const sessionData = {
                    token: token,
                    email: userData.email || email,
                    name: userData.name || userData.fullName || userData.username || name,
                    id: userData.id || userData._id || userData.userId,
                    ...userData
                };

                await storage.saveSession(sessionData);
                currentUser = sessionData;

                if (elements.userEmail) {
                    elements.userEmail.textContent = `Welcome, ${sessionData.name}!`;
                }

                utils.showMessage(elements.signupMessage, 'Account created successfully!', 'success');
                
                setTimeout(() => {
                    navigation.showDashboard();
                }, 1000);

            } catch (error) {
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

        logout: async () => {
            try {
                await storage.clearSession();
                currentUser = null;
                currentVideoSaved = false;
                navigation.showLogin();
                
                if (elements.loginFormElement) elements.loginFormElement.reset();
                if (elements.signupFormElement) elements.signupFormElement.reset();
                
                if (elements.loginMessage) {
                    elements.loginMessage.style.display = 'none';
                    elements.loginMessage.textContent = '';
                }
                if (elements.signupMessage) {
                    elements.signupMessage.style.display = 'none';
                    elements.signupMessage.textContent = '';
                }
                
            } catch (error) {
                // Handle logout errors silently
            }
        }
    };

    // Dashboard functionality
    const dashboard = {
        loadStats: async () => {
            try {
                const response = await api.getStats();
                
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
                if (elements.savedCount) elements.savedCount.textContent = '0';
                if (elements.approvedCount) elements.approvedCount.textContent = '0';
            }
        },

        updateCurrentPageInfo: async () => {
            try {
                if (typeof chrome !== 'undefined' && chrome.tabs) {
                    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
                    currentTab = tabs[0];
                    
                    if (currentTab?.url && utils.isYouTubeVideoUrl(currentTab.url)) {
                        // Check if video is already saved
                        const videoId = utils.extractVideoId(currentTab.url);
                        if (videoId) {
                            try {
                                const checkResponse = await api.checkVideoSaved(videoId);
                                currentVideoSaved = checkResponse.status === 'success' && checkResponse.data?.exists;
                            } catch (error) {
                                currentVideoSaved = false;
                            }
                        }

                        if (currentVideoSaved) {
                            elements.currentPageInfo.textContent = 'This video is already saved in your collection!';
                            elements.currentPageInfo.style.color = '#90EE90';
                            if (elements.saveCurrentBtn) {
                                elements.saveCurrentBtn.innerHTML = '<span>Already Saved</span>';
                                elements.saveCurrentBtn.disabled = true;
                                elements.saveCurrentBtn.style.background = 'rgba(30, 80, 30, 0.8)';
                            }
                        } else {
                            elements.currentPageInfo.textContent = 'YouTube video detected! Click to save this video.';
                            elements.currentPageInfo.style.color = '';
                            if (elements.saveCurrentBtn) {
                                elements.saveCurrentBtn.innerHTML = '<span>Save Current Video</span>';
                                elements.saveCurrentBtn.disabled = false;
                                elements.saveCurrentBtn.style.background = '';
                            }
                        }
                    } else {
                        elements.currentPageInfo.textContent = 'Navigate to a YouTube video to save it';
                        elements.currentPageInfo.style.color = '';
                        if (elements.saveCurrentBtn) {
                            elements.saveCurrentBtn.disabled = true;
                            elements.saveCurrentBtn.style.background = '';
                        }
                    }
                } else {
                    elements.currentPageInfo.textContent = 'Navigate to a YouTube video to save it';
                    if (elements.saveCurrentBtn) elements.saveCurrentBtn.disabled = true;
                }
            } catch (error) {
                if (elements.currentPageInfo) {
                    elements.currentPageInfo.textContent = 'Navigate to a YouTube video to save it';
                }
                if (elements.saveCurrentBtn) elements.saveCurrentBtn.disabled = true;
            }
        },

        saveCurrentVideo: async () => {
            if (isLoading || !currentTab?.url || currentVideoSaved) return;
            
            try {
                isLoading = true;
                utils.setLoading(elements.saveCurrentBtn, true, 'Saving...');

                const response = await api.saveCurrentVideo(currentTab.url);
                
                const isSuccess = response && (
                    response.status === 'success' || 
                    response.success === true ||
                    response.message?.includes('success') ||
                    response.saved === true
                );

                if (isSuccess) {
                    currentVideoSaved = true;
                    if (elements.currentPageInfo) {
                        elements.currentPageInfo.textContent = 'Video saved successfully!';
                        elements.currentPageInfo.style.color = '#00ff00';
                    }
                    
                    // Update button to show saved state
                    if (elements.saveCurrentBtn) {
                        elements.saveCurrentBtn.innerHTML = '<span>Already Saved</span>';
                        elements.saveCurrentBtn.disabled = true;
                        elements.saveCurrentBtn.style.background = 'rgba(30, 80, 30, 0.8)';
                    }
                    
                    dashboard.loadStats(); // Refresh stats
                } else {
                    throw new Error(response?.message || response?.error || 'Failed to save video');
                }

            } catch (error) {
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
                if (!currentVideoSaved) {
                    utils.setLoading(elements.saveCurrentBtn, false);
                }
            }
        }
    };

    // Event listeners
    const setupEventListeners = () => {
        Object.values(elements).forEach(element => {
            if (element?.tagName === 'BUTTON') {
                utils.storeOriginalButtonText(element);
            }
        });

        if (elements.showSignupBtn) {
            elements.showSignupBtn.addEventListener('click', navigation.showSignup);
        }
        if (elements.showLoginBtn) {
            elements.showLoginBtn.addEventListener('click', navigation.showLogin);
        }
        if (elements.logoutBtn) {
            elements.logoutBtn.addEventListener('click', auth.logout);
        }

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

        if (elements.saveCurrentBtn) {
            elements.saveCurrentBtn.addEventListener('click', dashboard.saveCurrentVideo);
        }

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
            if (!checkRequiredElements()) {
                return;
            }
            
            setupEventListeners();
            
            const userSession = await storage.getSession();
            
            if (userSession?.token) {
                currentUser = userSession;
                if (elements.userEmail) {
                    elements.userEmail.textContent = `Welcome, ${userSession.name || userSession.email}!`;
                }
                navigation.showDashboard();
            } else {
                navigation.showLogin();
            }
            
        } catch (error) {
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