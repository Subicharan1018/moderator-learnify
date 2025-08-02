// background.js - Optimized Service Worker
(() => {
    'use strict';

    // Configuration
    const CONFIG = {
        backendUrl: 'http://localhost:3000',
        endpoints: {
            saveLink: '/save-link'
        }
    };

    // State management
    let isProcessing = false;

    // Utility functions
    const utils = {
        // Log with timestamp
        log: (message, data = null) => {
            const timestamp = new Date().toISOString();
            console.log(`[${timestamp}] Background:`, message, data || '');
        },

        // Handle storage operations with error handling
        getStorage: (keys) => {
            return new Promise((resolve, reject) => {
                try {
                    chrome.storage.local.get(keys, (result) => {
                        if (chrome.runtime.lastError) {
                            reject(chrome.runtime.lastError);
                        } else {
                            resolve(result);
                        }
                    });
                } catch (error) {
                    reject(error);
                }
            });
        },

        // Validate YouTube URL
        isValidYouTubeUrl: (url) => {
            try {
                const urlObj = new URL(url);
                return urlObj.hostname === 'www.youtube.com' && 
                       urlObj.pathname === '/watch' && 
                       urlObj.searchParams.has('v');
            } catch {
                return false;
            }
        },

        // Create standardized response
        createResponse: (status, message, data = null) => {
            return {
                status,
                message,
                timestamp: new Date().toISOString(),
                ...(data && { data })
            };
        }
    };

    // API management
    const api = {
        // Make authenticated request to backend
        makeRequest: async (endpoint, options = {}) => {
            try {
                const { userSession } = await utils.getStorage(['userSession']);
                
                if (!userSession?.token) {
                    throw new Error('User not authenticated');
                }

                const headers = {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${userSession.token}`,
                    ...options.headers
                };

                utils.log('Making API request', { endpoint, method: options.method || 'GET' });

                const response = await fetch(`${CONFIG.backendUrl}${endpoint}`, {
                    ...options,
                    headers
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.message || `HTTP error! status: ${response.status}`);
                }

                utils.log('API request successful', { endpoint, status: response.status });
                return data;

            } catch (error) {
                utils.log('API request failed', { endpoint, error: error.message });
                throw error;
            }
        },

        // Save video link
        saveLink: async (url) => {
            return api.makeRequest(CONFIG.endpoints.saveLink, {
                method: 'POST',
                body: JSON.stringify({ url })
            });
        }
    };

    // Message handlers
    const messageHandlers = {
        // Handle save link requests
        saveLink: async (request, sender, sendResponse) => {
            if (isProcessing) {
                sendResponse(utils.createResponse('error', 'Another save operation is in progress'));
                return;
            }

            try {
                isProcessing = true;
                
                const { url } = request;
                
                if (!url) {
                    throw new Error('URL is required');
                }

                if (!utils.isValidYouTubeUrl(url)) {
                    throw new Error('Invalid YouTube URL');
                }

                utils.log('Processing save link request', { url });

                // Check user authentication
                const { userSession } = await utils.getStorage(['userSession']);
                
                if (!userSession?.token) {
                    throw new Error('User not authenticated. Please login first.');
                }

                // Make API call to save video
                const response = await api.saveLink(url);
                
                if (response.status === 'success') {
                    utils.log('Video saved successfully', { 
                        videoId: response.data?.video_id,
                        title: response.data?.title 
                    });
                    
                    sendResponse(utils.createResponse(
                        'success', 
                        response.message || 'Video saved successfully!',
                        response.data
                    ));
                } else {
                    throw new Error(response.message || 'Failed to save video');
                }

            } catch (error) {
                utils.log('Save link error', { error: error.message });
                
                let errorMessage = error.message;
                if (error.message.includes('fetch')) {
                    errorMessage = 'Unable to connect to server. Please ensure the backend is running.';
                } else if (error.message.includes('Authentication') || error.message.includes('token')) {
                    errorMessage = 'Please login again to continue.';
                }

                sendResponse(utils.createResponse('error', errorMessage));
            } finally {
                isProcessing = false;
            }
        },

        // Handle authentication check requests
        checkAuth: async (request, sender, sendResponse) => {
            try {
                const { userSession } = await utils.getStorage(['userSession']);
                const isAuthenticated = !!(userSession?.token);
                
                utils.log('Auth check', { authenticated: isAuthenticated, user: userSession?.email });
                
                sendResponse({
                    authenticated: isAuthenticated,
                    user: userSession || null
                });

            } catch (error) {
                utils.log('Auth check error', { error: error.message });
                sendResponse({
                    authenticated: false,
                    user: null
                });
            }
        },

        // Handle popup open requests
        openPopup: async (request, sender, sendResponse) => {
            try {
                utils.log('Opening popup for authentication');
                
                // Use chrome.action.openPopup() for Manifest V3
                if (chrome.action && chrome.action.openPopup) {
                    await chrome.action.openPopup();
                    sendResponse(utils.createResponse('success', 'Popup opened'));
                } else {
                    throw new Error('Popup API not available');
                }

            } catch (error) {
                utils.log('Error opening popup', { error: error.message });
                sendResponse(utils.createResponse('error', 'Failed to open popup. Please click the extension icon.'));
            }
        }
    };

    // Main message listener
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        try {
            utils.log('Received message', { action: request.action, sender: sender.tab?.url });

            const handler = messageHandlers[request.action];
            
            if (handler) {
                // Execute handler asynchronously
                handler(request, sender, sendResponse);
                return true; // Keep message channel open for async response
            } else {
                utils.log('Unknown action received', { action: request.action });
                sendResponse(utils.createResponse('error', `Unknown action: ${request.action}`));
            }

        } catch (error) {
            utils.log('Message handler error', { error: error.message });
            sendResponse(utils.createResponse('error', 'Internal error processing request'));
        }
    });

    // Handle extension startup
    chrome.runtime.onStartup.addListener(() => {
        utils.log('Extension started');
    });

    // Handle extension installation
    chrome.runtime.onInstalled.addListener((details) => {
        utils.log('Extension installed/updated', { reason: details.reason });
        
        if (details.reason === 'install') {
            // Set default settings or show welcome message
            utils.log('First time installation');
        } else if (details.reason === 'update') {
            utils.log('Extension updated', { 
                previousVersion: details.previousVersion,
                currentVersion: chrome.runtime.getManifest().version 
            });
        }
    });

    // Handle tab updates (optional - for future features)
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
        // Only process when tab is completely loaded and is a YouTube watch page
        if (changeInfo.status === 'complete' && 
            tab.url && 
            utils.isValidYouTubeUrl(tab.url)) {
            
            utils.log('YouTube video page loaded', { tabId, url: tab.url });
            
            // Could potentially inject content script here if needed
            // or perform other tab-specific operations
        }
    });

    // Global error handler
    self.addEventListener('error', (event) => {
        utils.log('Global error', { 
            message: event.message, 
            filename: event.filename, 
            lineno: event.lineno 
        });
    });

    // Unhandled promise rejection handler
    self.addEventListener('unhandledrejection', (event) => {
        utils.log('Unhandled promise rejection', { reason: event.reason });
        event.preventDefault(); // Prevent the default browser behavior
    });

    utils.log('Background script initialized successfully');

})();