// background.js - Optimized Service Worker
(() => {
    'use strict';

    // Configuration
    const CONFIG = {
        backendUrl: 'http://localhost:3000',
        endpoints: {
            saveLink: '/save-link',
            checkVideo: '/check-video'
        }
    };

    // State management
    let isProcessing = false;

    // Utility functions
    const utils = {
        // Storage operations with error handling
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

        // Extract video ID
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

                const response = await fetch(`${CONFIG.backendUrl}${endpoint}`, {
                    ...options,
                    headers
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.message || `HTTP error! status: ${response.status}`);
                }

                return data;

            } catch (error) {
                throw error;
            }
        },

        // Save video link
        saveLink: async (url) => {
            return api.makeRequest(CONFIG.endpoints.saveLink, {
                method: 'POST',
                body: JSON.stringify({ url })
            });
        },

        // Check if video is already saved
        checkVideo: async (videoId) => {
            return api.makeRequest(`/user/videos/check/${videoId}`, {
                method: 'GET'
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

                // Check user authentication
                const { userSession } = await utils.getStorage(['userSession']);
                
                if (!userSession?.token) {
                    throw new Error('User not authenticated. Please login first.');
                }

                // Make API call to save video
                const response = await api.saveLink(url);
                
                if (response.status === 'success') {
                    sendResponse(utils.createResponse(
                        'success', 
                        response.message || 'Video saved successfully!',
                        response.data
                    ));
                } else {
                    throw new Error(response.message || 'Failed to save video');
                }

            } catch (error) {
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
                
                sendResponse({
                    authenticated: isAuthenticated,
                    user: userSession || null
                });

            } catch (error) {
                sendResponse({
                    authenticated: false,
                    user: null
                });
            }
        },

        // Handle video status check
        checkVideoStatus: async (request, sender, sendResponse) => {
            try {
                const { url } = request;
                const videoId = utils.extractVideoId(url);
                
                if (!videoId) {
                    sendResponse(utils.createResponse('error', 'Invalid video URL'));
                    return;
                }

                const { userSession } = await utils.getStorage(['userSession']);
                
                if (!userSession?.token) {
                    sendResponse(utils.createResponse('error', 'Not authenticated'));
                    return;
                }

                const response = await api.checkVideo(videoId);
                sendResponse(utils.createResponse('success', 'Video status checked', {
                    isSaved: response.status === 'success' && response.data?.exists,
                    videoData: response.data
                }));

            } catch (error) {
                sendResponse(utils.createResponse('success', 'Video not saved', {
                    isSaved: false
                }));
            }
        },

        // Handle popup open requests
        openPopup: async (request, sender, sendResponse) => {
            try {
                if (chrome.action && chrome.action.openPopup) {
                    await chrome.action.openPopup();
                    sendResponse(utils.createResponse('success', 'Popup opened'));
                } else {
                    throw new Error('Popup API not available');
                }

            } catch (error) {
                sendResponse(utils.createResponse('error', 'Failed to open popup. Please click the extension icon.'));
            }
        }
    };

    // Main message listener
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        try {
            const handler = messageHandlers[request.action];
            
            if (handler) {
                handler(request, sender, sendResponse);
                return true; // Keep message channel open for async response
            } else {
                sendResponse(utils.createResponse('error', `Unknown action: ${request.action}`));
            }

        } catch (error) {
            sendResponse(utils.createResponse('error', 'Internal error processing request'));
        }
    });

    // Handle extension installation
    chrome.runtime.onInstalled.addListener((details) => {
        if (details.reason === 'install') {
            // Set default settings on first install
        }
    });

    // Handle tab updates for video status checking
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
        if (changeInfo.status === 'complete' && 
            tab.url && 
            utils.isValidYouTubeUrl(tab.url)) {
            
            // Notify content script that page is ready
            chrome.tabs.sendMessage(tabId, {
                action: 'pageReady',
                url: tab.url
            }).catch(() => {
                // Ignore errors if content script is not ready
            });
        }
    });

    // Global error handler
    self.addEventListener('error', (event) => {
        // Handle errors silently in production
    });

    // Unhandled promise rejection handler
    self.addEventListener('unhandledrejection', (event) => {
        event.preventDefault();
    });

})();