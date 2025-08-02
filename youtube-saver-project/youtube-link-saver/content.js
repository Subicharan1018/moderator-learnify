// content.js - Optimized YouTube Integration
(() => {
  'use strict';

  // Configuration
  const CONFIG = {
    selectors: {
      // Multiple selectors for button container (YouTube layout changes frequently)
      buttonContainers: [
        'ytd-watch-metadata #top-level-buttons-computed',
        'ytd-video-primary-info-renderer #top-level-buttons-computed',
        '#top-level-buttons-computed',
        'ytd-watch-metadata ytd-menu-renderer + div',
        '[id="top-level-buttons-computed"]'
      ]
    },
    elements: {
      buttonWrapperId: 'custom-save-link-button-wrapper',
      buttonId: 'custom-save-link-button',
      tooltipId: 'custom-save-link-tooltip',
      styleId: 'custom-save-link-styles'
    },
    debounceDelay: 300,
    maxRetries: 5,
    retryDelay: 1000
  };

  // State management
  let state = {
    isAuthenticated: false,
    currentUser: null,
    isInjected: false,
    isInitializing: false,
    observer: null,
    debounceTimer: null
  };

  // Utility functions
  const utils = {
    // Log with timestamp and context
    log: (message, data = null) => {
      const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
      console.log(`[${timestamp}] ContentScript:`, message, data || '');
    },

    // Debounce function to prevent excessive calls
    debounce: (func, delay) => {
      return (...args) => {
        clearTimeout(state.debounceTimer);
        state.debounceTimer = setTimeout(() => func.apply(this, args), delay);
      };
    },

    // Check if current page is a YouTube video
    isYouTubeVideoPage: () => {
      try {
        return window.location.hostname === 'www.youtube.com' && 
               window.location.pathname === '/watch' &&
               window.location.search.includes('v=');
      } catch {
        return false;
      }
    },

    // Wait for element with timeout
    waitForElement: (selector, timeout = 5000) => {
      return new Promise((resolve, reject) => {
        const element = document.querySelector(selector);
        if (element) {
          resolve(element);
          return;
        }

        const observer = new MutationObserver((mutations, obs) => {
          const element = document.querySelector(selector);
          if (element) {
            obs.disconnect();
            resolve(element);
          }
        });

        observer.observe(document.body, {
          childList: true,
          subtree: true
        });

        setTimeout(() => {
          observer.disconnect();
          reject(new Error(`Element not found: ${selector}`));
        }, timeout);
      });
    },

    // Send message to background script with promise
    sendMessage: (message) => {
      return new Promise((resolve) => {
        try {
          chrome.runtime.sendMessage(message, (response) => {
            if (chrome.runtime.lastError) {
              utils.log('Runtime error:', chrome.runtime.lastError.message);
              resolve({ status: 'error', message: chrome.runtime.lastError.message });
            } else {
              resolve(response || { status: 'error', message: 'No response received' });
            }
          });
        } catch (error) {
          utils.log('Send message error:', error.message);
          resolve({ status: 'error', message: error.message });
        }
      });
    },

    // Safe DOM manipulation
    safeExecute: (fn, context = 'unknown') => {
      try {
        return fn();
      } catch (error) {
        utils.log(`Error in ${context}:`, error.message);
        return null;
      }
    }
  };

  // Authentication management
  const auth = {
    // Check authentication status
    checkStatus: async () => {
      try {
        const response = await utils.sendMessage({ action: 'checkAuth' });
        
        if (response && typeof response.authenticated === 'boolean') {
          state.isAuthenticated = response.authenticated;
          state.currentUser = response.user;
          utils.log('Auth status updated', { 
            authenticated: state.isAuthenticated, 
            user: state.currentUser?.email 
          });
          return state.isAuthenticated;
        }
        
        return false;
      } catch (error) {
        utils.log('Auth check failed:', error.message);
        state.isAuthenticated = false;
        state.currentUser = null;
        return false;
      }
    },

    // Handle login redirect
    redirectToLogin: async () => {
      try {
        const response = await utils.sendMessage({ action: 'openPopup' });
        
        if (response.status !== 'success') {
          // Fallback: show instruction to user
          ui.showTooltipMessage('Please click the extension icon to login', 3000);
        }
      } catch (error) {
        utils.log('Login redirect failed:', error.message);
        ui.showTooltipMessage('Please click the extension icon to login', 3000);
      }
    }
  };

  // CSS injection
  const styles = {
    // Inject styles safely
    inject: () => {
      return utils.safeExecute(() => {
        if (document.getElementById(CONFIG.elements.styleId)) {
          return true;
        }

        const style = document.createElement('style');
        style.id = CONFIG.elements.styleId;
        style.textContent = styles.getCSS();
        
        document.head.appendChild(style);
        utils.log('Styles injected successfully');
        return true;
      }, 'style injection');
    },

    // Get CSS content
    getCSS: () => `
      @property --angle {
        syntax: "<angle>";
        initial-value: 0deg;
        inherits: false;
      }

      #${CONFIG.elements.buttonWrapperId} {
        position: relative;
        overflow: visible !important;
        z-index: 1000;
        display: flex;
        align-items: center;
        margin-right: 8px;
        height: 100%;
      }

      #${CONFIG.elements.buttonId} {
        position: relative;
        background: rgba(30, 30, 30, 0.8);
        color: #fff;
        border: solid 2px transparent;
        border-radius: 18px;
        padding: 8px 16px;
        cursor: pointer;
        font-family: "Roboto", "Arial", sans-serif;
        font-size: 1.4rem;
        font-weight: 500;
        letter-spacing: 0.5px;
        overflow: visible !important;
        z-index: 2;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 36px;
        transition: all 0.2s ease;
        min-width: 80px;
      }

      #${CONFIG.elements.buttonId}:hover {
        background: rgba(50, 50, 50, 0.9);
      }

      #${CONFIG.elements.buttonId}.unauthenticated {
        background: rgba(60, 30, 30, 0.8);
      }

      #${CONFIG.elements.buttonId}.unauthenticated:hover {
        background: rgba(80, 40, 40, 0.9);
      }

      #${CONFIG.elements.buttonId}::before {
        content: "";
        position: absolute;
        inset: -2px;
        border: inherit;
        border-radius: inherit;
        background: conic-gradient(
          from var(--angle),
          #ff0000 40%,
          transparent,
          #ff0000 60%
        ) border-box;
        mask: conic-gradient(#fff 0 0) subtract,
             conic-gradient(#fff 0 0) padding-box;
        z-index: -1;
        animation: rotating-border 3s linear infinite;
      }

      #${CONFIG.elements.buttonId}.unauthenticated::before {
        background: conic-gradient(
          from var(--angle),
          #ff6600 40%,
          transparent,
          #ff6600 60%
        ) border-box;
      }

      @keyframes rotating-border {
        from { --angle: 0deg; }
        to { --angle: 360deg; }
      }

      #${CONFIG.elements.buttonId}:hover::before {
        animation-duration: 1.5s;
      }

      #${CONFIG.elements.buttonId}:disabled {
        opacity: 0.7;
        cursor: not-allowed;
        background: rgba(40, 40, 40, 0.6);
      }

      #${CONFIG.elements.buttonId}:disabled::before {
        animation: none;
        opacity: 0.3;
      }

      #${CONFIG.elements.buttonId} span {
        position: relative;
        z-index: 1;
        white-space: nowrap;
      }

      #${CONFIG.elements.tooltipId} {
        position: absolute;
        bottom: -35px;
        left: 50%;
        transform: translateX(-50%);
        background: rgba(0, 0, 0, 0.9);
        color: #fff;
        padding: 6px 10px;
        border-radius: 4px;
        font-size: 0.8rem;
        white-space: nowrap;
        opacity: 0;
        pointer-events: none;
        transition: opacity 0.2s ease;
        z-index: 1001;
        max-width: 200px;
        text-align: center;
      }

      #${CONFIG.elements.buttonId}:hover #${CONFIG.elements.tooltipId} {
        opacity: 1;
      }

      @media (max-width: 656px) {
        #${CONFIG.elements.buttonId} {
          padding: 6px 12px;
          font-size: 1.3rem;
          height: 32px;
          min-width: 70px;
        }
      }

      /* Animation for state changes */
      .fade-in {
        animation: fadeIn 0.3s ease-in;
      }

      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-5px); }
        to { opacity: 1; transform: translateY(0); }
      }
    `
  };

  // UI management
  const ui = {
    // Create save button
    createButton: async () => {
      return utils.safeExecute(async () => {
        if (document.getElementById(CONFIG.elements.buttonWrapperId)) {
          utils.log('Button already exists, skipping creation');
          return true;
        }

        if (!utils.isYouTubeVideoPage()) {
          utils.log('Not a YouTube video page, skipping button creation');
          return false;
        }

        // Check authentication status
        await auth.checkStatus();

        // Find button container
        const buttonContainer = await ui.findButtonContainer();
        if (!buttonContainer) {
          utils.log('Button container not found');
          return false;
        }

        // Create elements
        const wrapper = ui.createElement('div', {
          id: CONFIG.elements.buttonWrapperId,
          className: 'fade-in'
        });

        const button = ui.createElement('button', {
          id: CONFIG.elements.buttonId,
          type: 'button',
          className: state.isAuthenticated ? '' : 'unauthenticated'
        });

        const buttonText = ui.createElement('span', {
          textContent: state.isAuthenticated ? 'Save' : 'Login'
        });

        const tooltip = ui.createElement('div', {
          id: CONFIG.elements.tooltipId,
          textContent: state.isAuthenticated 
            ? 'Save this video to your collection' 
            : 'Click to login and save videos'
        });

        // Assemble elements
        button.appendChild(buttonText);
        button.appendChild(tooltip);
        wrapper.appendChild(button);

        // Add event listener
        button.addEventListener('click', ui.handleButtonClick);

        // Insert into page
        ui.insertButton(buttonContainer, wrapper);

        utils.log('Button created successfully', { 
          authenticated: state.isAuthenticated,
          user: state.currentUser?.email 
        });
        
        state.isInjected = true;
        return true;

      }, 'button creation');
    },

    // Find button container with multiple fallbacks
    findButtonContainer: async () => {
      for (const selector of CONFIG.selectors.buttonContainers) {
        try {
          const container = await utils.waitForElement(selector, 2000);
          if (container) {
            utils.log('Found button container', { selector });
            return container;
          }
        } catch {
          // Continue to next selector
        }
      }
      
      utils.log('No button container found');
      return null;
    },

    // Create DOM element with properties
    createElement: (tag, props = {}) => {
      const element = document.createElement(tag);
      
      Object.entries(props).forEach(([key, value]) => {
        if (key === 'textContent') {
          element.textContent = value;
        } else if (key === 'className') {
          element.className = value;
        } else {
          element.setAttribute(key, value);
        }
      });

      return element;
    },

    // Insert button into container
    insertButton: (container, wrapper) => {
      try {
        // Insert after the first button (usually Like button) or at beginning
        const firstButton = container.children[1];
        if (firstButton) {
          container.insertBefore(wrapper, firstButton);
        } else {
          container.appendChild(wrapper);
        }
      } catch (error) {
        utils.log('Error inserting button:', error.message);
        container.appendChild(wrapper);
      }
    },

    // Handle button click
    handleButtonClick: async (event) => {
      event.preventDefault();
      event.stopPropagation();

      const button = event.currentTarget;
      const buttonText = button.querySelector('span');
      const tooltip = button.querySelector(`#${CONFIG.elements.tooltipId}`);

      if (!state.isAuthenticated) {
        await auth.redirectToLogin();
        return;
      }

      // Save video
      try {
        const originalText = buttonText.textContent;
        const originalTooltip = tooltip.textContent;

        // Set loading state
        button.disabled = true;
        buttonText.textContent = 'Saving...';
        tooltip.textContent = 'Processing your request...';

        const response = await utils.sendMessage({
          action: 'saveLink',
          url: window.location.href
        });

        if (response.status === 'success') {
          buttonText.textContent = 'Saved!';
          tooltip.textContent = response.message || 'Video saved successfully!';
          button.style.background = 'rgba(40, 100, 40, 0.8)';
        } else {
          buttonText.textContent = 'Error!';
          tooltip.textContent = response.message || 'Failed to save video';
          button.style.background = 'rgba(100, 40, 40, 0.8)';
        }

        // Reset after 3 seconds
        setTimeout(() => {
          buttonText.textContent = originalText;
          tooltip.textContent = originalTooltip;
          button.disabled = false;
          button.style.background = '';
        }, 3000);

      } catch (error) {
        utils.log('Button click error:', error.message);
        ui.showTooltipMessage('An error occurred', 2000);
      }
    },

    // Update button based on authentication status
    updateAuthState: async () => {
      const button = document.getElementById(CONFIG.elements.buttonId);
      const buttonText = button?.querySelector('span');
      const tooltip = document.getElementById(CONFIG.elements.tooltipId);

      if (!button) return;

      await auth.checkStatus();

      if (state.isAuthenticated) {
        button.classList.remove('unauthenticated');
        if (buttonText) buttonText.textContent = 'Save';
        if (tooltip) tooltip.textContent = 'Save this video to your collection';
      } else {
        button.classList.add('unauthenticated');
        if (buttonText) buttonText.textContent = 'Login';
        if (tooltip) tooltip.textContent = 'Click to login and save videos';
      }

      utils.log('Button auth state updated', { authenticated: state.isAuthenticated });
    },

    // Show temporary tooltip message
    showTooltipMessage: (message, duration = 2000) => {
      const tooltip = document.getElementById(CONFIG.elements.tooltipId);
      if (!tooltip) return;

      const originalText = tooltip.textContent;
      tooltip.textContent = message;
      tooltip.style.opacity = '1';

      setTimeout(() => {
        tooltip.textContent = originalText;
        tooltip.style.opacity = '';
      }, duration);
    }
  };

  // Observer management
  const observer = {
    // Start mutation observer
    start: () => {
      if (state.observer) {
        observer.stop();
      }

      state.observer = new MutationObserver(
        utils.debounce(observer.handleMutations, CONFIG.debounceDelay)
      );

      state.observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: false,
        characterData: false
      });

      utils.log('MutationObserver started');
    },

    // Stop mutation observer
    stop: () => {
      if (state.observer) {
        state.observer.disconnect();
        state.observer = null;
        utils.log('MutationObserver stopped');
      }
    },

    // Handle mutations
    handleMutations: (mutations) => {
      try {
        let shouldReinit = false;

        // Check if we're on a YouTube video page
        if (!utils.isYouTubeVideoPage()) {
          if (state.isInjected) {
            // Clean up if we left a video page
            const existingButton = document.getElementById(CONFIG.elements.buttonWrapperId);
            if (existingButton) {
              existingButton.remove();
              state.isInjected = false;
              utils.log('Button removed (left video page)');
            }
          }
          return;
        }

        // Check if button container exists but our button is missing
        for (const selector of CONFIG.selectors.buttonContainers) {
          const container = document.querySelector(selector);
          if (container && !document.getElementById(CONFIG.elements.buttonWrapperId)) {
            shouldReinit = true;
            break;
          }
        }

        if (shouldReinit) {
          utils.log('Reinitializing due to DOM changes');
          state.isInjected = false;
          initialization.init();
        }

      } catch (error) {
        utils.log('MutationObserver error:', error.message);
      }
    }
  };

  // Storage listener for authentication changes
  const storageListener = (changes, namespace) => {
    if (namespace === 'local' && changes.userSession) {
      utils.log('User session changed, updating UI');
      ui.updateAuthState();
    }
  };

  // Initialization
  const initialization = {
    // Initialize the extension
    init: async (retryCount = 0) => {
      if (state.isInitializing) {
        utils.log('Initialization already in progress');
        return;
      }

      try {
        state.isInitializing = true;
        utils.log('Initializing content script', { attempt: retryCount + 1 });

        // Check if we're on a YouTube video page
        if (!utils.isYouTubeVideoPage()) {
          utils.log('Not a YouTube video page, skipping initialization');
          return;
        }

        // Inject styles
        const stylesInjected = styles.inject();
        if (!stylesInjected) {
          throw new Error('Failed to inject styles');
        }

        // Create button
        const buttonCreated = await ui.createButton();
        if (!buttonCreated) {
          throw new Error('Failed to create button');
        }

        utils.log('Content script initialized successfully');

      } catch (error) {
        utils.log('Initialization error', { error: error.message, attempt: retryCount + 1 });

        if (retryCount < CONFIG.maxRetries) {
          const delay = CONFIG.retryDelay * (retryCount + 1);
          utils.log(`Retrying initialization in ${delay}ms`);
          setTimeout(() => initialization.init(retryCount + 1), delay);
        } else {
          utils.log('Max retries reached, giving up initialization');
        }
      } finally {
        state.isInitializing = false;
      }
    },

    // Start the extension
    start: () => {
      utils.log('Starting YouTube Link Saver content script');

      // Set up storage listener
      if (chrome.storage && chrome.storage.onChanged) {
        chrome.storage.onChanged.addListener(storageListener);
      }

      // Initialize immediately if page is ready
      if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setTimeout(() => {
          initialization.init();
          observer.start();
        }, 1000);
      } else {
        // Wait for DOM to be ready
        const initWhenReady = () => {
          initialization.init();
          observer.start();
        };

        document.addEventListener('DOMContentLoaded', initWhenReady);
        window.addEventListener('load', initWhenReady);
      }

      // Handle page navigation (YouTube SPA)
      let currentUrl = window.location.href;
      const checkUrlChange = () => {
        if (window.location.href !== currentUrl) {
          currentUrl = window.location.href;
          utils.log('URL changed, reinitializing', { newUrl: currentUrl });
          
          // Reset state
          state.isInjected = false;
          
          // Reinitialize after a short delay
          setTimeout(() => initialization.init(), 500);
        }
      };

      // Check for URL changes periodically (YouTube SPA navigation)
      setInterval(checkUrlChange, 1000);

      // Listen for history changes
      const originalPushState = history.pushState;
      const originalReplaceState = history.replaceState;

      history.pushState = function(...args) {
        originalPushState.apply(history, args);
        setTimeout(checkUrlChange, 100);
      };

      history.replaceState = function(...args) {
        originalReplaceState.apply(history, args);
        setTimeout(checkUrlChange, 100);
      };

      window.addEventListener('popstate', () => {
        setTimeout(checkUrlChange, 100);
      });

      utils.log('Content script setup complete');
    },

    // Cleanup function
    cleanup: () => {
      utils.log('Cleaning up content script');

      // Stop observer
      observer.stop();

      // Remove storage listener
      if (chrome.storage && chrome.storage.onChanged) {
        chrome.storage.onChanged.removeListener(storageListener);
      }

      // Clear timers
      if (state.debounceTimer) {
        clearTimeout(state.debounceTimer);
      }

      // Remove injected elements
      const button = document.getElementById(CONFIG.elements.buttonWrapperId);
      const styles = document.getElementById(CONFIG.elements.styleId);
      
      if (button) button.remove();
      if (styles) styles.remove();

      // Reset state
      state = {
        isAuthenticated: false,
        currentUser: null,
        isInjected: false,
        isInitializing: false,
        observer: null,
        debounceTimer: null
      };

      utils.log('Cleanup complete');
    }
  };

  // Global error handlers
  window.addEventListener('error', (event) => {
    if (event.filename && event.filename.includes('content.js')) {
      utils.log('Global error in content script', {
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno
      });
    }
  });

  window.addEventListener('unhandledrejection', (event) => {
    utils.log('Unhandled promise rejection in content script', {
      reason: event.reason
    });
  });

  // Handle page unload
  window.addEventListener('beforeunload', () => {
    initialization.cleanup();
  });

  // Start the extension
  initialization.start();

})();