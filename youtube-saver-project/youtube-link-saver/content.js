// content.js
(() => {
  'use strict';

  // Safely inject styles with error handling
  const injectStyles = () => {
    try {
      if (document.getElementById('custom-save-link-styles')) return;

      const style = document.createElement('style');
      style.id = 'custom-save-link-styles';
      
      // First add the style element to the DOM
      document.head.appendChild(style);
      
      // Now we can safely access the sheet property
      const sheet = style.sheet;
      const cssRules = [
        `@property --angle {
          syntax: "<angle>";
          initial-value: 0deg;
          inherits: false;
        }`,
        `#custom-save-link-button-wrapper {
          position: relative;
          overflow: visible !important;
          z-index: 1000;
          display: flex;
          align-items: center;
          margin-right: 8px;
          height: 100%;
        }`,
        `#custom-save-link-button {
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
        }`,
        `#custom-save-link-button:hover {
          background: rgba(50, 50, 50, 0.9);
        }`,
        `#custom-save-link-button::before {
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
        }`,

        `@keyframes rotating-border {
          from {
            --angle: 0deg;
          }
          to {
            --angle: 360deg;
          }
        }`,
        `#custom-save-link-button:hover::before {
          animation-duration: 1.5s;
        }`,
        `#custom-save-link-button:disabled {
          opacity: 0.7;
          cursor: not-allowed;
          background: rgba(40, 40, 40, 0.6);
        }`,
        `#custom-save-link-button:disabled::before {
          animation: none;
          opacity: 0.3;
        }`,
        `#custom-save-link-button span {
          position: relative;
          z-index: 1;
          white-space: nowrap;
        }`,
        `@media (max-width: 656px) {
          #custom-save-link-button {
            padding: 6px 12px;
            font-size: 1.3rem;
            height: 32px;
          }
        }`
      ];

      // Add rules one by one with error handling
      cssRules.forEach(rule => {
        try {
          sheet.insertRule(rule, sheet.cssRules.length);
        } catch (e) {
          console.error('Error inserting CSS rule:', e);
          // Fallback to textContent if CSSOM fails
          style.textContent += rule + '\n';
        }
      });
      
    } catch (error) {
      console.error('Error injecting styles:', error);
    }
  };

  // Create and insert save button with error handling
  const createSaveButton = () => {
    try {
      // Check if already injected
      if (document.getElementById('custom-save-link-button-wrapper')) return;
      
      // Find YouTube's button container with multiple selector options
      const buttonContainer = document.querySelector(
        'ytd-watch-metadata #top-level-buttons-computed, ' + 
        'ytd-video-primary-info-renderer #top-level-buttons-computed, ' +
        '#top-level-buttons-computed, ' +
        'ytd-watch-metadata ytd-menu-renderer.ytd-watch-metadata + div'
      );
      
      if (!buttonContainer) {
        console.log('Button container not found');
        return;
      }

      // Create wrapper
      const wrapper = document.createElement('div');
      wrapper.id = 'custom-save-link-button-wrapper';
      wrapper.style.marginLeft = '8px';
      
      // Create button
      const button = document.createElement('button');
      button.id = 'custom-save-link-button';
      button.setAttribute('type', 'button');
      
      // Create button text
      const buttonText = document.createElement('span');
      buttonText.textContent = 'Save';
      button.appendChild(buttonText);
      
      // Click handler with error handling
      button.addEventListener('click', () => {
        try {
          const originalText = buttonText.textContent;
          button.disabled = true;
          buttonText.textContent = 'Saving...';
          
          chrome.runtime.sendMessage(
            { action: 'saveLink', url: window.location.href },
            (response) => {
              try {
                if (response?.status === 'success') {
                  buttonText.textContent = 'Saved!';
                } else {
                  buttonText.textContent = 'Error!';
                  console.error('Save failed:', response?.error);
                }
                
                // Reset after 2 seconds
                setTimeout(() => {
                  buttonText.textContent = originalText;
                  button.disabled = false;
                }, 2000);
              } catch (e) {
                console.error('Error handling response:', e);
                buttonText.textContent = 'Error!';
                setTimeout(() => {
                  buttonText.textContent = originalText;
                  button.disabled = false;
                }, 2000);
              }
            }
          );
        } catch (e) {
          console.error('Error in click handler:', e);
          button.disabled = false;
        }
      });

      // Assemble elements
      wrapper.appendChild(button);
      
      // Insert after the Like button container or at beginning
      if (buttonContainer.firstChild) {
        buttonContainer.insertBefore(wrapper, buttonContainer.children[1]);
      } else {
        buttonContainer.appendChild(wrapper);
      }
      
    } catch (error) {
      console.error('Error creating save button:', error);
    }
  };

  // Initialize with retry logic
  const init = (retryCount = 0) => {
    try {
      injectStyles();
      createSaveButton();
    } catch (error) {
      console.error('Initialization error:', error);
      if (retryCount < 3) {
        setTimeout(() => init(retryCount + 1), 1000 * (retryCount + 1));
      }
    }
  };

  // Optimized MutationObserver
  const observer = new MutationObserver((mutations) => {
    try {
      let shouldReinit = false;
      
      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
          // Check if the button container exists but our button is missing
          const buttonContainer = document.querySelector(
            'ytd-watch-metadata #top-level-buttons-computed, ' + 
            'ytd-video-primary-info-renderer #top-level-buttons-computed'
          );
          
          if (buttonContainer && !document.getElementById('custom-save-link-button-wrapper')) {
            shouldReinit = true;
            break;
          }
        }
      }
      
      if (shouldReinit) {
        init();
      }
    } catch (e) {
      console.error('MutationObserver error:', e);
    }
  });

  // Initial execution with delay to ensure YouTube has loaded
  const startObserver = () => {
    try {
      init();
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: false,
        characterData: false
      });
    } catch (e) {
      console.error('Observer start error:', e);
    }
  };

  // Wait for YouTube to load
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(startObserver, 1000);
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(startObserver, 1000);
    });
    window.addEventListener('load', () => {
      setTimeout(startObserver, 1000);
    });
  }
})();