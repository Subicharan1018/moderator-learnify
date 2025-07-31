function createAndInsertButton() {
    const targetContainer = document.querySelector("ytd-watch-metadata #top-level-buttons-computed");
    if (targetContainer && !document.getElementById('custom-save-link-button-wrapper')) {
        // Main button
        const saveButton = document.createElement('button');
        saveButton.id = 'custom-save-link-button';
        saveButton.textContent = 'Save Link';

        // Iconic Youtube-alignment via flex settings and margins in wrapper
        const buttonWrapper = document.createElement('div');
        buttonWrapper.id = 'custom-save-link-button-wrapper';
        Object.assign(buttonWrapper.style, {
            display: 'flex',
            alignItems: 'center',
            marginRight: '4px',
            height: '100%',
            padding: '0'
        });

        // Bleeding animated red border using CSS class
        const style = document.createElement('style');
        style.textContent = `
        #custom-save-link-button {
            position: relative;
            background: rgba(30,30,30,1);
            color: #fff;
            border: none;
            border-radius: 18px;
            padding: 8px 16px;
            min-height: 32px;
            min-width: 48px;
            cursor: pointer;
            font-family: "Roboto", "Arial", sans-serif;
            font-size: 14px;
            font-weight: 500;
            z-index: 1;
            overflow: hidden;
        }
        #custom-save-link-button::before {
            content: "";
            position: absolute;
            top: -3px; left: -3px; right: -3px; bottom: -3px;
            border-radius: 20px;
            border: 2.5px solid #ff2c2c;
            box-shadow: 0 0 10px 2px #f00, 0 0 40px 6px rgba(255,0,0,0.4);
            z-index: 0;
            opacity: 0.75;
            pointer-events: none;
            animation: bleed-pulse 1.7s infinite alternate cubic-bezier(.68,-0.55,.27,1.55);
        }
        @keyframes bleed-pulse {
            0%   { box-shadow: 0 0 15px 2px #ff2424, 0 0 30px 6px rgba(255,0,0,0.3);}
            50%  { box-shadow: 0 0 35px 6px #ff0033, 0 0 60px 10px rgba(255,0,0,0.7);}
            100% { box-shadow: 0 0 15px 2px #ff4242, 0 0 30px 6px rgba(255,0,0,0.2);}
        }
        #custom-save-link-button:disabled {opacity: 0.7;}
        #custom-save-link-button:hover::before {
            box-shadow: 0 0 20px 3px #ff2929, 0 0 70px 14px rgba(255,0,0,0.8);
            transition: box-shadow 0.25s;
        }
        #custom-save-link-button span {
            position: relative;
            z-index: 2;
        }
        `;

        // Insert `<span>` for text for proper stacking
        const span = document.createElement('span');
        span.textContent = 'Save Link';
        saveButton.textContent = '';
        saveButton.appendChild(span);

        // Save functionality as before
        saveButton.addEventListener('click', () => {
            const videoUrl = window.location.href;
            saveButton.disabled = true;
            span.textContent = 'Saving...';

            chrome.runtime.sendMessage({ action: 'saveLink', url: videoUrl }, (response) => {
                if (response && response.status === 'success') {
                    span.textContent = 'Saved!';
                } else {
                    span.textContent = 'Error!';
                }
                setTimeout(() => {
                    span.textContent = 'Save Link';
                    saveButton.disabled = false;
                }, 2000);
            });
        });

        // Put everything together
        buttonWrapper.appendChild(saveButton);
        targetContainer.prepend(buttonWrapper);

        // Only add the style once
        if (!document.getElementById('bleeding-border-style')) {
            style.id = 'bleeding-border-style';
            document.head.appendChild(style);
        }
    }
}

// SPA support
const observer = new MutationObserver(() => {
    createAndInsertButton();
});

observer.observe(document.body, { childList: true, subtree: true });
createAndInsertButton();
