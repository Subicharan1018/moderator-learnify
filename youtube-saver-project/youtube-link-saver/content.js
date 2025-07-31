// content.js

// This function is responsible for creating and inserting the 'Save Link' button.
function createAndInsertButton() {
    // UPDATED SELECTOR for the latest YouTube layout.
    // This targets the container holding the like, share, and download buttons.
    const targetContainer = document.querySelector("#actions-inner");

    // Check if the target container exists and if our button hasn't been added yet.
    if (targetContainer && !document.getElementById('custom-save-link-button')) {
        console.log("Target container found. Creating button.");

        // Create the button element itself
        const saveButton = document.createElement('button');
        saveButton.id = 'custom-save-link-button';
        saveButton.textContent = 'Save Link';

        // Apply styling to the button to make it look like YouTube's buttons
        Object.assign(saveButton.style, {
            backgroundColor: 'rgba(255, 255, 255, 0.1)',
            color: '#fff',
            border: 'none',
            borderRadius: '18px',
            padding: '9px 16px',
            cursor: 'pointer',
            fontFamily: '"Roboto", "Arial", sans-serif',
            fontSize: '14px',
            fontWeight: '500',
            transition: 'background-color 0.3s'
        });

        // Add a hover effect for better user experience.
        saveButton.onmouseover = () => saveButton.style.backgroundColor = 'rgba(255, 255, 255, 0.2)';
        saveButton.onmouseout = () => saveButton.style.backgroundColor = 'rgba(255, 255, 255, 0.1)';

        // This is the main action: what happens when the button is clicked.
        saveButton.addEventListener('click', () => {
            const videoUrl = window.location.href;
            console.log('Save button clicked. Sending URL:', videoUrl);

            // Temporarily disable the button to prevent multiple clicks.
            saveButton.disabled = true;
            saveButton.textContent = 'Saving...';

            // Send a message to the background script (background.js).
            chrome.runtime.sendMessage({ action: 'saveLink', url: videoUrl }, (response) => {
                // This is a callback function that runs after the background script responds.
                if (response && response.status === 'success') {
                    console.log('Successfully saved link.');
                    saveButton.textContent = 'Saved!';
                } else {
                    console.error('Failed to save link:', response ? response.message : 'No response');
                    saveButton.textContent = 'Error!';
                }

                // Revert the button text after 2 seconds and re-enable it.
                setTimeout(() => {
                    saveButton.textContent = 'Save Link';
                    saveButton.disabled = false;
                }, 2000);
            });
        });

        // Create a wrapper for our button to match YouTube's layout structure.
        // This ensures our button fits into the horizontal row correctly.
        const buttonWrapper = document.createElement('div');
        buttonWrapper.style.marginRight = '8px'; // Adds spacing between our button and the next one.
        buttonWrapper.appendChild(saveButton);

        // Insert the wrapper (which contains our button) into the target container.
        targetContainer.prepend(buttonWrapper);
    }
}

// YouTube's page is a single-page application (SPA), meaning content loads
// dynamically without full page reloads. A MutationObserver is the robust
// way to detect when new elements (like the video player) are added to the page.
const observer = new MutationObserver((mutations) => {
    // We loop through the mutations, but really we just need to know that *something* changed.
    // We can then try to find our target container and add the button.
    createAndInsertButton();
});

// Start observing the entire document body for changes to its direct children or entire subtree.
observer.observe(document.body, {
    childList: true,
    subtree: true,
});

// Finally, call the function once on initial script injection, just in case
// the elements are already present when the script loads.
createAndInsertButton();
