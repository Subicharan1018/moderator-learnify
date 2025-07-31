// background.js

// This script runs in the background of the browser, listening for events.

// Add a listener for messages sent from other parts of the extension (like content.js).
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Check if the message is the one we're interested in.
    if (request.action === 'saveLink') {
        const videoUrl = request.url;
        console.log('Background script received message to save URL:', videoUrl);

        // Define the URL of our local backend server.
        const backendUrl = 'http://localhost:3000/save-link';

        // Use the `fetch` API to send a POST request to our server.
        fetch(backendUrl, {
            method: 'POST',
            // Set headers to indicate we are sending JSON data.
            headers: {
                'Content-Type': 'application/json',
            },
            // The `body` of the request must be a JSON string.
            body: JSON.stringify({ url: videoUrl }),
        })
        .then(response => {
            // The first .then() handles the raw HTTP response.
            // We need to check if the response was successful (e.g., status 200).
            if (!response.ok) {
                // If not okay, throw an error to be caught by the .catch() block.
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            // If the response is okay, parse its body as JSON.
            return response.json();
        })
        .then(data => {
            // This .then() handles the parsed JSON data from the server's response.
            console.log('Received response from backend:', data);
            // Send a success response back to the content script.
            sendResponse({ status: 'success', message: data.message });
        })
        .catch(error => {
            // This .catch() block will execute if the fetch request fails for any reason
            // (e.g., network error, server is not running, CORS issue).
            console.error('Error sending data to backend:', error);
            // Send an error response back to the content script.
            sendResponse({ status: 'error', message: error.message });
        });

        // IMPORTANT: Return `true` from the event listener.
        // This tells Chrome to keep the messaging channel open because we will
        // be sending a response asynchronously after the `fetch` call is complete.
        // Without this, the channel would close immediately and sendResponse would fail.
        return true;
    }
});
