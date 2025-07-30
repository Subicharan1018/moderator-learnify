from flask import Flask, request, jsonify, render_template_string
import re
from yt_dlp import YoutubeDL
from datetime import datetime
import traceback
import json

app = Flask(__name__)

def extract_video_id_from_iframe(iframe_input):
    iframe_patterns = [
        r'src=["\']https?://www\.youtube\.com/embed/([a-zA-Z0-9_-]{11})["\']',
        r'src=["\']https?://youtube\.com/embed/([a-zA-Z0-9_-]{11})["\']',
        r'https?://www\.youtube\.com/embed/([a-zA-Z0-9_-]{11})',
        r'https?://youtube\.com/embed/([a-zA-Z0-9_-]{11})',
        r'youtu\.be/([a-zA-Z0-9_-]{11})',
        r'youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})',
    ]
    
    for pattern in iframe_patterns:
        match = re.search(pattern, iframe_input)
        if match:
            return match.group(1)
    return None

def fetch_youtube_metadata(video_id):
    """Fetch YouTube video metadata using yt-dlp"""
    url = f"https://www.youtube.com/watch?v={video_id}"
    
    ydl_opts = {
        'quiet': True,
        'no_warnings': True,
    }
    
    try:
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            
            # Format duration from seconds to MM:SS or HH:MM:SS
            duration_seconds = info.get('duration', 0)
            if duration_seconds:
                hours = duration_seconds // 3600
                minutes = (duration_seconds % 3600) // 60
                seconds = duration_seconds % 60
                if hours > 0:
                    duration = f"{hours}:{minutes:02d}:{seconds:02d}"
                else:
                    duration = f"{minutes}:{seconds:02d}"
            else:
                duration = "0:00"
            
            # Format view count
            view_count = info.get('view_count', 0)
            if view_count >= 1000000:
                views = f"{view_count // 1000000}M views"
            elif view_count >= 1000:
                views = f"{view_count // 1000}K views"
            else:
                views = f"{view_count} views"
            
            # Format upload date
            upload_date = info.get('upload_date', '')
            if upload_date:
                formatted_date = f"{upload_date[:4]}-{upload_date[4:6]}-{upload_date[6:8]}"
            else:
                formatted_date = ""
            
            # Get thumbnail URL (highest quality available)
            thumbnail = info.get('thumbnail', '')
            if not thumbnail and info.get('thumbnails'):
                thumbnail = info['thumbnails'][-1]['url']
            
            # Format subscriber count
            subscriber_count = info.get('channel_follower_count', 0)
            if subscriber_count >= 1000000:
                subscribers = f"{subscriber_count // 1000000}M"
            elif subscriber_count >= 1000:
                subscribers = f"{subscriber_count // 1000}K"
            else:
                subscribers = str(subscriber_count)
            
            # Get chapters if available
            chapters = []
            if info.get('chapters'):
                for chapter in info['chapters']:
                    chapters.append({
                        "title": chapter.get('title', ''),
                        "start_time": chapter.get('start_time', 0),
                        "end_time": chapter.get('end_time', 0)
                    })
            
            # Get tags
            tags = info.get('tags', [])
            
            return {
                "video_id": video_id,
                "title": info.get('title', ''),
                "url": url,
                "embed_url": f"https://www.youtube.com/embed/{video_id}",
                "thumbnail": thumbnail,
                "duration": duration,
                "views": views,
                "upload_date": formatted_date,
                "description": info.get('description', ''),
                "channel": {
                    "name": info.get('channel', ''),
                    "url": info.get('channel_url', ''),
                    "subscribers": subscribers,
                    "verified": info.get('channel_is_verified', False),
                    "logo": info.get('channel_thumbnail', '')
                },
                "category": info.get('categories', ['Unknown']),
                "age_rating": info.get('age_limit', 'N/A'),
                "content_flags": {
                    "violence": False,
                    "explicit_language": False,
                    "sensitive_topics": False
                },
                "likes": info.get('like_count', 0),
                "dislikes": info.get('dislike_count', 0),
                "comments_enabled": info.get('comment_count', 0) > 0,
                "comment_count": info.get('comment_count', 0),
                "tags": tags,
                "chapters": chapters,
                "approved": True,
                "approved_by": "admin@protube.com",
                "last_updated": datetime.now().isoformat() + "Z"
            }
    except Exception as e:
        raise Exception(f"Error fetching video data: {str(e)}")

# HTML template for the web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>YouTube Video Data Extractor</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .input-section {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 10px;
            font-weight: bold;
            color: #555;
        }
        textarea {
            width: 100%;
            height: 120px;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-family: monospace;
            font-size: 14px;
            resize: vertical;
        }
        button {
            background-color: #ff0000;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }
        button:hover {
            background-color: #cc0000;
        }
        .result {
            margin-top: 30px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
            border: 1px solid #ddd;
        }
        .json-output {
            background-color: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 14px;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .error {
            background-color: #ffebee;
            color: #c62828;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ffcdd2;
        }
        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }
        .examples {
            background-color: #f0f8ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #b3d9ff;
        }
        .examples h3 {
            margin-top: 0;
            color: #0066cc;
        }
        .example-item {
            margin-bottom: 10px;
            font-family: monospace;
            font-size: 12px;
            background-color: white;
            padding: 8px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎬 YouTube Video Data Extractor</h1>
        
        <div class="examples">
            <h3>Supported Input Formats:</h3>
            <div class="example-item">
                <strong>Full iframe:</strong><br>
                &lt;iframe src="https://www.youtube.com/embed/hSwXMLlWPuc"&gt;&lt;/iframe&gt;
            </div>
            <div class="example-item">
                <strong>Embed URL:</strong><br>
                https://www.youtube.com/embed/hSwXMLlWPuc
            </div>
            <div class="example-item">
                <strong>Watch URL:</strong><br>
                https://www.youtube.com/watch?v=hSwXMLlWPuc
            </div>
            <div class="example-item">
                <strong>Short URL:</strong><br>
                https://youtu.be/hSwXMLlWPuc
            </div>
        </div>
        
        <div class="input-section">
            <label for="iframe-input">Paste your YouTube iframe or URL here:</label>
            <textarea 
                id="iframe-input" 
                placeholder="Paste your iframe HTML or YouTube URL here...

Example:
<iframe width='560' height='315' src='https://www.youtube.com/embed/hSwXMLlWPuc' frameborder='0' allowfullscreen></iframe>"
            ></textarea>
            <button onclick="extractVideoData()">Extract Video Data</button>
        </div>
        
        <div id="result"></div>
    </div>

    <script>
        async function extractVideoData() {
            const input = document.getElementById('iframe-input').value.trim();
            const resultDiv = document.getElementById('result');
            
            if (!input) {
                resultDiv.innerHTML = '<div class="error">Please enter an iframe or YouTube URL</div>';
                return;
            }
            
            resultDiv.innerHTML = '<div class="loading">🔄 Extracting video data...</div>';
            
            try {
                const response = await fetch('/extract-video-data', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        iframe_input: input
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    resultDiv.innerHTML = `
                        <div class="result">
                            <h3>✅ Video Data Extracted Successfully!</h3>
                            <div class="json-output">${JSON.stringify(data, null, 2)}</div>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `
                        <div class="error">
                            <h3>❌ Error</h3>
                            <p>${data.error || 'Unknown error occurred'}</p>
                            ${data.message ? `<p><strong>Details:</strong> ${data.message}</p>` : ''}
                        </div>
                    `;
                }
            } catch (error) {
                resultDiv.innerHTML = `
                    <div class="error">
                        <h3>❌ Network Error</h3>
                        <p>Failed to connect to the server: ${error.message}</p>
                    </div>
                `;
            }
        }
        
        // Allow Enter key to trigger extraction
        document.getElementById('iframe-input').addEventListener('keydown', function(event) {
            if (event.ctrlKey && event.key === 'Enter') {
                extractVideoData();
            }
        });
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    """Home page with user input form"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/extract-video-data', methods=['POST'])
def extract_video_data():
    """API endpoint to extract video data from iframe HTML or URL"""
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data or 'iframe_input' not in data:
            return jsonify({
                "error": "Missing 'iframe_input' in request body"
            }), 400
        
        iframe_input = data['iframe_input']
        
        # Extract video ID from iframe HTML or URL
        video_id = extract_video_id_from_iframe(iframe_input)
        
        if not video_id:
            return jsonify({
                "error": "Could not extract video ID from the provided input",
                "provided_input": iframe_input[:100] + "..." if len(iframe_input) > 100 else iframe_input
            }), 400
        
        # Fetch video metadata
        video_data = fetch_youtube_metadata(video_id)
        
        # Print full JSON details to console
        print("="*50)
        print("USER INPUT:")
        print("="*50)
        print(iframe_input)
        print("="*50)
        print("EXTRACTED VIDEO ID:", video_id)
        print("="*50)
        print("FULL VIDEO DATA JSON:")
        print("="*50)
        print(json.dumps(video_data, indent=2, ensure_ascii=False))
        print("="*50)
        
        return jsonify(video_data), 200
        
    except Exception as e:
        error_response = {
            "error": "Internal server error",
            "message": str(e)
        }
        
        # Print error to console
        print("="*50)
        print("ERROR:")
        print("="*50)
        print(json.dumps(error_response, indent=2))
        print("="*50)
        
        return jsonify(error_response), 500

@app.route('/api-docs')
def api_docs():
    """API documentation"""
    return jsonify({
        "message": "YouTube Video Data Extractor API",
        "endpoints": {
            "GET /": "Web interface for user input",
            "POST /extract-video-data": "Extract video data from iframe",
            "GET /api-docs": "This documentation"
        },
        "usage": {
            "endpoint": "/extract-video-data",
            "method": "POST",
            "content_type": "application/json",
            "body": {
                "iframe_input": "Your iframe HTML or YouTube URL"
            }
        }
    })

if __name__ == '__main__':
    print("🚀 Starting YouTube Video Data Extractor...")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("🔍 Users can paste iframe HTML or YouTube URLs directly")
    app.run(debug=True, host='0.0.0.0', port=5000)
