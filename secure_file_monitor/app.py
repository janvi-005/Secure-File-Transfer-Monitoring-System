import os
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure File Transfer Monitoring System</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f4f7fb;
                text-align: center;
                padding-top: 100px;
            }
            .box {
                background: white;
                width: 600px;
                max-width: 90%;
                margin: auto;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            }
            h1 {
                color: #1f2937;
            }
            .status {
                color: green;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="box">
            <h1>🔐 Secure File Transfer Monitoring System</h1>
            <p class="status">● Project is Online</p>
            <p>This is the deployed web interface of the project.</p>
            <p>File monitoring and security system.</p>
        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
