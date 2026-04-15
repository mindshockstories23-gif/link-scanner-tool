from flask import Flask, render_template, request
import requests
import os
import time
import base64

app = Flask(__name__)

# API Key (Render Environment Variable se lega)
API_KEY = os.getenv("API_KEY")

def check_virustotal(url):
    try:
        # URL encode
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {
            "x-apikey": API_KEY
        }

        # Step 1: Check existing report
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )

        # Agar report nahi hai to submit karo
        if response.status_code == 404:
            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )
            time.sleep(5)

            analysis_id = submit_response.json()["data"]["id"]

            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )

            stats = analysis_response.json()["data"]["attributes"]["stats"]
        else:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)

        return malicious, harmless, None

    except Exception as e:
        return 0, 0, str(e)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")

        malicious, harmless, error = check_virustotal(url)

        if error:
            return render_template(
                "index.html",
                status="ERROR",
                message=error,
                score=0,
                malicious=0,
                harmless=0
            )

        total = malicious + harmless
        score = int((malicious / total) * 100) if total > 0 else 0

        status = "SAFE" if malicious == 0 else "DANGER"

        return render_template(
            "index.html",
            status=status,
            score=score,
            malicious=malicious,
            harmless=harmless,
            url=url
        )

    # GET request (page load)
    return render_template(
        "index.html",
        status=None,
        score=0,
        malicious=0,
        harmless=0
    )


if __name__ == "__main__":
    app.run(debug=True)
