from flask import Flask, render_template, request
import requests
import time

app = Flask(__name__)

# 🔴 Your VirusTotal API Key
VT_API_KEY = "369a2aecc7cc2316dba58bd1d93e7fc167317a0853082dbd35b85e57a873451f"


def check_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}

    # Step 1: Submit URL
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return None, None, "API Error"

    url_id = response.json()["data"]["id"]

    # Step 2: Wait for analysis (important)
    time.sleep(3)

    # Step 3: Get report
    report = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{url_id}",
        headers=headers
    )

    if report.status_code != 200:
        return None, None, "Report Error"

    stats = report.json()["data"]["attributes"]["stats"]

    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)

    return malicious, harmless, None


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]

        try:
            malicious, harmless, error = check_virustotal(url)

            if error:
                return render_template("index.html",
                                       status="ERROR",
                                       message=error)

            # 📊 Risk Score Calculation
            score = malicious * 10

            if score >= 60:
                status = "DANGEROUS 🔴"
            elif score >= 30:
                status = "SUSPICIOUS 🟠"
            else:
                status = "SAFE 🟢"

            return render_template(
                "index.html",
                url=url,
                status=status,
                score=score,
                malicious=malicious,
                harmless=harmless
            )

        except Exception as e:
            return render_template(
                "index.html",
                status="ERROR",
                message=str(e)
            )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)