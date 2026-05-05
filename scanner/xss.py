import requests

PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
]

def detect_xss(url, cookies=None):
    vulnerabilities = []

    if 'Submit' not in url:
        url = url + '&Submit=Submit'

    for payload in PAYLOADS:
        parts = url.split('&Submit=Submit')
        test_url = parts[0] + payload + '&Submit=Submit'

        try:
            response = requests.get(
                test_url,
                cookies=cookies,
                timeout=5
            )
            response_text = response.text

            if payload in response_text:
                vulnerabilities.append({
                    'type': 'XSS (Reflected)',
                    'severity': 'High',
                    'description': 'Payload ' + payload + ' was reflected unescaped in the response - JavaScript would execute in victim browser'
                })

        except requests.exceptions.ConnectionError:
            vulnerabilities.append({
                'type': 'XSS',
                'severity': 'Info',
                'description': 'Could not connect to ' + test_url
            })
        except requests.exceptions.Timeout:
            vulnerabilities.append({
                'type': 'XSS',
                'severity': 'Info',
                'description': 'Request timed out for ' + test_url
            })

    return vulnerabilities
    