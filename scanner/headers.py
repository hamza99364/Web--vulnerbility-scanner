import requests

SECURITY_HEADERS = {
    'Content-Security-Policy': {
        'severity': 'High',
        'description': 'Missing Content-Security-Policy header - browser will load scripts from any source, making XSS attacks easier to exploit'
    },
    'X-Frame-Options': {
        'severity': 'Medium',
        'description': 'Missing X-Frame-Options header - site can be embedded in iframes, enabling Clickjacking attacks'
    },
    'X-Content-Type-Options': {
        'severity': 'Medium',
        'description': 'Missing X-Content-Type-Options header - browser may execute files with wrong content type'
    },
    'Strict-Transport-Security': {
        'severity': 'High',
        'description': 'Missing Strict-Transport-Security header - site can be accessed over HTTP, enabling Man-in-the-Middle attacks'
    },
    'Referrer-Policy': {
        'severity': 'Low',
        'description': 'Missing Referrer-Policy header - sensitive URLs may be leaked to third party websites'
    },
}

def check_headers(url, cookies=None):
    vulnerabilities = []

    try:
        response = requests.get(url, cookies=cookies, timeout=5)
        response_headers = response.headers

        print('Headers received from server:')
        for header, value in response_headers.items():
            print(' ' + header + ': ' + value)
        print('---')

        for header, info in SECURITY_HEADERS.items():
            if header not in response_headers:
                vulnerabilities.append({
                    'type': 'Missing Security Header: ' + header,
                    'severity': info['severity'],
                    'description': info['description']
                })
            else:
                print('PRESENT: ' + header)

    except requests.exceptions.ConnectionError:
        vulnerabilities.append({
            'type': 'Missing Security Headers',
            'severity': 'Info',
            'description': 'Could not connect to ' + url
        })
    except requests.exceptions.Timeout:
        vulnerabilities.append({
            'type': 'Missing Security Headers',
            'severity': 'Info',
            'description': 'Request timed out for ' + url
        })

    return vulnerabilities
    