from scanner import xss

cookies = {
    'PHPSESSID': 'b33205de2499858ba23b6e131fab262d',
    'security': 'low'
}

url = 'http://127.0.0.1:42001/vulnerabilities/xss_r/?name=test&Submit=Submit'

results = xss.detect_xss(url, cookies=cookies)

if results:
    for r in results:
        print(r)
else:
    print('No results')