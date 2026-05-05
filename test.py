from scanner import headers

url = 'http://127.0.0.1:42001'

results = headers.check_headers(url)

print('VULNERABILITIES FOUND:')
for r in results:
    print(r)
    