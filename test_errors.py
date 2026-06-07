import requests, re, time, subprocess, sys, os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
for f in ['instance/medsecure.db', 'instance/encryption.key']:
    try: os.remove(f)
    except: pass

proc = subprocess.Popen([sys.executable, '-c', 
    'from app import create_app; app = create_app(); app.run(port=16555, debug=False)'],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(4)

pages = [
    '/', '/auth/login', '/auth/register', '/auth/forgot-password',
    '/api/health', '/robots.txt', '/.well-known/security.txt',
    '/nonexistent'
]

print('=== PUBLIC PAGES ===')
for p in pages:
    try:
        r = requests.get(f'http://localhost:16555{p}', timeout=5, allow_redirects=False)
        if r.status_code in (200, 302, 404):
            print(f'  OK {r.status_code} {p}')
        else:
            text = r.text[:200].replace('\n',' ').replace('\r','')
            print(f'  FAIL {r.status_code} {p} => {text}')
    except Exception as e:
        print(f'  ERROR {p}: {e}')

s = requests.Session()
r = s.get('http://localhost:16555/auth/login', timeout=5)
m = re.search(r'name="csrf_token"[^>]+value="([^"]+)"', r.text)
ct = m.group(1) if m else ''
r = s.post('http://localhost:16555/auth/login',
    data={'csrf_token': ct, 'username': 'admin', 'password': 'Admin123!'},
    allow_redirects=True, timeout=5)

r = s.get('http://localhost:16555/auth/profile', timeout=5)
cs = re.search(r'name="csrf_token"[^>]+value="([^"]+)"', r.text)

admin_pages = [
    '/admin/dashboard', '/admin/users', '/admin/logs',
    '/admin/appointments', '/admin/suspicious-ips'
]

print('\n=== ADMIN PAGES ===')
for p in admin_pages:
    try:
        r = s.get(f'http://localhost:16555{p}', timeout=5, allow_redirects=False)
        if r.status_code in (200, 302):
            print(f'  OK {r.status_code} {p}')
        else:
            text = r.text[:200].replace('\n',' ').replace('\r','')
            print(f'  FAIL {r.status_code} {p} => {text}')
    except Exception as e:
        print(f'  ERROR {p}: {e}')

auth_pages = [
    '/auth/profile', '/auth/setup-2fa', '/auth/sessions',
    '/auth/delete-account'
]

print('\n=== AUTH PAGES ===')
for p in auth_pages:
    try:
        r = s.get(f'http://localhost:16555{p}', timeout=5, allow_redirects=False)
        if r.status_code in (200, 302):
            print(f'  OK {r.status_code} {p}')
        else:
            text = r.text[:200].replace('\n',' ').replace('\r','')
            print(f'  FAIL {r.status_code} {p} => {text}')
    except Exception as e:
        print(f'  ERROR {p}: {e}')

# Login as patient
ps = requests.Session()
r = ps.get('http://localhost:16555/auth/login', timeout=5)
m = re.search(r'name="csrf_token"[^>]+value="([^"]+)"', r.text)
ct2 = m.group(1) if m else ''
r = ps.post('http://localhost:16555/auth/register',
    data={'csrf_token': ct2, 'username': 'neil', 'email': 'n@n.com',
          'password': 'Test1234!', 'confirm_password': 'Test1234!', 'role': 'patient'},
    allow_redirects=True, timeout=5)

r = ps.get('http://localhost:16555/auth/login', timeout=5)
m = re.search(r'name="csrf_token"[^>]+value="([^"]+)"', r.text)
ct3 = m.group(1) if m else ''
r = ps.post('http://localhost:16555/auth/login',
    data={'csrf_token': ct3, 'username': 'neil', 'password': 'Test1234!'},
    allow_redirects=True, timeout=5)

patient_pages = [
    '/patient/dashboard', '/patient/profile',
    '/patient/appointments', '/patient/appointments/book',
    '/patient/medical-records'
]

print('\n=== PATIENT PAGES ===')
for p in patient_pages:
    try:
        r = ps.get(f'http://localhost:16555{p}', timeout=5, allow_redirects=False)
        if r.status_code in (200, 302):
            print(f'  OK {r.status_code} {p}')
        else:
            text = r.text[:200].replace('\n',' ').replace('\r','')
            print(f'  FAIL {r.status_code} {p} => {text}')
    except Exception as e:
        print(f'  ERROR {p}: {e}')

proc.terminate()
proc.wait()
