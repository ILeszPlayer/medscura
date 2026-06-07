import subprocess, time, sys, os, requests, re, traceback

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Clean DB
for f in ['instance/medsecure.db', 'instance/encryption.key']:
    try: os.remove(f)
    except: pass

proc = subprocess.Popen([sys.executable, '-c', 
    'from app import create_app; app = create_app(); app.run(port=16333, debug=False)'],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(5)

session = requests.Session()

# Get CSRF
r = session.get('http://localhost:16333/auth/login', timeout=5)
csrf = re.search(r'name="csrf_token"[^>]+value="([^"]+)"', r.text)
csrf_token = csrf.group(1) if csrf else ''

# Login as admin
r = session.post('http://localhost:16333/auth/login',
    data={'csrf_token': csrf_token, 'username': 'admin', 'password': 'Admin123!'},
    allow_redirects=True, timeout=5)

# Get fresh CSRF after login
r = session.get('http://localhost:16333/admin/dashboard', timeout=5)
csrf = re.search(r'name="csrf_token"[^>]+value="([^"]+)"', r.text)
csrf_token = csrf.group(1) if csrf else ''

pages = [
    '/',
    '/auth/login',
    '/auth/register',
    '/auth/forgot-password',
    '/auth/profile',
    '/auth/setup-2fa',
    '/auth/sessions',
    '/auth/delete-account',
    '/auth/logout',
    '/admin/dashboard',
    '/admin/users',
    '/admin/logs',
    '/admin/appointments',
    '/admin/suspicious-ips',
    '/patient/dashboard',
    '/patient/profile',
    '/patient/appointments',
    '/patient/appointments/book',
    '/patient/medical-records',
    '/doctor/dashboard',
    '/doctor/profile',
    '/doctor/appointments',
    '/doctor/patients',
    '/api/health',
    '/robots.txt',
    '/.well-known/security.txt',
]

# Login as patient first and test patient pages
patients = requests.Session()
r = patients.get('http://localhost:16333/auth/login', timeout=5)
csrf2 = re.search(r'name="csrf_token"[^>]+value="([^"]+)"', r.text)

# Register a test patient
r = patients.post('http://localhost:16333/auth/register',
    data={'csrf_token': csrf2.group(1), 'username': 'testpatient', 'email': 'test@test.com',
          'password': 'Test1234!', 'confirm_password': 'Test1234!', 'role': 'patient'},
    allow_redirects=True, timeout=5)

# Login as test patient
r = patients.get('http://localhost:16333/auth/login', timeout=5)
csrf3 = re.search(r'name="csrf_token"[^>]+value="([^"]+)"', r.text)
r = patients.post('http://localhost:16333/auth/login',
    data={'csrf_token': csrf3.group(1), 'username': 'testpatient', 'password': 'Test1234!'},
    allow_redirects=True, timeout=5)

patient_pages = [
    '/patient/dashboard',
    '/patient/profile',
    '/patient/appointments',
    '/patient/appointments/book',
    '/patient/medical-records',
]

print('=== ADMIN PAGES ===')
for p in pages:
    try:
        r = session.get(f'http://localhost:16333{p}', timeout=5, allow_redirects=False)
        status = r.status_code
        if status in (200, 302):
            print(f'  OK {status:3d} {p}')
        else:
            print(f'  FAIL {status:3d} {p} - {r.text[:100]}')
    except Exception as e:
        print(f'  ERROR {p}: {e}')

print('\n=== PATIENT PAGES ===')
for p in patient_pages:
    try:
        r = patients.get(f'http://localhost:16333{p}', timeout=5, allow_redirects=False)
        status = r.status_code
        if status in (200, 302):
            print(f'  OK {status:3d} {p}')
        else:
            print(f'  FAIL {status:3d} {p} - {r.text[:200]}')
    except Exception as e:
        print(f'  ERROR {p}: {e}')

proc.terminate()
proc.wait()
