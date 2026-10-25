"""Run with: python -m unittest discover -s tests"""
import os, re, tempfile, unittest
from pathlib import Path

_TMP = tempfile.TemporaryDirectory()
os.environ['CLOUDSHARE_INSTANCE_DIR'] = str(Path(_TMP.name) / 'instance')
os.environ['CLOUDSHARE_STORAGE_DIR'] = str(Path(_TMP.name) / 'storage')
os.environ['CLOUDSHARE_DB_PATH'] = str(Path(_TMP.name) / 'test.sqlite3')
os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-not-for-production'
os.environ['FERNET_KEY'] = ''

import app as cloud_app

class CloudShareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cloud_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

    def setUp(self):
        with cloud_app.app.app_context():
            conn = cloud_app.db()
            conn.execute('DELETE FROM share_links'); conn.execute('DELETE FROM shares'); conn.execute('DELETE FROM files'); conn.execute('DELETE FROM users'); conn.commit()
        self.client = cloud_app.app.test_client()

    def csrf(self, response):
        match = re.search(rb'name="_csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match, 'page should contain a CSRF token')
        return match.group(1).decode()

    def register(self, username):
        page = self.client.get('/signup')
        return self.client.post('/signup', data={'_csrf_token': self.csrf(page), 'username': username, 'password': 'long-test-password-123'}, follow_redirects=True)

    def login(self, username):
        page = self.client.get('/login')
        return self.client.post('/login', data={'_csrf_token': self.csrf(page), 'username': username, 'password': 'long-test-password-123'}, follow_redirects=True)

    def test_signup_login_upload_download_and_integrity(self):
        self.register('alice'); self.login('alice')
        page = self.client.get('/upload')
        from io import BytesIO
        response = self.client.post('/upload', data={'_csrf_token': self.csrf(page), 'file': (BytesIO(b'hello cloud'), 'hello.txt')}, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with cloud_app.app.app_context():
            row = cloud_app.db().execute('SELECT * FROM files').fetchone()
            self.assertIsNotNone(row)
            self.assertNotEqual(Path(cloud_app.STORAGE_DIR / row['storage_name']).read_bytes(), b'hello cloud')
        self.assertEqual(self.client.get('/download/' + row['id']).data, b'hello cloud')
        self.assertEqual(self.client.get('/verify/' + row['id']).status_code, 302)

    def test_user_to_user_sharing_and_revocation(self):
        self.register('alice'); self.register('bob'); self.login('alice')
        from io import BytesIO
        page = self.client.get('/upload')
        self.client.post('/upload', data={'_csrf_token': self.csrf(page), 'file': (BytesIO(b'secret'), 'secret.txt')}, content_type='multipart/form-data')
        with cloud_app.app.app_context(): file_id = cloud_app.db().execute('SELECT id FROM files').fetchone()['id']
        page = self.client.get('/share/' + file_id)
        self.client.post('/share/' + file_id, data={'_csrf_token': self.csrf(page), 'username': 'bob'}, follow_redirects=True)
        self.client.post('/logout', data={'_csrf_token': self.csrf(self.client.get('/dashboard'))})
        self.login('bob')
        self.assertEqual(self.client.get('/download/' + file_id).data, b'secret')
        self.client.post('/logout', data={'_csrf_token': self.csrf(self.client.get('/dashboard'))})
        self.login('alice')
        with cloud_app.app.app_context(): share_id = cloud_app.db().execute('SELECT id FROM shares').fetchone()['id']
        self.client.post(f'/unshare/{share_id}', data={'_csrf_token': self.csrf(self.client.get('/dashboard'))})
        self.client.post('/logout', data={'_csrf_token': self.csrf(self.client.get('/dashboard'))})
        self.login('bob')
        self.assertEqual(self.client.get('/download/' + file_id).status_code, 404)

if __name__ == '__main__': unittest.main()
