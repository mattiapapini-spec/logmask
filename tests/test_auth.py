import sqlite3
import tempfile
import unittest
from pathlib import Path

from auth import AuthStore, InvalidCredentials, RateLimited


class AuthStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_bootstrap_password_file_and_password_hash(self):
        store = AuthStore(self.root / "auth.db")
        username, generated = store.bootstrap_admin("admin", None, self.root / "bootstrap-admin.txt")
        self.assertEqual(username, "admin")
        self.assertTrue(generated)
        self.assertIn(generated, (self.root / "bootstrap-admin.txt").read_text())
        db = sqlite3.connect(self.root / "auth.db")
        password_hash = db.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()[0]
        db.close()
        self.assertNotIn(generated, password_hash)
        self.assertTrue(password_hash.startswith("$argon2"))

    def test_session_and_csrf(self):
        store = AuthStore(self.root / "auth.db")
        store.bootstrap_admin("admin", "Bootstrap-Password-2026!", self.root / "bootstrap.txt")
        token, csrf, user = store.authenticate("admin", "Bootstrap-Password-2026!", "127.0.0.1")
        session = store.session(token)
        self.assertIsNotNone(session)
        self.assertEqual(session.user.username, user.username)
        self.assertTrue(store.verify_csrf(session, csrf))
        self.assertFalse(store.verify_csrf(session, "wrong"))
        store.revoke_session(token)
        self.assertIsNone(store.session(token))

    def test_rate_limit_after_failed_logins(self):
        store = AuthStore(
            self.root / "auth.db",
            login_max_failures=2,
            login_window_seconds=900,
        )
        store.bootstrap_admin("admin", "Bootstrap-Password-2026!", self.root / "bootstrap.txt")
        for _ in range(2):
            with self.assertRaises(InvalidCredentials):
                store.authenticate("admin", "wrong-password", "10.0.0.10")
        with self.assertRaises(RateLimited):
            store.authenticate("admin", "Bootstrap-Password-2026!", "10.0.0.10")


if __name__ == "__main__":
    unittest.main()
