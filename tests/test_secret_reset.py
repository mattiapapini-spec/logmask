"""v0.27.1 - reset secret: rigenerare la master key.

La master key (data/master.key) e' il "secret" da cui derivano tutti i token.
Rigenerarla cambia ogni token futuro e rende non piu' reversibile ogni vault
esistente. E' un'operazione globale e distruttiva, quindi - come per l'azzera
vault - nulla viene cancellato: vecchia chiave e vault vengono archiviati con
un timestamp e sono recuperabili solo insieme. Utenti e sessioni NON dipendono
dalla master key, quindi nessuno viene disconnesso.
"""
import importlib
import os
import tempfile
import unittest
from pathlib import Path


def fresh_app():
    os.environ["LOGMASK_DATA"] = tempfile.mkdtemp()
    os.environ["LOGMASK_ADMIN_PASSWORD"] = "Str0ng-Pass-9921xZ"
    import app
    importlib.reload(app)
    return app


def logged_in_client(app):
    from fastapi.testclient import TestClient
    c = TestClient(app.app, raise_server_exceptions=False)
    c.post("/api/login", json={"username": "admin", "password": "Str0ng-Pass-9921xZ"})
    csrf = c.cookies.get("logmask_csrf")
    c.post("/api/change-password",
           json={"current_password": "Str0ng-Pass-9921xZ", "new_password": "An0ther-Pass-7788zz"},
           headers={"X-CSRF-Token": csrf})
    return c, c.cookies.get("logmask_csrf")


def anon(c, csrf, text="host,ip\r\nSRV-DC01.corp.local,10.20.30.40\r\n"):
    r = c.post("/api/anonymize",
               json={"tenant": "acme", "text": text, "format": "csv",
                     "safe_mode": False, "ip_mode": "all", "url_mode": "all"},
               headers={"X-CSRF-Token": csrf})
    return r.json().get("output", "")


class SecretResetTests(unittest.TestCase):
    def test_tokens_change_after_reset(self):
        app = fresh_app()
        c, csrf = logged_in_client(app)
        before = anon(c, csrf)
        r = c.post("/api/admin/secret/reset", json={"confirm": "RESET"},
                   headers={"X-CSRF-Token": csrf})
        self.assertEqual(r.status_code, 200, r.text)
        after = anon(c, csrf)
        self.assertNotEqual(before, after)

    def test_users_stay_logged_in(self):
        app = fresh_app()
        c, csrf = logged_in_client(app)
        anon(c, csrf)
        c.post("/api/admin/secret/reset", json={"confirm": "RESET"},
               headers={"X-CSRF-Token": csrf})
        self.assertEqual(c.get("/api/me").status_code, 200)

    def test_old_key_and_vaults_are_archived_not_deleted(self):
        app = fresh_app()
        c, csrf = logged_in_client(app)
        anon(c, csrf)   # crea un vault
        data = Path(os.environ["LOGMASK_DATA"])
        c.post("/api/admin/secret/reset", json={"confirm": "RESET"},
               headers={"X-CSRF-Token": csrf})
        archived = list(data.rglob("*prereset*"))
        names = [p.name for p in archived]
        self.assertTrue(any(n.startswith("master-prereset") for n in names), names)
        self.assertTrue(any(n.startswith("vault-prereset") for n in names), names)
        self.assertTrue(app.KEY_PATH.exists())   # una nuova chiave e' stata creata

    def test_wrong_confirmation_is_rejected(self):
        app = fresh_app()
        c, csrf = logged_in_client(app)
        for bad in ("reset secret", "nope", "", "RE SET"):
            with self.subTest(bad=bad):
                r = c.post("/api/admin/secret/reset", json={"confirm": bad},
                           headers={"X-CSRF-Token": csrf})
                self.assertEqual(r.status_code, 400)

    def test_requires_admin(self):
        app = fresh_app()
        from fastapi.testclient import TestClient
        c = TestClient(app.app, raise_server_exceptions=False)
        r = c.post("/api/admin/secret/reset", json={"confirm": "RESET"})
        self.assertEqual(r.status_code, 401)

    def test_requires_csrf(self):
        app = fresh_app()
        c, _csrf = logged_in_client(app)
        r = c.post("/api/admin/secret/reset", json={"confirm": "RESET"})
        self.assertEqual(r.status_code, 403)

    def test_reset_with_no_vaults_still_rotates_key(self):
        app = fresh_app()
        c, csrf = logged_in_client(app)
        r = c.post("/api/admin/secret/reset", json={"confirm": "RESET"},
                   headers={"X-CSRF-Token": csrf})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["vaults_archived"], 0)
        self.assertIsNotNone(r.json()["archived_key"])

    def test_same_value_maps_consistently_after_reset(self):
        """Dopo il reset la derivazione resta deterministica: lo stesso valore,
        due volte, da' lo stesso NUOVO token."""
        app = fresh_app()
        c, csrf = logged_in_client(app)
        c.post("/api/admin/secret/reset", json={"confirm": "RESET"},
               headers={"X-CSRF-Token": csrf})
        a = anon(c, csrf)
        b = anon(c, csrf)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
