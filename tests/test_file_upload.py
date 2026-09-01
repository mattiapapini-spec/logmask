import atexit
import csv
import io
import os
import tempfile
import unittest
from pathlib import Path

_BOOT_DATA = tempfile.TemporaryDirectory()
atexit.register(_BOOT_DATA.cleanup)
os.environ.setdefault("LOGMASK_DATA", _BOOT_DATA.name)
os.environ.setdefault("LOGMASK_ADMIN_PASSWORD", "Bootstrap-Upload-Password-2026!")

import app as webapp
from logmask import Anonymizer, Deanonymizer, Options, ORDER, Vault


class FileUploadFrontendTests(unittest.TestCase):
    def test_frontend_exposes_upload_drag_drop_and_download_for_both_flows(self):
        html = (Path(__file__).parents[1] / "static" / "index.html").read_text(encoding="utf-8")
        for element_id in (
            'id="file-anon"',
            'id="file-deanon"',
            'id="anon-upload-card"',
            'id="deanon-upload-card"',
            'id="download-anon"',
            'id="download-deanon"',
        ):
            self.assertIn(element_id, html)
        self.assertIn("bindFileLoader('anon')", html)
        self.assertIn("bindFileLoader('deanon')", html)
        self.assertIn("File troppo grande", html)
        self.assertIn("Il file sembra binario", html)
        self.assertIn("URL.createObjectURL", html)


    def test_frontend_supports_multifile_session_batch_zip(self):
        html = (Path(__file__).parents[1] / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="file-anon" type="file" multiple', html)
        self.assertIn('id="file-deanon" type="file" multiple', html)
        self.assertIn('const FILE_BATCH={anon:[],deanon:[]}', html)
        self.assertIn('runBatchAnon', html)
        self.assertIn('runBatchDeanon', html)
        self.assertIn('zipBlob', html)
        self.assertIn('logmask-anonymized-batch.zip', html)
        self.assertIn("source:'batch:'+f.format", html)

    def test_server_advertises_upload_and_body_limits(self):
        self.assertGreater(webapp.MAX_FILE_BYTES, 0)
        self.assertGreater(webapp.MAX_BODY_BYTES, webapp.MAX_FILE_BYTES)


class CsvReverseUploadTests(unittest.TestCase):
    def test_csv_reverse_preserves_quoted_delimiters(self):
        with tempfile.TemporaryDirectory() as td:
            vault = Vault(Path(td) / "vault.db", b"U" * 32)
            try:
                anon = Anonymizer(vault, set(ORDER), Options())
                pseudo = anon._map("email", "mario.rossi@example.com")
                vault.commit()
                source = io.StringIO(newline="")
                writer = csv.writer(source)
                writer.writerow(["user_email", "description"])
                writer.writerow([pseudo, "hello, world"])
                restored = webapp._deanonymize_csv_text(
                    source.getvalue(), Deanonymizer(vault, Options())
                )
                rows = list(csv.reader(io.StringIO(restored)))
                self.assertEqual(rows[1][0], "mario.rossi@example.com")
                self.assertEqual(rows[1][1], "hello, world")
            finally:
                vault.db.close()


if __name__ == "__main__":
    unittest.main()
