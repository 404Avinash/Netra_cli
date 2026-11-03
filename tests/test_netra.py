"""
Unit test suite for NETRA_CLI.

Comprehensive offline tests mocking HTTP, SSL, socket, and subprocess operations.
Zero external network or service dependencies.
"""

import datetime
import io
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import netra


class TestURLAndRepoValidation(unittest.TestCase):
    """Test URL and repository parsing and validation."""

    def test_valid_urls(self):
        valid = [
            "https://example.com",
            "http://example.com",
            "https://sub.domain.org/path?query=1",
            "https://example.com:8443/",
            "http://localhost:8080",
        ]
        for url in valid:
            self.assertEqual(netra.validate_url(url), url)

    def test_invalid_urls(self):
        invalid = [
            "",
            "ftp://example.com",
            "http://",
            "https://",
            "just_a_string",
        ]
        for url in invalid:
            with self.assertRaises(ValueError):
                netra.validate_url(url)

    def test_scheme_normalization(self):
        """Test auto-prepending https:// to bare domains and normal targets."""
        cases = [
            ("example.com", "https://example.com"),
            ("example.com:8443", "https://example.com:8443"),
            ("sub.domain.org/path?query=1", "https://sub.domain.org/path?query=1"),
            ("https://example.com", "https://example.com"),
            ("http://example.com", "http://example.com"),
            ("localhost:8080", "https://localhost:8080"),
            ("localhost", "https://localhost"),
        ]
        for raw, expected in cases:
            self.assertEqual(netra.validate_url(raw), expected)

    def test_valid_repos(self):
        valid = [
            ("owner/repo", "owner", "repo"),
            ("org-name/repo.js", "org-name", "repo.js"),
            ("user_1/my_project-v2", "user_1", "my_project-v2"),
        ]
        for repo_str, expected_owner, expected_repo in valid:
            owner, repo = netra.validate_repo(repo_str)
            self.assertEqual(owner, expected_owner)
            self.assertEqual(repo, expected_repo)

    def test_invalid_repos(self):
        invalid = [
            "",
            "owner",
            "owner/repo/extra",
            "/repo",
            "owner/",
            "invalid user/repo",
            "owner/repo$",
        ]
        for repo_str in invalid:
            with self.assertRaises(ValueError):
                netra.validate_repo(repo_str)


class TestRedirectCheck(unittest.TestCase):
    """Test HTTP to HTTPS redirect inspection."""

    @patch("http.client.HTTPConnection")
    def test_redirect_pass_301(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 301
        mock_resp.getheader.return_value = "https://example.com/"
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        res = netra.check_redirect("https://example.com")
        self.assertEqual(res["status"], "pass")
        self.assertIn("301 redirects to HTTPS", res["details"])

    @patch("http.client.HTTPConnection")
    def test_redirect_pass_302(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 302
        mock_resp.getheader.return_value = "https://example.com/login"
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        res = netra.check_redirect("https://example.com")
        self.assertEqual(res["status"], "pass")
        self.assertIn("302 redirects to HTTPS", res["details"])

    @patch("http.client.HTTPConnection")
    def test_redirect_fail_200_ok(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = None
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        res = netra.check_redirect("http://example.com")
        self.assertEqual(res["status"], "fail")
        self.assertIn("without HTTPS redirection", res["details"])

    @patch("http.client.HTTPConnection")
    def test_redirect_fail_non_https(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 301
        mock_resp.getheader.return_value = "http://insecure.example.com/"
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        res = netra.check_redirect("http://example.com")
        self.assertEqual(res["status"], "fail")
        self.assertIn("non-HTTPS location", res["details"])

    @patch("http.client.HTTPConnection")
    def test_redirect_fallback_on_405(self, mock_conn_cls):
        mock_conn = MagicMock()
        resp_405 = MagicMock()
        resp_405.status = 405
        resp_405.getheader.return_value = None

        resp_301 = MagicMock()
        resp_301.status = 301
        resp_301.getheader.return_value = "https://example.com/"

        mock_conn.getresponse.side_effect = [resp_405, resp_301]
        mock_conn_cls.return_value = mock_conn

        res = netra.check_redirect("https://example.com")
        self.assertEqual(res["status"], "pass")
        self.assertEqual(mock_conn.request.call_count, 2)

    @patch("http.client.HTTPConnection")
    def test_redirect_inconclusive_on_timeout(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn.request.side_effect = socket.timeout("timed out")
        mock_conn_cls.return_value = mock_conn

        res = netra.check_redirect("https://example.com")
        self.assertEqual(res["status"], "inconclusive")
        self.assertIn("timeout", res["details"])


class TestTLSCheck(unittest.TestCase):
    """Test TLS certificate inspection and expiration calculations."""

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_tls_valid_cert(self, mock_ctx_cls, mock_sock_conn):
        mock_ssock = MagicMock()
        # Certificate expires in future
        future_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=75)
        future_str = future_dt.strftime("%b %d %H:%M:%S %Y GMT")

        mock_ssock.getpeercert.return_value = {
            "notAfter": future_str,
            "issuer": ((("organizationName", "Let's Encrypt"),),),
        }
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ctx_cls.return_value = mock_ctx

        res = netra.check_tls("example.com")
        self.assertEqual(res["status"], "pass")
        self.assertGreaterEqual(res["days_remaining"], 74)
        self.assertEqual(res["issuer"], "Let's Encrypt")

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_tls_expired_cert(self, mock_ctx_cls, mock_sock_conn):
        mock_ssock = MagicMock()
        past_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
        past_str = past_dt.strftime("%b %d %H:%M:%S %Y GMT")

        mock_ssock.getpeercert.return_value = {
            "notAfter": past_str,
            "issuer": ((("commonName", "Acme Root CA"),),),
        }
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ctx_cls.return_value = mock_ctx

        res = netra.check_tls("example.com")
        self.assertEqual(res["status"], "fail")
        self.assertLessEqual(res["days_remaining"], 0)
        self.assertIn("EXPIRED", res["details"])

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_tls_verification_error(self, mock_ctx_cls, mock_sock_conn):
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "certificate verify failed: certificate has expired"
        )
        mock_ctx_cls.return_value = mock_ctx

        res = netra.check_tls("example.com")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["days_remaining"], 0)

    @patch("socket.create_connection")
    def test_tls_inconclusive_on_timeout(self, mock_sock_conn):
        mock_sock_conn.side_effect = socket.timeout("Connection timed out")

        res = netra.check_tls("example.com")
        self.assertEqual(res["status"], "inconclusive")
        self.assertIsNone(res["days_remaining"])
        self.assertIn("timed out", res["details"])


class TestHeadersCheck(unittest.TestCase):
    """Test HTTP security headers inspection."""

    @patch("urllib.request.urlopen")
    def test_all_headers_present(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = netra.check_headers("https://example.com")
        self.assertEqual(res["Strict-Transport-Security"]["status"], "present")
        self.assertEqual(res["Content-Security-Policy"]["status"], "present")
        self.assertEqual(res["X-Content-Type-Options"]["status"], "present")
        self.assertEqual(res["Referrer-Policy"]["status"], "present")

    @patch("urllib.request.urlopen")
    def test_headers_missing(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = netra.check_headers("https://example.com")
        self.assertEqual(res["Strict-Transport-Security"]["status"], "missing")
        self.assertEqual(res["Content-Security-Policy"]["status"], "missing")
        self.assertEqual(res["X-Content-Type-Options"]["status"], "missing")
        self.assertEqual(res["Referrer-Policy"]["status"], "missing")

    @patch("urllib.request.urlopen")
    def test_x_content_type_options_invalid_value(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "X-Content-Type-Options": "sniff-away",
        }
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = netra.check_headers("https://example.com")
        self.assertEqual(res["X-Content-Type-Options"]["status"], "fail")
        self.assertEqual(res["X-Content-Type-Options"]["value"], "sniff-away")

    @patch("urllib.request.urlopen")
    def test_headers_extracted_on_http_error(self, mock_urlopen):
        # Even on HTTP 403 Forbidden, server security headers should be inspected
        error_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        http_error = urllib.error.HTTPError(
            url="https://example.com",
            code=403,
            msg="Forbidden",
            hdrs=error_headers,
            fp=io.BytesIO(b""),
        )
        mock_urlopen.side_effect = http_error

        res = netra.check_headers("https://example.com")
        http_error.close()
        self.assertEqual(res["Strict-Transport-Security"]["status"], "present")
        self.assertEqual(res["X-Content-Type-Options"]["status"], "present")
        self.assertEqual(res["Content-Security-Policy"]["status"], "missing")

    @patch("urllib.request.urlopen")
    def test_headers_inconclusive_on_network_timeout(self, mock_urlopen):
        mock_urlopen.side_effect = socket.timeout("Read timed out")

        res = netra.check_headers("https://example.com")
        for hdr, val in res.items():
            self.assertEqual(val["status"], "inconclusive", f"Expected {hdr} to be inconclusive")
            self.assertIn("error", val)


class TestObservationEngine(unittest.TestCase):
    """Test full observation assembly."""

    @patch("netra.check_headers")
    @patch("netra.check_tls")
    @patch("netra.check_redirect")
    def test_observe_target(self, mock_red, mock_tls, mock_hdrs):
        mock_red.return_value = {"status": "pass", "details": "Redirected"}
        mock_tls.return_value = {
            "status": "pass",
            "days_remaining": 60,
            "expiry": "2027-01-01T00:00:00Z",
            "issuer": "Let's Encrypt",
            "details": "Valid",
        }
        mock_hdrs.return_value = {
            "Strict-Transport-Security": {"status": "present", "value": "max-age=31536000"},
            "Content-Security-Policy": {"status": "missing", "value": None},
            "X-Content-Type-Options": {"status": "present", "value": "nosniff"},
            "Referrer-Policy": {"status": "present", "value": "strict-origin"},
        }

        obs = netra.observe("https://example.com")
        self.assertEqual(obs["target"], "https://example.com")
        self.assertIn("timestamp", obs)
        self.assertEqual(obs["redirect"]["status"], "pass")
        self.assertEqual(obs["tls"]["status"], "pass")
        self.assertEqual(obs["headers"]["Strict-Transport-Security"]["status"], "present")


class TestBaselineEngine(unittest.TestCase):
    """Test saving and loading reviewed security baselines."""

    def test_save_and_load_baseline(self):
        obs = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "pass", "details": "Redirected"},
            "tls": {"status": "pass", "days_remaining": 50, "issuer": "DigiCert"},
            "headers": {
                "Strict-Transport-Security": {"status": "present", "value": "max-age=31536000"},
                "Content-Security-Policy": {"status": "present", "value": "default-src 'self'"},
                "X-Content-Type-Options": {"status": "present", "value": "nosniff"},
                "Referrer-Policy": {"status": "present", "value": "strict-origin"},
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_file = Path(tmpdir) / "example.com.json"
            saved = netra.save_baseline(obs, filepath=baseline_file, auto_confirm=True)
            self.assertTrue(saved)
            self.assertTrue(baseline_file.exists())

            loaded = netra.load_baseline(baseline_file)
            self.assertEqual(loaded["target"], "https://example.com")
            self.assertTrue(loaded["reviewed"])
            self.assertIn("saved_at", loaded)
            self.assertEqual(loaded["headers"]["Strict-Transport-Security"]["status"], "present")

    def test_save_aborted_by_user(self):
        obs = {"target": "https://example.com", "redirect": {}, "tls": {}, "headers": {}}
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_file = Path(tmpdir) / "test.json"
            with patch("builtins.input", return_value="n"):
                saved = netra.save_baseline(obs, filepath=baseline_file, auto_confirm=False)
                self.assertFalse(saved)
                self.assertFalse(baseline_file.exists())

    def test_load_nonexistent_baseline(self):
        non_existent = Path("/nonexistent/baseline.json")
        with self.assertRaises(FileNotFoundError):
            netra.load_baseline(non_existent)


class TestDriftComparisonEngine(unittest.TestCase):
    """Test security drift and regression detection."""

    def setUp(self):
        self.baseline = {
            "target": "https://example.com",
            "saved_at": "2026-10-01T00:00:00Z",
            "reviewed": True,
            "redirect": {"status": "pass"},
            "tls": {"status": "pass", "days_remaining": 40},
            "headers": {
                "Strict-Transport-Security": {"status": "present", "value": "max-age=31536000"},
                "Content-Security-Policy": {"status": "present", "value": "default-src 'self'"},
                "X-Content-Type-Options": {"status": "present", "value": "nosniff"},
                "Referrer-Policy": {"status": "present", "value": "strict-origin"},
            },
        }

    def test_no_drift_when_identical(self):
        live = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "pass"},
            "tls": {"status": "pass", "days_remaining": 30},
            "headers": {
                "Strict-Transport-Security": {"status": "present", "value": "max-age=31536000"},
                "Content-Security-Policy": {"status": "present", "value": "default-src 'self'"},
                "X-Content-Type-Options": {"status": "present", "value": "nosniff"},
                "Referrer-Policy": {"status": "present", "value": "strict-origin"},
            },
        }
        diff = netra.compare_drift(self.baseline, live)
        self.assertFalse(diff["drift_detected"])
        self.assertEqual(diff["regressions_count"], 0)

    def test_header_regression_detected(self):
        # CSP and HSTS removed
        live = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "pass"},
            "tls": {"status": "pass", "days_remaining": 30},
            "headers": {
                "Strict-Transport-Security": {"status": "missing", "value": None},
                "Content-Security-Policy": {"status": "missing", "value": None},
                "X-Content-Type-Options": {"status": "present", "value": "nosniff"},
                "Referrer-Policy": {"status": "present", "value": "strict-origin"},
            },
        }
        diff = netra.compare_drift(self.baseline, live)
        self.assertTrue(diff["drift_detected"])
        self.assertEqual(diff["regressions_count"], 2)

        controls = {r["control"]: r for r in diff["regressions"]}
        self.assertIn("Strict-Transport-Security", controls)
        self.assertEqual(controls["Strict-Transport-Security"]["severity"], "medium")
        self.assertIn("Content-Security-Policy", controls)
        self.assertEqual(controls["Content-Security-Policy"]["severity"], "medium")

    def test_tls_expired_regression(self):
        live = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "pass"},
            "tls": {"status": "fail", "days_remaining": 0, "details": "Certificate expired"},
            "headers": self.baseline["headers"],
        }
        diff = netra.compare_drift(self.baseline, live)
        self.assertTrue(diff["drift_detected"])
        self.assertEqual(diff["regressions_count"], 1)
        reg = diff["regressions"][0]
        self.assertEqual(reg["control"], "TLS Certificate Validity")
        self.assertEqual(reg["severity"], "high")

    def test_redirect_regression(self):
        live = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "fail", "details": "HTTP 200 OK"},
            "tls": {"status": "pass", "days_remaining": 30},
            "headers": self.baseline["headers"],
        }
        diff = netra.compare_drift(self.baseline, live)
        self.assertTrue(diff["drift_detected"])
        self.assertEqual(diff["regressions_count"], 1)
        self.assertEqual(diff["regressions"][0]["control"], "HTTP->HTTPS Redirect")
        self.assertEqual(diff["regressions"][0]["severity"], "medium")

    def test_ignores_routine_changes(self):
        # Cert renewed (from 40 days to 90 days)
        # HSTS max-age extended
        live = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "pass"},
            "tls": {"status": "pass", "days_remaining": 90},
            "headers": {
                "Strict-Transport-Security": {
                    "status": "present",
                    "value": "max-age=63072000; includeSubDomains; preload",
                },
                "Content-Security-Policy": {"status": "present", "value": "default-src 'self'"},
                "X-Content-Type-Options": {"status": "present", "value": "nosniff"},
                "Referrer-Policy": {"status": "present", "value": "strict-origin"},
            },
        }
        diff = netra.compare_drift(self.baseline, live)
        self.assertFalse(diff["drift_detected"])
        self.assertEqual(diff["regressions_count"], 0)


class TestSwytchcodeIssueNotification(unittest.TestCase):
    """Test issue formatting, preview mode, and Swytchcode execution dispatch."""

    def setUp(self):
        self.diff = {
            "target": "https://example.com",
            "drift_detected": True,
            "regressions_count": 1,
            "regressions": [
                {
                    "control": "Strict-Transport-Security",
                    "severity": "medium",
                    "baseline": "present",
                    "observed": "missing",
                    "recommendation": "Restore Strict-Transport-Security header",
                }
            ],
            "live": {"timestamp": "2026-11-02T20:00:00Z"},
            "baseline": {"saved_at": "2026-10-01T00:00:00Z"},
        }

    def test_issue_content_generation(self):
        title, body = netra.generate_issue_content("https://example.com", self.diff)
        self.assertIn("[NETRA Security Drift]", title)
        self.assertIn("example.com", title)
        self.assertIn("1 regression(s) detected", title)
        self.assertIn("Strict-Transport-Security", body)
        self.assertIn("MEDIUM", body)

    @patch("subprocess.run")
    def test_notify_preview_mode_does_not_call_subprocess(self, mock_subproc):
        args = MagicMock()
        args.target = "https://example.com"
        args.repo = "testowner/testrepo"
        args.confirm = False
        args.timeout = 10.0

        with patch("netra.load_baseline", return_value={"headers": {}}), \
             patch("netra.observe"), \
             patch("netra.compare_drift", return_value=self.diff), \
             patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:

            exit_code = netra.handle_notify(args)
            self.assertEqual(exit_code, 0)
            mock_subproc.assert_not_called()
            output = mock_stdout.getvalue()
            self.assertIn("[PREVIEW MODE]", output)
            self.assertIn("testowner/testrepo", output)
            self.assertIn("--confirm", output)

    @patch("subprocess.run")
    def test_notify_with_confirm_invokes_swytchcode(self, mock_subproc):
        args = MagicMock()
        args.target = "https://example.com"
        args.repo = "myorg/myrepo"
        args.confirm = True
        args.timeout = 10.0

        mock_subproc.return_value = subprocess.CompletedProcess(
            args=["swytchcode", "exec"],
            returncode=0,
            stdout=json.dumps({"id": 101, "html_url": "https://github.com/myorg/myrepo/issues/101"}),
            stderr="",
        )

        with patch("netra.load_baseline", return_value={"headers": {}}), \
             patch("netra.observe"), \
             patch("netra.compare_drift", return_value=self.diff), \
             patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:

            exit_code = netra.handle_notify(args)
            self.assertEqual(exit_code, 0)
            self.assertEqual(mock_subproc.call_count, 1)

            # Verify subprocess call payload
            call_kwargs = mock_subproc.call_args[1]
            stdin_data = json.loads(call_kwargs["input"])
            self.assertEqual(stdin_data["tool"], "github.issue.create")
            self.assertEqual(stdin_data["args"]["owner"], "myorg")
            self.assertEqual(stdin_data["args"]["repo"], "myrepo")
            self.assertIn("Strict-Transport-Security", stdin_data["args"]["body"]["body"])

            self.assertIn("Issue created successfully", mock_stdout.getvalue())

    @patch("subprocess.run")
    def test_notify_dispatch_handles_swytchcode_error(self, mock_subproc):
        args = MagicMock()
        args.target = "https://example.com"
        args.repo = "myorg/myrepo"
        args.confirm = True
        args.timeout = 10.0

        mock_subproc.return_value = subprocess.CompletedProcess(
            args=["swytchcode", "exec"],
            returncode=3,
            stdout="",
            stderr='{"error":"missing credentials for GitHub - run `swytchcode auth connect GitHub`","category":"auth"}',
        )

        with patch("netra.load_baseline", return_value={"headers": {}}), \
             patch("netra.observe"), \
             patch("netra.compare_drift", return_value=self.diff), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:

            exit_code = netra.handle_notify(args)
            self.assertEqual(exit_code, 3)
            self.assertIn("Swytchcode execution failed with exit code 3", mock_stderr.getvalue())
            self.assertIn("missing credentials", mock_stderr.getvalue())


class TestEnhancedResilienceAndEdgeCases(unittest.TestCase):
    """Test enhanced resilience, edge-case headers, cert math, and formatting."""

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_tls_valid_cert_under_24_hours(self, mock_ctx_cls, mock_sock_conn):
        mock_ssock = MagicMock()
        # Certificate expires in 12 hours (still valid!)
        future_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=12)
        future_str = future_dt.strftime("%b %d %H:%M:%S %Y GMT")

        mock_ssock.getpeercert.return_value = {
            "notAfter": future_str,
            "issuer": ((("organizationName", "DigiCert Inc"),),),
        }
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ctx_cls.return_value = mock_ctx

        res = netra.check_tls("example.com")
        self.assertEqual(res["status"], "pass")
        self.assertIn("Valid certificate", res["details"])
        self.assertNotIn("EXPIRED", res["details"])

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_tls_self_signed_cert_days_remaining_is_none(self, mock_ctx_cls, mock_sock_conn):
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "certificate verify failed: self-signed certificate in certificate chain"
        )
        mock_ctx_cls.return_value = mock_ctx

        res = netra.check_tls("example.com")
        self.assertEqual(res["status"], "fail")
        self.assertIsNone(res["days_remaining"])
        self.assertIn("self-signed certificate", res["details"])

    @patch("urllib.request.urlopen")
    def test_hsts_max_age_zero_fails(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=0; includeSubDomains",
        }
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = netra.check_headers("https://example.com")
        self.assertEqual(res["Strict-Transport-Security"]["status"], "fail")
        self.assertIn("disables HSTS", res["Strict-Transport-Security"]["details"])

    @patch("urllib.request.urlopen")
    def test_hsts_missing_max_age_fails(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "includeSubDomains; preload",
        }
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = netra.check_headers("https://example.com")
        self.assertEqual(res["Strict-Transport-Security"]["status"], "fail")
        self.assertIn("Missing required max-age", res["Strict-Transport-Security"]["details"])

    @patch("urllib.request.urlopen")
    def test_headers_whitespace_values_reported_missing(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "   ",
            "Content-Security-Policy": "\t  \n",
            "Referrer-Policy": "  ",
            "X-Content-Type-Options": "   ",
        }
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = netra.check_headers("https://example.com")
        self.assertEqual(res["Strict-Transport-Security"]["status"], "missing")
        self.assertEqual(res["Content-Security-Policy"]["status"], "missing")
        self.assertEqual(res["Referrer-Policy"]["status"], "missing")
        self.assertEqual(res["X-Content-Type-Options"]["status"], "missing")

    @patch("urllib.request.urlopen")
    def test_headers_unverified_fallback_on_cert_error(self, mock_urlopen):
        # First call with default context fails with SSLCertVerificationError
        # Second call with unverified context succeeds
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
        }
        cert_err = urllib.error.URLError(
            ssl.SSLCertVerificationError("certificate verify failed: certificate has expired")
        )

        mock_enter = MagicMock()
        mock_enter.__enter__.return_value.headers = mock_resp.headers
        mock_urlopen.side_effect = [cert_err, mock_enter]

        res = netra.check_headers("https://example.com")
        self.assertEqual(res["Strict-Transport-Security"]["status"], "present")
        self.assertEqual(res["Content-Security-Policy"]["status"], "present")
        self.assertEqual(mock_urlopen.call_count, 2)

    def test_ansi_padding_alignment(self):
        plain_text = "DRIFT"
        colored_text = netra.color_text(plain_text, netra.ANSI_RED + netra.ANSI_BOLD)
        padded_plain = netra.pad_ansi(plain_text, 12)
        padded_colored = netra.pad_ansi(colored_text, 12)

        self.assertEqual(len(netra.strip_ansi(padded_plain)), 12)
        self.assertEqual(len(netra.strip_ansi(padded_colored)), 12)


class TestSecurityScoreAndTUI(unittest.TestCase):
    """Test security score algorithm, grade levels, and CLI commands."""

    def test_score_all_passing(self):
        obs = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "pass"},
            "tls": {"status": "pass"},
            "headers": {
                "Strict-Transport-Security": {"status": "present"},
                "Content-Security-Policy": {"status": "present"},
                "X-Content-Type-Options": {"status": "present"},
                "Referrer-Policy": {"status": "present"},
            },
        }
        score, grade, bar = netra.calculate_security_score(obs)
        self.assertEqual(score, 100)
        self.assertEqual(grade, "A+")
        self.assertEqual(bar, "█" * 20)

    def test_score_partial_missing_headers(self):
        obs = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "pass"},  # 25
            "tls": {"status": "pass"},       # 25
            "headers": {
                "Strict-Transport-Security": {"status": "present"},  # 20
                "Content-Security-Policy": {"status": "missing"},   # 0
                "X-Content-Type-Options": {"status": "missing"},    # 0
                "Referrer-Policy": {"status": "missing"},           # 0
            },
        }
        score, grade, bar = netra.calculate_security_score(obs)
        self.assertEqual(score, 70)
        self.assertEqual(grade, "C")
        self.assertIn("█", bar)
        self.assertIn("░", bar)

    def test_score_critical_failures(self):
        obs = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "fail"},
            "tls": {"status": "fail"},
            "headers": {
                "Strict-Transport-Security": {"status": "missing"},
                "Content-Security-Policy": {"status": "missing"},
                "X-Content-Type-Options": {"status": "missing"},
                "Referrer-Policy": {"status": "missing"},
            },
        }
        score, grade, bar = netra.calculate_security_score(obs)
        self.assertEqual(score, 0)
        self.assertEqual(grade, "F")
        self.assertEqual(bar, "░" * 20)

    def test_cli_parser_top_and_monitor(self):
        parser = netra.build_parser()
        args_top = parser.parse_args(["top", "--target", "https://example.com", "--interval", "2.0"])
        self.assertEqual(args_top.command, "top")
        self.assertEqual(args_top.target, "https://example.com")
        self.assertEqual(args_top.interval, 2.0)

        args_mon = parser.parse_args(["monitor", "--target", "https://example.com"])
        self.assertEqual(args_mon.command, "monitor")
        self.assertEqual(args_mon.target, "https://example.com")
        self.assertEqual(args_mon.interval, 5.0)

    def test_format_observation_table_renders_box_art(self):
        obs = {
            "target": "https://example.com",
            "timestamp": "2026-11-02T20:00:00Z",
            "redirect": {"status": "pass", "details": "Redirects to HTTPS"},
            "tls": {"status": "pass", "details": "Valid cert"},
            "headers": {
                "Strict-Transport-Security": {"status": "present", "value": "max-age=31536000"},
                "Content-Security-Policy": {"status": "present", "value": "default-src 'self'"},
                "X-Content-Type-Options": {"status": "present", "value": "nosniff"},
                "Referrer-Policy": {"status": "present", "value": "strict-origin"},
            },
        }
        output = netra.format_observation_table(obs)
        self.assertIn("┌", output)
        self.assertIn("GRADE: A+", output)
        self.assertIn("100/100", output)
        self.assertIn("HTTP -> HTTPS Redirect", output)



class TestCLIErgonomicsAndPositionalArgs(unittest.TestCase):
    """Test nmap-style bare domain invocation and positional arguments across all commands."""

    def test_bare_domain_invocation_routes_to_check(self):
        parser = netra.build_parser()
        args1 = parser.parse_args(["example.com"])
        self.assertEqual(args1.command, "check")
        self.assertEqual(args1.target, "example.com")
        self.assertFalse(args1.json)

        args2 = parser.parse_args(["https://example.com"])
        self.assertEqual(args2.command, "check")
        self.assertEqual(args2.target, "https://example.com")

        args3 = parser.parse_args(["example.com", "--json"])
        self.assertEqual(args3.command, "check")
        self.assertEqual(args3.target, "example.com")
        self.assertTrue(args3.json)

    def test_positional_arguments_for_subcommands(self):
        parser = netra.build_parser()

        # check
        args_check = parser.parse_args(["check", "example.com"])
        self.assertEqual(args_check.command, "check")
        self.assertEqual(args_check.target, "example.com")

        # top & monitor
        args_top = parser.parse_args(["top", "example.com", "--interval", "2.5"])
        self.assertEqual(args_top.command, "top")
        self.assertEqual(args_top.target, "example.com")
        self.assertEqual(args_top.interval, 2.5)

        args_mon = parser.parse_args(["monitor", "example.com"])
        self.assertEqual(args_mon.command, "monitor")
        self.assertEqual(args_mon.target, "example.com")

        # compare
        args_comp = parser.parse_args(["compare", "example.com"])
        self.assertEqual(args_comp.command, "compare")
        self.assertEqual(args_comp.target, "example.com")

        # baseline save
        args_base = parser.parse_args(["baseline", "save", "example.com", "--yes"])
        self.assertEqual(args_base.command, "baseline")
        self.assertEqual(args_base.baseline_action, "save")
        self.assertEqual(args_base.target, "example.com")
        self.assertTrue(args_base.yes)

        # notify
        args_notif = parser.parse_args(["notify", "example.com", "--repo", "404Avinash/Netra_cli"])
        self.assertEqual(args_notif.command, "notify")
        self.assertEqual(args_notif.target, "example.com")
        self.assertEqual(args_notif.repo, "404Avinash/Netra_cli")

    def test_flag_backward_compatibility(self):
        parser = netra.build_parser()

        args_check = parser.parse_args(["check", "--target", "https://example.com", "--json"])
        self.assertEqual(args_check.command, "check")
        self.assertEqual(args_check.target, "https://example.com")
        self.assertTrue(args_check.json)

        args_top = parser.parse_args(["top", "--target", "https://example.com", "--interval", "3.0"])
        self.assertEqual(args_top.command, "top")
        self.assertEqual(args_top.target, "https://example.com")

        args_comp = parser.parse_args(["compare", "--target", "https://example.com"])
        self.assertEqual(args_comp.command, "compare")
        self.assertEqual(args_comp.target, "https://example.com")

        args_base = parser.parse_args(["baseline", "save", "--target", "https://example.com", "--yes"])
        self.assertEqual(args_base.command, "baseline")
        self.assertEqual(args_base.target, "https://example.com")
        self.assertTrue(args_base.yes)

    def test_missing_target_defaults_to_localhost(self):
        parser = netra.build_parser()
        for cmd_args in [["check"], ["top"], ["compare"], ["baseline", "save"]]:
            args = parser.parse_args(cmd_args)
            self.assertEqual(args.target, "localhost")

        args_notif = parser.parse_args(["notify", "--repo", "owner/repo"])
        self.assertEqual(args_notif.target, "localhost")

        # But notify still requires --repo
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["notify"])
        self.assertEqual(ctx.exception.code, 2)

    @patch("netra.handle_check")
    def test_bare_netra_defaults_to_localhost_check(self, mock_handle_check):
        mock_handle_check.return_value = 0
        ret = netra.main([])
        self.assertEqual(ret, 0)
        self.assertTrue(mock_handle_check.called)
        args = mock_handle_check.call_args[0][0]
        self.assertEqual(args.command, "check")
        self.assertEqual(args.target, "localhost")

    @patch("netra.handle_check")
    def test_main_bare_domain_dispatch(self, mock_handle_check):
        mock_handle_check.return_value = 0
        ret = netra.main(["example.com"])
        self.assertEqual(ret, 0)
        self.assertTrue(mock_handle_check.called)
        args = mock_handle_check.call_args[0][0]
        self.assertEqual(args.command, "check")
        self.assertEqual(args.target, "example.com")

    def test_bare_domain_with_help(self):
        parser = netra.build_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["example.com", "--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_version_flags(self):
        parser = netra.build_parser()
        for flag in ["--version", "-v"]:
            with self.assertRaises(SystemExit) as ctx:
                parser.parse_args([flag])
            self.assertEqual(ctx.exception.code, 0)

    def test_direct_subparser_positional(self):
        parser = netra.build_parser()
        subact = [a for a in parser._actions if isinstance(a, netra.argparse._SubParsersAction)][0]
        check_p = subact.choices["check"]
        args = check_p.parse_args(["example.com"])
        self.assertEqual(args.target, "example.com")

    def test_bare_flag_without_subcommand(self):
        parser = netra.build_parser()
        args = parser.parse_args(["--target", "https://example.com", "--json"])
        self.assertEqual(args.command, "check")
        self.assertEqual(args.target, "https://example.com")
        self.assertTrue(args.json)


class TestHostSecurityAndNetworkGuardian(unittest.TestCase):
    """Test local host security, network telemetry, socket inspection, heuristics, and drift."""

    def test_is_local_target(self):
        self.assertTrue(netra.is_local_target(None))
        self.assertTrue(netra.is_local_target(""))
        self.assertTrue(netra.is_local_target("localhost"))
        self.assertTrue(netra.is_local_target("127.0.0.1"))
        self.assertTrue(netra.is_local_target("::1"))
        self.assertTrue(netra.is_local_target("host"))
        self.assertTrue(netra.is_local_target("local"))
        self.assertFalse(netra.is_local_target("example.com"))
        self.assertFalse(netra.is_local_target("https://example.com"))
        self.assertFalse(netra.is_local_target("https://localhost"))
        self.assertFalse(netra.is_local_target("localhost:8080"))

    def test_categorize_exposure(self):
        self.assertEqual(netra.categorize_exposure("0.0.0.0"), "EXPOSED")
        self.assertEqual(netra.categorize_exposure("*"), "EXPOSED")
        self.assertEqual(netra.categorize_exposure("::"), "EXPOSED")
        self.assertEqual(netra.categorize_exposure("192.168.1.100"), "EXPOSED")
        self.assertEqual(netra.categorize_exposure("10.0.0.5"), "EXPOSED")
        self.assertEqual(netra.categorize_exposure("127.0.0.1"), "LOCAL")
        self.assertEqual(netra.categorize_exposure("127.0.0.53"), "LOCAL")
        self.assertEqual(netra.categorize_exposure("::1"), "LOCAL")
        self.assertEqual(netra.categorize_exposure("localhost"), "LOCAL")

    def test_split_addr_port(self):
        cases = [
            ("0.0.0.0:6379", ("0.0.0.0", 6379)),
            ("*:3000", ("*", 3000)),
            ("[::]:6379", ("::", 6379)),
            ("[::1]:631", ("::1", 631)),
            ("127.0.0.53%lo:53", ("127.0.0.53", 53)),
            ("[fe80::1]%eth0:546", ("fe80::1", 546)),
            ("192.168.29.175:56020", ("192.168.29.175", 56020)),
        ]
        for raw, expected in cases:
            self.assertEqual(netra.split_addr_port(raw), expected)

    def test_read_proc_net_dev_parsing(self):
        sample_data = (
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            "    lo: 1000       10    0    0    0     0          0         0     1000       10    0    0    0     0       0          0\n"
            "wlp4s0: 50000000   4000    1    2    0     0          0         0 25000000   2000    3    4    0     0       0          0\n"
        )
        with patch("os.path.exists", return_value=True), patch("builtins.open", mock_open(read_data=sample_data)):
            ifaces = netra.read_proc_net_dev("/proc/net/dev")
            self.assertIn("lo", ifaces)
            self.assertIn("wlp4s0", ifaces)
            self.assertEqual(ifaces["wlp4s0"]["rx_bytes"], 50000000)
            self.assertEqual(ifaces["wlp4s0"]["tx_bytes"], 25000000)
            self.assertEqual(ifaces["wlp4s0"]["rx_errs"], 1)
            self.assertEqual(ifaces["wlp4s0"]["rx_drop"], 2)

    def test_sample_interface_bandwidth(self):
        s1 = {"wlp4s0": {"rx_bytes": 100000, "tx_bytes": 50000, "rx_drop": 0, "tx_drop": 0, "rx_errs": 0, "tx_errs": 0}}
        s2 = {"wlp4s0": {"rx_bytes": 200000, "tx_bytes": 100000, "rx_drop": 0, "tx_drop": 0, "rx_errs": 0, "tx_errs": 0}}
        with patch("netra.read_proc_net_dev", side_effect=[s1, s2]), patch("time.time", side_effect=[100.0, 101.0]):
            res = netra.sample_interface_bandwidth(duration=0)
            self.assertEqual(res["primary_interface"], "wlp4s0")
            self.assertEqual(res["rx_bytes"], 200000)
            self.assertEqual(res["tx_bytes"], 100000)
            self.assertAlmostEqual(res["rx_rate_bps"], 100000.0, places=1)
            self.assertAlmostEqual(res["tx_rate_bps"], 50000.0, places=1)

    def test_parse_ss_sockets(self):
        ss_text = (
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            "tcp   LISTEN 0 4096 0.0.0.0:6379 0.0.0.0:* users:((\"redis-server\",pid=1234,fd=6))\n"
            "tcp   LISTEN 0 4096 0.0.0.0:5678 0.0.0.0:* \n"
            "tcp   LISTEN 0 511 *:3000 *:* users:((\"MainThread\",pid=55688,fd=38))\n"
            "tcp   LISTEN 0 4096 127.0.0.1:11434 0.0.0.0:* \n"
            "tcp   LISTEN 0 2048 127.0.0.1:8000 0.0.0.0:* users:((\"python\",pid=2055,fd=7))\n"
            "tcp   LISTEN 0 4096 [::]:6379 [::]:* \n"
            "tcp   ESTAB 0 0 192.168.29.175:56020 140.82.114.26:443 users:((\"brave\",pid=63003,fd=50))\n"
            "tcp   ESTAB 0 0 127.0.0.1:40423 127.0.0.1:57678 users:((\"language_server\",pid=22145,fd=31))\n"
            "tcp   ESTAB 0 0 192.168.29.175:40000 93.184.216.34:80 users:((\"curl\",pid=777,fd=3))\n"
        )
        l_ports, e_conns, o_conns = netra.parse_ss_sockets(ss_text)
        ports = {p["port"]: p for p in l_ports}
        self.assertIn(6379, ports)
        self.assertEqual(ports[6379]["exposure"], "EXPOSED")
        self.assertEqual(ports[6379]["severity"], "HIGH")
        self.assertEqual(ports[6379]["service"], "Redis Database")
        self.assertEqual(ports[6379]["processes"][0]["name"], "redis-server")

        self.assertIn(5678, ports)
        self.assertEqual(ports[5678]["exposure"], "EXPOSED")
        self.assertEqual(ports[5678]["severity"], "HIGH")

        self.assertIn(3000, ports)
        self.assertEqual(ports[3000]["exposure"], "EXPOSED")
        self.assertEqual(ports[3000]["severity"], "MEDIUM")

        self.assertIn(11434, ports)
        self.assertEqual(ports[11434]["exposure"], "LOCAL")
        self.assertEqual(ports[11434]["severity"], "INFO")

        self.assertIn(8000, ports)
        self.assertEqual(ports[8000]["exposure"], "LOCAL")
        self.assertEqual(ports[8000]["severity"], "INFO")

        self.assertEqual(len(e_conns), 3)
        remote_ports = {c["remote_port"]: c for c in e_conns}
        self.assertIn(443, remote_ports)
        self.assertEqual(remote_ports[443]["service"], "GitHub (TLS)")
        self.assertIn(80, remote_ports)
        self.assertEqual(remote_ports[80]["service"], "Unencrypted HTTP (Plaintext)")

    def test_parse_proc_net_sockets_fallback(self):
        tcp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27029 1 0000000000000000 100 0 0 10 0\n"
            "   1: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2055 1 0000000000000000 100 0 0 10 0\n"
        )
        def fake_open(filename, *args, **kwargs):
            if filename == "/proc/net/tcp":
                return io.StringIO(tcp_content)
            return io.StringIO("")

        with patch("os.path.exists", side_effect=lambda p: p == "/proc/net/tcp"), patch("builtins.open", side_effect=fake_open):
            l_ports, e_conns, o_conns = netra.parse_proc_net_sockets()
            ports = {p["port"]: p for p in l_ports}
            self.assertIn(6379, ports)
            self.assertEqual(ports[6379]["exposure"], "EXPOSED")
            self.assertIn(8000, ports)
            self.assertEqual(ports[8000]["exposure"], "LOCAL")

    def test_threat_heuristics(self):
        # 1. Suspicious listening port
        listening = [{"port": 4444, "bind_address": "0.0.0.0", "service": "Metasploit / C2 Listener"}]
        estab = []
        other = []
        threats = netra.evaluate_threat_heuristics(listening, estab, other)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["severity"], "CRITICAL")
        self.assertIn("4444", threats[0]["details"])

        # 2. Plaintext outbound
        listening = []
        estab = [{"remote_ip": "1.2.3.4", "remote_port": 80, "processes": [{"name": "curl", "pid": 123}]}]
        threats = netra.evaluate_threat_heuristics(listening, estab, other)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["severity"], "MEDIUM")
        self.assertIn("Plaintext", threats[0]["category"])

        # 3. SYN_RECV flood
        other = [{"state": "SYN-RECV"}] * 12
        threats = netra.evaluate_threat_heuristics(listening, [], other)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["severity"], "HIGH")
        self.assertIn("SYN Flood", threats[0]["category"])

    def test_ssh_key_permissions_hygiene(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            key_insecure = ssh_dir / "id_rsa"
            key_insecure.write_text("dummy key")
            key_insecure.chmod(0o644)

            res = netra.inspect_ssh_key_hygiene(ssh_dir)
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("id_rsa", res["details"])
            self.assertIn("should be 0600", res["details"])

            key_insecure.chmod(0o600)
            res2 = netra.inspect_ssh_key_hygiene(ssh_dir)
            self.assertEqual(res2["status"], "PASS")

    def test_workspace_secrets_hygiene(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws_dir = Path(tmpdir)
            env_file = ws_dir / ".env"
            env_file.write_text("SECRET=123")
            env_file.chmod(0o644)

            with patch("subprocess.run") as mock_subproc:
                mock_res = MagicMock()
                mock_res.returncode = 1
                mock_subproc.return_value = mock_res

                res = netra.inspect_workspace_secrets_hygiene(ws_dir)
                self.assertEqual(res["status"], "FAIL")
                self.assertIn(".env", res["details"])

    def test_calculate_host_security_score(self):
        clean_obs = {
            "listening_ports": [{"port": 8000, "exposure": "LOCAL", "severity": "INFO"}],
            "threats": [],
            "hygiene": {"ssh_keys": {"status": "PASS"}, "workspace_secrets": {"status": "PASS"}},
        }
        score, grade, bar = netra.calculate_host_security_score(clean_obs)
        self.assertEqual(score, 100)
        self.assertEqual(grade, "A+")

        risky_obs = {
            "listening_ports": [
                {"port": 6379, "exposure": "EXPOSED", "severity": "HIGH"},
                {"port": 5678, "exposure": "EXPOSED", "severity": "HIGH"},
                {"port": 3000, "exposure": "EXPOSED", "severity": "MEDIUM"},
            ],
            "threats": [],
            "hygiene": {"ssh_keys": {"status": "PASS"}, "workspace_secrets": {"status": "PASS"}},
        }
        score, grade, bar = netra.calculate_host_security_score(risky_obs)
        self.assertEqual(score, 50)
        self.assertEqual(grade, "F")

    def test_format_host_observation_table(self):
        obs = {
            "hostname": "test-laptop",
            "ip": "192.168.1.10",
            "network": {"primary_interface": "wlan0", "rx_bytes": 1024000, "tx_bytes": 512000},
            "score": 85,
            "grade": "A",
            "score_bar": "█" * 17 + "░" * 3,
            "listening_ports": [
                {"proto": "tcp", "bind_address": "0.0.0.0", "port": 6379, "exposure": "EXPOSED", "severity": "HIGH", "service": "Redis Database", "processes": []},
                {"proto": "tcp", "bind_address": "127.0.0.1", "port": 8000, "exposure": "LOCAL", "severity": "INFO", "service": "Dev Server", "processes": []},
            ],
            "established_connections": [{"remote_port": 443, "processes": [{"name": "curl"}]}],
            "threats": [],
            "hygiene": {"ssh_keys": {"status": "PASS"}, "workspace_secrets": {"status": "PASS"}},
        }
        output = netra.format_host_observation_table(obs)
        self.assertIn("test-laptop", output)
        self.assertIn("192.168.1.10", output)
        self.assertIn("Exposed Port 0.0.0.0:6379", output)
        self.assertIn("Localhost Ports", output)
        self.assertIn("Malicious / Backdoor Radar", output)
        self.assertIn("Workspace & SSH Hygiene", output)
        self.assertIn("GRADE: A", output)

    def test_compare_host_drift(self):
        baseline = {
            "type": "host",
            "target": "localhost",
            "hostname": "test-laptop",
            "saved_at": "2026-11-01T12:00:00Z",
            "listening_ports": [
                {"proto": "tcp", "port": 8000, "exposure": "LOCAL", "bind_address": "127.0.0.1", "service": "Dev Server"},
            ],
            "threats": [],
            "hygiene": {"ssh_keys": {"status": "PASS"}, "workspace_secrets": {"status": "PASS"}},
        }
        live_clean = dict(baseline)
        diff = netra.compare_host_drift(baseline, live_clean)
        self.assertFalse(diff["drift_detected"])
        self.assertEqual(diff["regressions_count"], 0)

        live_drift = {
            "type": "host",
            "target": "localhost",
            "hostname": "test-laptop",
            "listening_ports": [
                {"proto": "tcp", "port": 8000, "exposure": "LOCAL", "bind_address": "127.0.0.1", "service": "Dev Server"},
                {"proto": "tcp", "port": 6379, "exposure": "EXPOSED", "bind_address": "0.0.0.0", "service": "Redis Database", "severity": "HIGH", "processes": []},
            ],
            "threats": [],
            "hygiene": {"ssh_keys": {"status": "PASS"}, "workspace_secrets": {"status": "PASS"}},
        }
        diff2 = netra.compare_host_drift(baseline, live_drift)
        self.assertTrue(diff2["drift_detected"])
        self.assertEqual(diff2["regressions_count"], 1)
        self.assertIn("6379", diff2["regressions"][0]["control"])
        self.assertEqual(diff2["regressions"][0]["severity"], "high")

        live_escalation = {
            "type": "host",
            "target": "localhost",
            "hostname": "test-laptop",
            "listening_ports": [
                {"proto": "tcp", "port": 8000, "exposure": "EXPOSED", "bind_address": "0.0.0.0", "service": "Dev Server", "severity": "MEDIUM", "processes": []},
            ],
            "threats": [],
            "hygiene": {"ssh_keys": {"status": "PASS"}, "workspace_secrets": {"status": "PASS"}},
        }
        diff3 = netra.compare_host_drift(baseline, live_escalation)
        self.assertTrue(diff3["drift_detected"])
        self.assertIn("Port Exposure", diff3["regressions"][0]["control"])

    def test_generate_host_issue_content(self):
        diff = {
            "type": "host",
            "target": "localhost",
            "live": {"hostname": "nitro-laptop", "ip": "192.168.1.5", "timestamp": "2026-11-03T18:00:00Z"},
            "baseline": {"saved_at": "2026-11-01T10:00:00Z"},
            "drift_detected": True,
            "regressions_count": 1,
            "regressions": [
                {
                    "control": "Exposed Port 0.0.0.0:6379",
                    "severity": "high",
                    "baseline": "closed",
                    "observed": "0.0.0.0:6379 (EXPOSED)",
                    "recommendation": "Bind Redis to 127.0.0.1",
                }
            ],
        }
        title, body = netra.generate_host_issue_content(diff)
        self.assertIn("[NETRA Host Incident]", title)
        self.assertIn("nitro-laptop", title)
        self.assertIn("Exposed Port 0.0.0.0:6379", body)
        self.assertIn("Swytchcode", body)

    def test_categorize_exposure_ipv6_mapped_and_lan_services(self):
        # IPv4-mapped IPv6 loopback should be LOCAL
        self.assertEqual(netra.categorize_exposure("::ffff:127.0.0.1"), "LOCAL")
        self.assertEqual(netra.categorize_exposure("[::ffff:127.0.0.1]"), "LOCAL")
        # Full 172.16.0.0/12 private range identified as LAN
        self.assertEqual(netra.identify_connection_service("172.25.0.1", 8080), "Local Network (LAN)")
        self.assertEqual(netra.identify_connection_service("172.31.255.254", 3000), "Local Network (LAN)")
        # Link-local IPv6 identified as LAN
        self.assertEqual(netra.identify_connection_service("fe80::1", 5353), "Local Network (LAN)")

    def test_parse_proc_net_sockets_fallback_ipv6_and_inodes(self):
        # /proc/net/tcp6 line with ::ffff:127.0.0.1:8080 (port 8080 = 0x1F90), inode 99999
        tcp6_content = (
            "  sl  local_address                         rem_address                            st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0\n"
        )
        fake_inode_map = {"99999": [{"name": "node", "pid": 4321}]}
        def fake_open(filename, *args, **kwargs):
            if filename == "/proc/net/tcp6":
                return io.StringIO(tcp6_content)
            return io.StringIO("")

        with patch("os.path.exists", side_effect=lambda p: p == "/proc/net/tcp6"), \
             patch("builtins.open", side_effect=fake_open), \
             patch("netra.get_proc_inode_map", return_value=fake_inode_map):
            l_ports, e_conns, o_conns = netra.parse_proc_net_sockets()
            self.assertEqual(len(l_ports), 1)
            lp = l_ports[0]
            self.assertEqual(lp["port"], 8080)
            self.assertEqual(lp["exposure"], "LOCAL")
            self.assertEqual(lp["processes"], [{"name": "node", "pid": 4321}])

    def test_format_host_observation_table_multi_threats_and_empty_conns(self):
        obs = {
            "hostname": "test-box",
            "ip": "10.0.0.2",
            "network": {"primary_interface": "lo", "rx_bytes": 0, "tx_bytes": 0},
            "score": 40,
            "grade": "F",
            "score_bar": "█" * 8 + "░" * 12,
            "listening_ports": [],
            "established_connections": [],  # 0 connections
            "threats": [
                {"category": "Suspicious Listener :4444", "severity": "CRITICAL", "details": "Port 4444 active"},
                {"category": "Plaintext Outbound Traffic", "severity": "MEDIUM", "details": "Unencrypted outbound traffic to 93.184.216.34:80"},
            ],
            "hygiene": {
                "ssh_keys": {"status": "FAIL", "issues": ["Private key 'id_rsa' has unsafe permissions 644"]},
                "workspace_secrets": {"status": "FAIL", "issues": ["Secret file '.env' is NOT ignored in .gitignore"]},
            },
        }
        output = netra.format_host_observation_table(obs)
        # Verify both threats are rendered
        self.assertIn("Suspicious Listener :4444", output)
        self.assertIn("Plaintext Outbound Traffic", output)
        # Verify 0 connections message is clean
        self.assertIn("Outbound Conns (0)", output)
        self.assertIn("No active outbound connections", output)
        # Verify both hygiene failure rows are rendered
        self.assertIn("SSH Key Hygiene", output)
        self.assertIn("Workspace Secrets", output)

    def test_save_baseline_verbose_false(self):
        obs = {
            "target": "localhost",
            "type": "host",
            "hostname": "test-box",
            "listening_ports": [],
            "threats": [],
            "hygiene": {},
        }
        with tempfile.TemporaryDirectory() as td:
            filepath = Path(td) / "localhost.json"
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                success = netra.save_baseline(obs, filepath=filepath, auto_confirm=True, verbose=False)
                self.assertTrue(success)
                self.assertTrue(filepath.exists())
                self.assertEqual(mock_stdout.getvalue(), "")

    def test_workspace_secrets_hygiene_subdirectories_and_non_git(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws_dir = Path(tmpdir)
            subdir = ws_dir / "backend"
            subdir.mkdir()
            sub_env = subdir / ".env.local"
            sub_env.write_text("API_KEY=xyz")
            sub_env.chmod(0o644)

            # In a non-git directory without .gitignore, flags unsafe world permissions
            res = netra.inspect_workspace_secrets_hygiene(ws_dir)
            self.assertEqual(res["status"], "FAIL")
            self.assertTrue(any(".env.local" in issue for issue in res["issues"]))


class TestCursesTerminalRadar(unittest.TestCase):
    """Test curses terminal radar rendering, window dimension boundaries, and hotkeys."""

    def test_curses_host_main_renders_and_quits(self):
        mock_stdscr = MagicMock()
        mock_stdscr.getmaxyx.return_value = (24, 80)
        mock_stdscr.getch.side_effect = [ord("q")]

        with patch("netra.inspect_local_host") as mock_inspect:
            mock_inspect.return_value = {
                "hostname": "test-host",
                "ip": "127.0.0.1",
                "score": 90,
                "grade": "A",
                "score_bar": "█" * 18 + "░" * 2,
                "network": {"primary_interface": "lo", "rx_bytes": 100, "tx_bytes": 100, "rx_rate_bps": 10, "tx_rate_bps": 10},
                "listening_ports": [
                    {"port": 8000, "proto": "tcp", "bind_address": "127.0.0.1", "exposure": "LOCAL", "severity": "INFO", "service": "Dev Server", "processes": []}
                ],
                "established_connections": [],
            }
            ret = netra.curses_host_main(mock_stdscr, interval=1.0, max_frames=1)
            self.assertEqual(ret, 0)
            self.assertTrue(mock_stdscr.refresh.called)
            addstr_calls = [c[0][2] for c in mock_stdscr.addstr.call_args_list if len(c[0]) >= 3]
            self.assertTrue(any("NETRA HOST RADAR" in str(txt) for txt in addstr_calls))

    def test_curses_host_main_small_terminal_resilience(self):
        mock_stdscr = MagicMock()
        mock_stdscr.getmaxyx.return_value = (15, 60)  # Too small (< 76x22)
        mock_stdscr.getch.side_effect = [ord("q")]

        ret = netra.curses_host_main(mock_stdscr, interval=1.0, max_frames=1)
        self.assertEqual(ret, 0)
        addstr_calls = [c[0][2] for c in mock_stdscr.addstr.call_args_list if len(c[0]) >= 3]
        self.assertTrue(any("Terminal size too small" in str(txt) for txt in addstr_calls))

    def test_curses_host_main_hotkeys_refresh_and_save(self):
        mock_stdscr = MagicMock()
        mock_stdscr.getmaxyx.return_value = (24, 80)
        mock_stdscr.getch.side_effect = [ord("r"), ord("s"), ord("q")]

        with patch("netra.inspect_local_host") as mock_inspect, \
             patch("netra.save_baseline") as mock_save:
            mock_inspect.return_value = {
                "hostname": "test-host",
                "ip": "127.0.0.1",
                "score": 100,
                "grade": "A+",
                "score_bar": "█" * 20,
                "network": {"primary_interface": "lo", "rx_bytes": 0, "tx_bytes": 0, "rx_rate_bps": 0, "tx_rate_bps": 0},
                "listening_ports": [],
                "established_connections": [],
            }
            ret = netra.curses_host_main(mock_stdscr, interval=1.0, max_frames=3)
            self.assertEqual(ret, 0)
            self.assertTrue(mock_save.called)
            save_kwargs = mock_save.call_args[1]
            self.assertFalse(save_kwargs.get("verbose", True))


if __name__ == "__main__":
    unittest.main()


