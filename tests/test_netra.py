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
            "example.com",
            "http://",
            "https://",
            "just_a_string",
        ]
        for url in invalid:
            with self.assertRaises(ValueError):
                netra.validate_url(url)

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


if __name__ == "__main__":
    unittest.main()
