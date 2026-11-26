import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch


os.environ["APP_ENV"] = "testing"
os.environ["SECRET_KEY"] = "test-only-cybershield-secret"
os.environ["DATABASE_URL"] = "sqlite://"

import app as app_module
from extensions import db


class AppRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app_module.app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
            SESSION_COOKIE_SECURE=False
        )

    @classmethod
    def tearDownClass(cls):
        with app_module.app.app_context():
            db.session.remove()
            db.engine.dispose()

    def setUp(self):
        with app_module.app.app_context():
            db.session.remove()
            db.drop_all()
            db.create_all()

            self.user = app_module.User(
                username="test-user",
                email="test@example.com"
            )
            self.user.set_password("correct horse battery staple")
            db.session.add(self.user)
            db.session.commit()
            self.user_id = self.user.id

        self.client = app_module.app.test_client()

    def tearDown(self):
        with app_module.app.app_context():
            db.session.remove()

    def login(self):
        return self.client.post(
            "/login",
            data={
                "identity": "test-user",
                "password": "correct horse battery staple"
            }
        )

    def test_password_is_hashed_and_login_succeeds(self):
        with app_module.app.app_context():
            user = db.session.get(app_module.User, self.user_id)
            self.assertNotEqual(
                user.password_hash,
                "correct horse battery staple"
            )
            self.assertTrue(
                user.check_password("correct horse battery staple")
            )

        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/"))

    def test_login_rejects_external_and_encoded_open_redirects(self):
        for target in (
            "https://attacker.example",
            "//attacker.example",
            "/%2f%2fattacker.example",
            "/%5c%5cattacker.example",
            "/%252f%252fattacker.example"
        ):
            with self.subTest(target=target):
                response = self.client.post(
                    "/login",
                    query_string={"next": target},
                    data={
                        "identity": "test-user",
                        "password": "correct horse battery staple"
                    }
                )
                self.assertEqual(response.status_code, 302)
                self.assertNotIn("attacker.example", response.headers["Location"])

    def test_login_allows_same_site_redirect(self):
        response = self.client.post(
            "/login",
            query_string={"next": "/analysis"},
            data={
                "identity": "test-user",
                "password": "correct horse battery staple"
            }
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/analysis"))

    def test_security_headers_are_set(self):
        response = self.client.get("/health")
        self.assertEqual(
            response.headers["X-Content-Type-Options"],
            "nosniff"
        )
        self.assertEqual(
            response.headers["X-Frame-Options"],
            "SAMEORIGIN"
        )
        self.assertEqual(
            response.headers["Referrer-Policy"],
            "strict-origin-when-cross-origin"
        )
        self.assertNotIn(
            app_module.BASE_DIR.as_posix(),
            response.get_data(as_text=True)
        )

    def test_alerts_cannot_be_resolved_by_another_user(self):
        with app_module.app.app_context():
            alert = app_module.Alert(
                title="Private test alert",
                user_id=self.user_id
            )
            other_user = app_module.User(
                username="other-user",
                email="other@example.com"
            )
            other_user.set_password("another correct password")
            db.session.add_all([alert, other_user])
            db.session.commit()
            alert_id = alert.id
            other_user_id = other_user.id

        self.client.post(
            "/login",
            data={
                "identity": "other-user",
                "password": "another correct password"
            }
        )
        response = self.client.post(
            f"/alerts/{alert_id}/resolve"
        )
        self.assertEqual(response.status_code, 404)

        with app_module.app.app_context():
            alert = db.session.get(app_module.Alert, alert_id)
            self.assertEqual(alert.status, "open")

    def test_invalid_capture_adapter_is_rejected(self):
        self.login()
        with (
            patch.object(
                app_module,
                "get_capture_backend_error",
                return_value=None
            ),
            patch.object(
                app_module,
                "get_capture_interfaces",
                return_value=[{"value": "wifi0", "label": "Wi-Fi"}]
            )
        ):
            response = self.client.post(
                "/monitor/start",
                json={"interface": "not-an-adapter"}
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("not available", response.json["message"])

    def test_monitor_reports_capture_thread_failure(self):
        self.login()
        failed_sniffer = SimpleNamespace(
            running=False,
            thread=None,
            exception=RuntimeError("capture permission denied")
        )

        with app_module.app.app_context():
            app_module.LIVE_MONITOR_STATE[self.user_id] = {
                **app_module.get_live_monitor_state(self.user_id),
                "running": True
            }
            app_module.LIVE_MONITOR_RUNTIME[self.user_id] = failed_sniffer

        response = self.client.get("/api/monitor/status")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["monitor"]["running"])
        self.assertIn(
            "capture permission denied",
            response.json["monitor"]["message"]
        )

        with app_module.app.app_context():
            self.assertNotIn(
                self.user_id,
                app_module.LIVE_MONITOR_RUNTIME
            )
            app_module.LIVE_MONITOR_STATE.pop(self.user_id, None)

    def test_monitor_reports_stop_failure(self):
        self.login()
        with app_module.app.app_context():
            state = app_module.get_live_monitor_state(self.user_id)
            state["running"] = True
            app_module.LIVE_MONITOR_FLOWS[self.user_id] = {}

        with patch.object(
            app_module,
            "stop_packet_capture",
            return_value="driver stop failed"
        ):
            response = self.client.post("/monitor/stop")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "driver stop failed",
            response.json["monitor"]["message"]
        )
        self.assertFalse(response.json["monitor"]["running"])
        with app_module.app.app_context():
            app_module.LIVE_MONITOR_STATE.pop(self.user_id, None)

    def test_live_flow_samples_are_bounded(self):
        samples = []
        original_limit = app_module.LIVE_FLOW_MAX_PACKET_SAMPLES
        app_module.LIVE_FLOW_MAX_PACKET_SAMPLES = 3
        try:
            for value in range(5):
                app_module.append_bounded_sample(samples, value)
        finally:
            app_module.LIVE_FLOW_MAX_PACKET_SAMPLES = original_limit

        self.assertEqual(samples, [2, 3, 4])


class ConfigurationTests(unittest.TestCase):
    def test_development_secret_is_random_not_a_known_placeholder(self):
        first = app_module.resolve_secret_key("development", "")
        second = app_module.resolve_secret_key("development", "")
        self.assertNotEqual(first, second)
        self.assertNotEqual(
            first,
            "development-only-change-this-key"
        )

    def test_production_rejects_missing_or_placeholder_secret(self):
        for key in (
            "",
            "replace-with-a-random-secret",
            "short-secret"
        ):
            with self.subTest(key=key):
                with self.assertRaises(RuntimeError):
                    app_module.resolve_secret_key("production", key)

    def test_production_accepts_configured_secret(self):
        self.assertEqual(
            app_module.resolve_secret_key(
                "production",
                "a-unique-production-secret-that-is-long-enough"
            ),
            "a-unique-production-secret-that-is-long-enough"
        )


if __name__ == "__main__":
    unittest.main()
