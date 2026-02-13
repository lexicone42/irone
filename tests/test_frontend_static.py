"""Tests for the static frontend files (Phases 3-4).

Validates that all required frontend files exist, that HTML pages reference
the correct assets and API endpoints, that the Alpine.js app.js defines
all required components, and that auth integration is properly wired.
"""

from pathlib import Path

import pytest

FRONTEND_DIR = Path(__file__).parent.parent / "src" / "secdashboards" / "frontend"
ASSETS_DIR = FRONTEND_DIR / "assets"


class TestFrontendFilesExist:
    """Verify all expected frontend files are present."""

    @pytest.mark.parametrize(
        "filename",
        [
            "index.html",
            "monitoring.html",
            "detections.html",
            "sources.html",
            "login.html",
            "callback.html",
            "investigations.html",
        ],
    )
    def test_html_pages_exist(self, filename: str) -> None:
        assert (FRONTEND_DIR / filename).is_file(), f"Missing {filename}"

    @pytest.mark.parametrize(
        "filename",
        ["app.js", "auth.js", "terminal.css", "manifest.json"],
    )
    def test_assets_exist(self, filename: str) -> None:
        assert (ASSETS_DIR / filename).is_file(), f"Missing assets/{filename}"


class TestHTMLStructure:
    """Verify HTML pages have required elements."""

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html", "investigations.html"],
    )
    def test_pages_reference_terminal_css(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "/assets/terminal.css" in content

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html", "investigations.html"],
    )
    def test_pages_reference_app_js(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "/assets/app.js" in content

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html", "investigations.html"],
    )
    def test_pages_reference_alpine(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "alpinejs" in content

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html", "investigations.html"],
    )
    def test_pages_have_iris_brand(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "iris" in content.lower()

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html", "investigations.html"],
    )
    def test_pages_have_nav_sidebar(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "navApp()" in content
        assert 'class="sidebar"' in content

    @pytest.mark.parametrize(
        "filename,component",
        [
            ("index.html", "dashboardApp()"),
            ("monitoring.html", "healthMonitor()"),
            ("detections.html", "detectionsApp()"),
            ("sources.html", "sourcesApp()"),
            ("investigations.html", "investigationsApp()"),
        ],
    )
    def test_pages_use_correct_alpine_component(self, filename: str, component: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert component in content


class TestAppJS:
    """Verify app.js defines all required Alpine.js components."""

    @pytest.fixture
    def app_js(self) -> str:
        return (ASSETS_DIR / "app.js").read_text()

    @pytest.mark.parametrize(
        "function_name",
        [
            "dashboardApp",
            "healthMonitor",
            "detectionsApp",
            "sourcesApp",
            "investigationsApp",
            "navApp",
        ],
    )
    def test_component_functions_defined(self, app_js: str, function_name: str) -> None:
        assert f"function {function_name}()" in app_js

    @pytest.mark.parametrize(
        "function_name",
        [
            "dashboardApp",
            "healthMonitor",
            "detectionsApp",
            "sourcesApp",
            "investigationsApp",
            "navApp",
        ],
    )
    def test_components_registered_with_alpine(self, app_js: str, function_name: str) -> None:
        assert f'Alpine.data("{function_name}"' in app_js

    def test_api_fetch_helper(self, app_js: str) -> None:
        assert "async function apiFetch(" in app_js
        assert '"/api"' in app_js or "'/api'" in app_js or 'API = "/api"' in app_js

    @pytest.mark.parametrize(
        "endpoint",
        ["/dashboard", "/sources/health", "/sources/refresh", "/sources", "/rules"],
    )
    def test_api_endpoints_referenced(self, app_js: str, endpoint: str) -> None:
        assert endpoint in app_js

    def test_duckdb_wasm_integration(self, app_js: str) -> None:
        """Verify DuckDB-WASM local query support in detectionsApp."""
        assert "initWasm" in app_js
        assert "runLocalQuery" in app_js
        assert "loadResultsIntoWasm" in app_js
        assert "wasmReady" in app_js

    def test_investigations_endpoints_referenced(self, app_js: str) -> None:
        assert "/investigations" in app_js


class TestDetectionsDuckDBWasm:
    """Verify detections page includes DuckDB-WASM."""

    def test_duckdb_wasm_script_tag(self) -> None:
        content = (FRONTEND_DIR / "detections.html").read_text()
        assert "duckdb-wasm" in content

    def test_local_query_section(self) -> None:
        content = (FRONTEND_DIR / "detections.html").read_text()
        assert "Local Query" in content
        assert "runLocalQuery()" in content
        assert "wasmReady" in content


class TestManifest:
    """Verify PWA manifest."""

    def test_manifest_is_valid_json(self) -> None:
        import json

        content = (ASSETS_DIR / "manifest.json").read_text()
        data = json.loads(content)
        assert data["short_name"] == "iris"
        assert data["start_url"] == "/"
        assert data["display"] == "standalone"


class TestAuthIntegration:
    """Verify client-side auth is wired into all pages."""

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html", "investigations.html"],
    )
    def test_app_pages_include_auth_js(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "/assets/auth.js" in content

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html", "investigations.html"],
    )
    def test_app_pages_have_logout_link(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "doLogout()" in content

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html", "investigations.html"],
    )
    def test_app_pages_show_user_email(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "userEmail" in content

    def test_callback_page_handles_code(self) -> None:
        content = (FRONTEND_DIR / "callback.html").read_text()
        assert "auth.handleCallback" in content

    def test_login_page_has_sign_in_button(self) -> None:
        content = (FRONTEND_DIR / "login.html").read_text()
        assert "Sign In" in content

    def test_login_page_checks_auth_config(self) -> None:
        content = (FRONTEND_DIR / "login.html").read_text()
        assert "/api/auth/config" in content


class TestAuthJS:
    """Verify auth.js has required session-based auth functions."""

    @pytest.fixture
    def auth_js(self) -> str:
        return (ASSETS_DIR / "auth.js").read_text()

    def test_session_check(self, auth_js: str) -> None:
        assert "/auth/me" in auth_js
        assert "/auth/login" in auth_js

    def test_auth_config_fetch(self, auth_js: str) -> None:
        assert "/api/auth/config" in auth_js
        assert "auth_enabled" in auth_js

    def test_session_storage_cleanup(self, auth_js: str) -> None:
        assert "sessionStorage" in auth_js
        assert "iris_auth" in auth_js

    def test_logout_redirect(self, auth_js: str) -> None:
        assert "/auth/logout" in auth_js
        assert "getAuthHeaders" in auth_js

    @pytest.mark.parametrize(
        "method",
        [
            "init",
            "handleCallback",
            "refreshTokens",
            "logout",
            "getAuthHeaders",
            "isAuthenticated",
            "isRedirecting",
            "getUser",
            "isAuthEnabled",
        ],
    )
    def test_public_api_methods(self, auth_js: str, method: str) -> None:
        assert method in auth_js
