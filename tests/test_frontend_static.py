"""Tests for the static frontend files (Phase 3).

Validates that all required frontend files exist, that HTML pages reference
the correct assets and API endpoints, and that the Alpine.js app.js defines
all required components.
"""

from pathlib import Path

import pytest

FRONTEND_DIR = Path(__file__).parent.parent / "src" / "secdashboards" / "frontend"
ASSETS_DIR = FRONTEND_DIR / "assets"


class TestFrontendFilesExist:
    """Verify all expected frontend files are present."""

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html"],
    )
    def test_html_pages_exist(self, filename: str) -> None:
        assert (FRONTEND_DIR / filename).is_file(), f"Missing {filename}"

    @pytest.mark.parametrize(
        "filename",
        ["app.js", "terminal.css", "manifest.json"],
    )
    def test_assets_exist(self, filename: str) -> None:
        assert (ASSETS_DIR / filename).is_file(), f"Missing assets/{filename}"


class TestHTMLStructure:
    """Verify HTML pages have required elements."""

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html"],
    )
    def test_pages_reference_terminal_css(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "/assets/terminal.css" in content

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html"],
    )
    def test_pages_reference_app_js(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "/assets/app.js" in content

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html"],
    )
    def test_pages_reference_alpine(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "alpinejs" in content

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html"],
    )
    def test_pages_have_iris_brand(self, filename: str) -> None:
        content = (FRONTEND_DIR / filename).read_text()
        assert "iris" in content.lower()

    @pytest.mark.parametrize(
        "filename",
        ["index.html", "monitoring.html", "detections.html", "sources.html"],
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


class TestManifest:
    """Verify PWA manifest."""

    def test_manifest_is_valid_json(self) -> None:
        import json

        content = (ASSETS_DIR / "manifest.json").read_text()
        data = json.loads(content)
        assert data["short_name"] == "iris"
        assert data["start_url"] == "/"
        assert data["display"] == "standalone"
