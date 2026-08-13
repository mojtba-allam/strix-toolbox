"""Docker sandbox tests — skipped when Docker or the image is unavailable."""

from __future__ import annotations

import pytest

from strix.toolbox.session import docker_available, image_present, start_sandbox, stop_sandbox


pytestmark = pytest.mark.skipif(not docker_available()[0], reason="Docker is not available")


def test_sandbox_status_without_start() -> None:
    from strix.toolbox.session import current_sandbox

    # Do not start a container in the default unit run.
    assert current_sandbox() is None or isinstance(current_sandbox().status(), dict)


@pytest.mark.skipif(not image_present(), reason="Strix sandbox image is not present")
def test_sandbox_start_stop() -> None:
    handle = start_sandbox()
    try:
        status = handle.status()
        assert status["running"] is True
    finally:
        stop_sandbox()
