import time
from unittest.mock import MagicMock, patch

from docker.errors import DockerException, NotFound, APIError, ImageNotFound

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "execution-engine" / "docker-sandbox"))

from sandbox_manager import (
    SandboxManager,
    SandboxConfig,
    ImageSpec,
    SandboxError,
    SandboxHealthError,
)


@pytest.fixture
def config():
    return SandboxConfig(
        image=ImageSpec(repository="test-image", tag="latest"),
        container_name_prefix="ut-sandbox",
        network_name="ut-sandbox-net",
        management_network="ut-mgmt-net",
        cpu_limit=0.5,
        memory_limit="256m",
        read_only_rootfs=False,
        user="root",
    )


@pytest.fixture
def mock_client():
    with patch("sandbox_manager.docker.from_env") as mock:
        client = MagicMock()
        client.ping.return_value = True
        mock.return_value = client
        yield client


@pytest.fixture
def manager(config, mock_client):
    m = SandboxManager(config)
    m._client = mock_client
    return m


class TestSandboxManagerInit:
    def test_connects_on_init(self, config):
        with patch("sandbox_manager.docker.from_env") as mock:
            client = MagicMock()
            client.ping.return_value = True
            mock.return_value = client
            m = SandboxManager(config)
            assert m._client is client
            mock.assert_called_once()

    def test_raises_on_docker_connect_failure(self, config):
        with patch("sandbox_manager.docker.from_env") as mock:
            mock.side_effect = DockerException("Daemon down")
            with pytest.raises(SandboxError):
                SandboxManager(config)

    def test_creates_networks_on_init(self, config):
        with patch("sandbox_manager.docker.from_env") as mock:
            client = MagicMock()
            client.ping.return_value = True
            client.networks.get.side_effect = NotFound("Not found")
            mock.return_value = client
            m = SandboxManager(config)
            assert client.networks.create.call_count >= 2


class TestSandboxManagerCreate:
    def test_create_container(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_client.containers.run.return_value = mock_container

        cid = manager.create("test-1")
        assert cid == "ut-sandbox-test-1"
        assert "ut-sandbox-test-1" in manager._containers

    def test_create_duplicate_raises(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("dup")
        with pytest.raises(SandboxError, match="already exists"):
            manager.create("dup")

    def test_create_passes_config(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container

        manager.config.env_vars = {"TEST_VAR": "value123"}
        manager.create("env-test")
        call_kwargs = mock_client.containers.run.call_args[-1]
        assert call_kwargs["environment"].get("TEST_VAR") == "value123"

    def test_create_failure_raises(self, manager, mock_client):
        mock_client.containers.run.side_effect = ImageNotFound("Image not found")
        with pytest.raises(SandboxError, match="Failed to create container"):
            manager.create("fail")


class TestSandboxManagerDestroy:
    def test_destroy_active_container(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("to-destroy")
        manager.destroy("to-destroy")
        mock_container.stop.assert_called_once()
        mock_container.remove.assert_called_once_with(v=True, force=True)

    def test_destroy_nonexistent(self, manager, mock_client):
        mock_client.containers.get.side_effect = NotFound("Not found")
        manager.destroy("ghost")

    def test_destroy_cleans_up_state(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("clean")
        manager.destroy("clean")
        assert "ut-sandbox-clean" not in manager._containers


class TestSandboxManagerReset:
    def test_reset_destroys_and_recreates(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "abc"
        mock_client.containers.run.return_value = mock_container

        manager.create("reset-me")
        manager.reset("reset-me")
        assert mock_container.stop.called
        assert mock_container.remove.called
        assert mock_client.containers.run.called


class TestSandboxManagerHealthCheck:
    def test_health_check_active(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.attrs = {
            "State": {"Status": "running", "Health": {"Status": "healthy"}},
            "Created": "2024-01-01T00:00:00Z",
        }
        mock_container.image.tags = ["test:latest"]
        mock_client.containers.run.return_value = mock_container
        exec_result = MagicMock()
        exec_result.exit_code = 0
        exec_result.output = b"pong\n"
        mock_container.exec_run.return_value = exec_result

        manager.create("health")
        status = manager.health_check("health")
        assert status["status"] == "running"
        assert status["reachable"] is True

    def test_health_check_not_found(self, manager):
        status = manager.health_check("nonexistent")
        assert status["status"] == "not_found"

    def test_health_check_unreachable(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.attrs = {
            "State": {"Status": "running"},
            "Created": "2024-01-01T00:00:00Z",
        }
        mock_container.image.tags = ["test:latest"]
        mock_client.containers.run.return_value = mock_container
        exec_result = MagicMock()
        exec_result.exit_code = 1
        exec_result.output = b""
        mock_container.exec_run.return_value = exec_result

        manager.create("unreachable")
        status = manager.health_check("unreachable")
        assert status["reachable"] is False


class TestSandboxManagerSnapshot:
    def test_snapshot_commits_container(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "snap"
        mock_image = MagicMock()
        mock_image.short_id = "img123"
        mock_image.id = "sha256:img123"
        mock_client.containers.run.return_value = mock_container
        mock_container.commit.return_value = mock_image

        manager.create("snap-test")
        img_id = manager.snapshot("snap-test")
        assert img_id == "sha256:img123"
        assert "snap-test" in manager._snapshots

    def test_snapshot_no_container_raises(self, manager):
        with pytest.raises(SandboxError, match="is not active"):
            manager.snapshot("missing")


class TestSandboxManagerExecRun:
    def test_exec_run_on_active(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        exec_result = MagicMock()
        exec_result.exit_code = 0
        exec_result.output = b"hello\n"
        mock_container.exec_run.return_value = exec_result

        manager.create("exec-test")
        rc, out = manager.exec_run("exec-test", ["echo", "hello"])
        assert rc == 0
        assert "hello" in out

    def test_exec_run_no_container(self, manager):
        with pytest.raises(SandboxError, match="is not active"):
            manager.exec_run("ghost", ["echo", "test"])


class TestSandboxManagerCleanup:
    def test_cleanup_destroys_all(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("cleanup-1")
        manager.create("cleanup-2")
        manager.cleanup()
        assert len(manager._containers) == 0

    def test_cleanup_as_context_manager(self, config, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        with SandboxManager(config) as m:
            m.create("ctx")
            assert len(m._containers) == 1
        assert len(m._containers) == 0


class TestSandboxManagerList:
    def test_list_containers(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "lst"
        mock_container.attrs = {
            "State": {"Status": "running"},
            "NetworkSettings": {
                "Networks": {"ut-sandbox-net": {"IPAddress": "172.28.0.10"}}
            },
        }
        mock_client.containers.run.return_value = mock_container
        manager.create("list-test")
        containers = manager.list_containers()
        assert len(containers) >= 1
        assert containers[0]["tag"] == "ut-sandbox-list-test"

    def test_list_handles_lost_containers(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "lost"
        mock_client.containers.run.return_value = mock_container
        mock_container.reload.side_effect = NotFound("Container gone")
        manager.create("lost")
        containers = manager.list_containers()
        lost = [c for c in containers if c["status"] == "lost"]
        assert len(lost) >= 1
