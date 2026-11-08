from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from conftest import BASE

import importlib.util
import sys

sandbox_path = BASE / "execution-engine" / "docker-sandbox" / "sandbox_manager.py"
spec = importlib.util.spec_from_file_location("sandbox_manager", str(sandbox_path))
sandbox_mod = importlib.util.module_from_spec(spec)
sys.modules["sandbox_manager"] = sandbox_mod
spec.loader.exec_module(sandbox_mod)

SandboxManager = sandbox_mod.SandboxManager
SandboxConfig = sandbox_mod.SandboxConfig
SandboxError = sandbox_mod.SandboxError
SandboxHealthError = sandbox_mod.SandboxHealthError
ImageSpec = sandbox_mod.ImageSpec
from docker.errors import DockerException, NotFound, APIError, ImageNotFound


@pytest.fixture
def config():
    return SandboxConfig(
        container_name_prefix="test-sb",
        network_name="test-sb-net",
        management_network="test-mgmt-net",
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


class TestSandboxCreation:
    def test_sandbox_creation(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_client.containers.run.return_value = mock_container
        cid = manager.create("test-create")
        assert cid == "test-sb-test-create"
        assert cid in manager._containers

    def test_sandbox_creation_with_env(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.config.env_vars = {"CUSTOM_VAR": "custom_val"}
        manager.create("env-test")
        call_kwargs = mock_client.containers.run.call_args[-1]
        assert call_kwargs["environment"]["CUSTOM_VAR"] == "custom_val"

    def test_sandbox_creation_with_env_override(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("override-test", env_override={"OVERRIDE": "yes"})
        call_kwargs = mock_client.containers.run.call_args[-1]
        assert call_kwargs["environment"]["OVERRIDE"] == "yes"

    def test_duplicate_sandbox_raises(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("dup-test")
        with pytest.raises(SandboxError, match="already exists"):
            manager.create("dup-test")

    def test_sandbox_creation_failure_raises(self, manager, mock_client):
        mock_client.containers.run.side_effect = ImageNotFound("Not found")
        with pytest.raises(SandboxError, match="Failed to create container"):
            manager.create("fail-test")


class TestSandboxExec:
    def test_sandbox_exec_command(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        exec_result = MagicMock()
        exec_result.exit_code = 0
        exec_result.output = b"command output\n"
        mock_container.exec_run.return_value = exec_result
        manager.create("exec-test")
        rc, out = manager.exec_run("exec-test", ["echo", "hello"])
        assert rc == 0
        assert "command output" in out

    def test_exec_on_nonexistent_raises(self, manager):
        with pytest.raises(SandboxError, match="is not active"):
            manager.exec_run("ghost", ["echo"])


class TestSnapshotRestore:
    def test_snapshot_creates_image(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "snap"
        mock_image = MagicMock()
        mock_image.short_id = "img123"
        mock_image.id = "sha256:snap123"
        mock_client.containers.run.return_value = mock_container
        mock_container.commit.return_value = mock_image
        manager.create("snap-test")
        img_id = manager.snapshot("snap-test")
        assert img_id == "sha256:snap123"
        assert "snap-test" in manager._snapshots

    def test_snapshot_no_container_raises(self, manager):
        with pytest.raises(SandboxError, match="is not active"):
            manager.snapshot("missing")

    def test_restore_from_snapshot(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "orig"
        mock_image = MagicMock()
        mock_image.id = "sha256:restore"
        mock_client.containers.run.return_value = mock_container
        mock_container.commit.return_value = mock_image
        manager.create("restore-test")
        manager.snapshot("restore-test")
        manager.destroy("restore-test")
        mock_image2 = MagicMock()
        mock_client.images.get.return_value = mock_image2
        mock_container2 = MagicMock()
        mock_container2.short_id = "restored"
        mock_client.containers.run.return_value = mock_container2
        cid = manager.restore("restore-test")
        assert cid == "test-sb-restore-test"

    def test_restore_no_snapshot_raises(self, manager):
        with pytest.raises(SandboxError, match="No snapshot found"):
            manager.restore("no-snap")


class TestHealthCheck:
    def test_health_check_running(self, manager, mock_client):
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
        manager.create("health-test")
        status = manager.health_check("health-test")
        assert status["status"] == "running"
        assert status["reachable"] is True

    def test_health_check_not_found(self, manager):
        status = manager.health_check("nonexistent")
        assert status["status"] == "not_found"

    def test_health_check_unreachable(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.attrs = {"State": {"Status": "running"}, "Created": ""}
        mock_container.image.tags = ["test:latest"]
        mock_client.containers.run.return_value = mock_container
        exec_result = MagicMock()
        exec_result.exit_code = 1
        exec_result.output = b""
        mock_container.exec_run.return_value = exec_result
        manager.create("unreachable")
        status = manager.health_check("unreachable")
        assert status["reachable"] is False

    def test_wait_healthy_timeout(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.attrs = {"State": {"Status": "starting"}, "Created": ""}
        mock_container.image.tags = ["test:latest"]
        mock_client.containers.run.return_value = mock_container
        exec_result = MagicMock()
        exec_result.exit_code = 1
        exec_result.output = b""
        mock_container.exec_run.return_value = exec_result
        manager.create("wait-test")
        healthy = manager.wait_healthy("wait-test", timeout=1.0)
        assert healthy is False


class TestResourceLimits:
    def test_resource_limits_in_config(self, config):
        assert config.cpu_limit == 0.5
        assert config.memory_limit == "256m"
        assert config.pids_limit == 100
        assert config.disk_read_bps == 10 * 1024 * 1024

    def test_resource_limits_passed_to_container(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("limits-test")
        call_kwargs = mock_client.containers.run.call_args[-1]
        assert call_kwargs["mem_limit"] == "256m"
        assert call_kwargs["pids_limit"] == 100
        assert call_kwargs["read_only"] is False
        assert call_kwargs["user"] == "root"


class TestImageManagement:
    def test_build_image_requires_context(self, manager):
        with pytest.raises(SandboxError, match="build_context"):
            manager.build_image()

    def test_pull_image(self, manager, mock_client):
        mock_image = MagicMock()
        mock_image.id = "sha256:pulled"
        mock_image.short_id = "pulled"
        mock_client.images.pull.return_value = mock_image
        spec = ImageSpec(repository="alpine", tag="latest")
        img_id = manager.pull_image(spec)
        assert img_id == "sha256:pulled"

    def test_pull_image_failure(self, manager, mock_client):
        mock_client.images.pull.side_effect = ImageNotFound("Not found")
        with pytest.raises(SandboxError):
            manager.pull_image(ImageSpec(repository="nonexistent"))


class TestContainerLifecycle:
    def test_start_container(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("start-test")
        manager.start("start-test")
        mock_container.start.assert_called_once()

    def test_stop_container(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("stop-test")
        manager.stop("stop-test")
        mock_container.stop.assert_called_once()

    def test_stop_nonexistent(self, manager):
        with pytest.raises(SandboxError):
            manager.stop("ghost")

    def test_destroy_container(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("destroy-test")
        manager.destroy("destroy-test")
        mock_container.stop.assert_called_once()
        mock_container.remove.assert_called_once_with(v=True, force=True)

    def test_destroy_cleans_state(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("clean-test")
        manager.destroy("clean-test")
        assert "test-sb-clean-test" not in manager._containers

    def test_clean_workspace(self, manager, mock_client):
        mock_container = MagicMock()
        exec_result = MagicMock()
        exec_result.exit_code = 0
        exec_result.output = b""
        mock_container.exec_run.return_value = exec_result
        mock_client.containers.run.return_value = mock_container
        manager.create("clean-ws")
        manager.clean("clean-ws")
        assert mock_container.exec_run.called

    def test_reset_destroys_and_creates(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "orig"
        mock_client.containers.run.return_value = mock_container
        manager.create("reset-test")
        mock_container2 = MagicMock()
        mock_container2.short_id = "new"
        mock_client.containers.run.return_value = mock_container2
        cid = manager.reset("reset-test")
        assert cid == "test-sb-reset-test"


class TestCleanup:
    def test_cleanup_destroys_all(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("clean-1")
        manager.create("clean-2")
        manager.cleanup()
        assert len(manager._containers) == 0

    def test_cleanup_as_context_manager(self, config, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        with SandboxManager(config) as m:
            m._client = mock_client
            m.create("ctx-test")
            assert len(m._containers) == 1
        assert len(m._containers) == 0


class TestCopyOperations:
    def test_copy_to(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        manager.create("copy-test")
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write(b"test data")
        try:
            with patch("tempfile.NamedTemporaryFile") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value.name = "/tmp/test.tar"
                with patch("builtins.open", MagicMock()):
                    manager.copy_to("copy-test", tmp_path, "/tmp/dest")
        finally:
            os.unlink(tmp_path)
        assert mock_container.put_archive.called

    def test_copy_from(self, manager, mock_client):
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_container.get_archive.return_value = ([b"data"], None)
        manager.create("copy-from-test")
        with patch("tarfile.open"):
            manager.copy_from("copy-from-test", "/tmp/file", "/tmp/dest")
        assert mock_container.get_archive.called


class TestIPAndList:
    def test_get_container_ip(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.attrs = {
            "NetworkSettings": {
                "Networks": {"test-sb-net": {"IPAddress": "172.20.0.10"}}
            }
        }
        mock_client.containers.run.return_value = mock_container
        manager.create("ip-test")
        ip = manager.get_container_ip("ip-test")
        assert ip == "172.20.0.10"

    def test_list_containers(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "lst"
        mock_container.attrs = {
            "State": {"Status": "running"},
            "NetworkSettings": {
                "Networks": {"test-sb-net": {"IPAddress": "172.20.0.10"}}
            },
        }
        mock_client.containers.run.return_value = mock_container
        manager.create("list-test")
        containers = manager.list_containers()
        assert len(containers) >= 1

    def test_list_handles_lost_containers(self, manager, mock_client):
        mock_container = MagicMock()
        mock_container.short_id = "lost"
        mock_client.containers.run.return_value = mock_container
        mock_container.reload.side_effect = NotFound("Container gone")
        manager.create("lost-test")
        containers = manager.list_containers()
        lost = [c for c in containers if c["status"] == "lost"]
        assert len(lost) >= 1
