import atexit
import json
import logging
import os
import platform
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Optional

import docker
from docker.errors import DockerException, ImageNotFound, NotFound, APIError

logger = logging.getLogger(__name__)


class SandboxError(Exception):
    pass


class SandboxHealthError(SandboxError):
    pass


class SandboxResourceError(SandboxError):
    pass


@dataclass
class ImageSpec:
    repository: str
    tag: str = "latest"
    digest: Optional[str] = None
    build_context: Optional[str] = None
    build_dockerfile: Optional[str] = None

    @property
    def full_ref(self) -> str:
        if self.digest:
            return f"{self.repository}@{self.digest}"
        return f"{self.repository}:{self.tag}"

    @property
    def short_ref(self) -> str:
        return f"{self.repository}:{self.tag}"


@dataclass
class SandboxConfig:
    image: ImageSpec = field(default_factory=lambda: ImageSpec(repository="hivebreach-sandbox"))
    container_name_prefix: str = "hb-sandbox"
    network_name: str = "hb-sandbox-net"
    management_network: str = "hb-mgmt-net"
    cpu_limit: float = 1.0
    memory_limit: str = "512m"
    memory_swap_limit: str = "512m"
    pids_limit: int = 100
    disk_read_bps: int = 10 * 1024 * 1024
    disk_write_bps: int = 10 * 1024 * 1024
    network_rate: int = 1024 * 1024
    network_ceil: int = 2048 * 1024
    health_check_interval: float = 2.0
    health_check_retries: int = 5
    snapshot_dir: str = ""
    env_vars: Dict[str, str] = field(default_factory=dict)
    volume_mounts: List[str] = field(default_factory=list)
    exposed_ports: Dict[str, int] = field(default_factory=dict)
    privileged: bool = False
    read_only_rootfs: bool = True
    user: str = "operator"
    work_dir: str = "/workspace"
    keep_alive_cmd: List[str] = field(default_factory=lambda: ["tail", "-f", "/dev/null"])


class SandboxManager:
    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._lock = RLock()
        self._client: Optional[docker.DockerClient] = None
        self._containers: Dict[str, docker.models.containers.Container] = {}
        self._snapshots: Dict[str, str] = {}
        self._image_cache: Dict[str, str] = {}
        self._tmp_dir: Optional[str] = None
        self._connect_client()
        self._ensure_networks()
        atexit.register(self.cleanup)

    def _connect_client(self) -> None:
        try:
            self._client = docker.from_env()
            self._client.ping()
            logger.info("Docker client connected")
        except DockerException as e:
            raise SandboxError(f"Failed to connect to Docker daemon: {e}") from e

    def _ensure_networks(self) -> None:
        for net_name in (self.config.network_name, self.config.management_network):
            try:
                self._client.networks.get(net_name)
            except NotFound:
                self._client.networks.create(net_name, driver="bridge", internal=(net_name == self.config.network_name))
                logger.info("Created network: %s", net_name)

    def _container_id(self, tag: str = "default") -> str:
        return f"{self.config.container_name_prefix}-{tag}"

    def build_image(self, spec: Optional[ImageSpec] = None, nocache: bool = False) -> str:
        spec = spec or self.config.image
        if not spec.build_context or not spec.build_dockerfile:
            raise SandboxError("build_context and build_dockerfile are required to build an image")

        context_path = os.path.abspath(spec.build_context)
        dockerfile_path = os.path.abspath(spec.build_dockerfile)
        dockerfile_rel = os.path.relpath(dockerfile_path, context_path)

        tag = spec.short_ref
        try:
            image, _ = self._client.images.build(
                path=context_path,
                dockerfile=dockerfile_rel,
                tag=tag,
                nocache=nocache,
                rm=True,
            )
            self._image_cache[tag] = image.id
            logger.info("Built image %s (id=%s)", tag, image.short_id)
            return image.id
        except (docker.errors.BuildError, APIError, DockerException) as e:
            raise SandboxError(f"Failed to build image {tag}: {e}") from e

    def pull_image(self, spec: Optional[ImageSpec] = None) -> str:
        spec = spec or self.config.image
        try:
            image = self._client.images.pull(spec.repository, tag=spec.tag)
            self._image_cache[spec.short_ref] = image.id
            logger.info("Pulled image %s (id=%s)", spec.short_ref, image.short_id)
            return image.id
        except (ImageNotFound, APIError, DockerException) as e:
            raise SandboxError(f"Failed to pull image {spec.short_ref}: {e}") from e

    def list_images(self, repository: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            images = self._client.images.list(name=repository)
            result = []
            for img in images:
                for tag in img.tags:
                    created = img.attrs.get("Created", "")
                    size = img.attrs.get("Size", 0)
                    result.append({
                        "id": img.short_id,
                        "tag": tag,
                        "created": created,
                        "size_mb": round(size / (1024 * 1024), 2) if size else 0,
                    })
            return result
        except (APIError, DockerException) as e:
            raise SandboxError(f"Failed to list images: {e}") from e

    def remove_image(self, spec: ImageSpec) -> bool:
        try:
            self._client.images.remove(spec.full_ref, force=True)
            self._image_cache.pop(spec.short_ref, None)
            logger.info("Removed image %s", spec.full_ref)
            return True
        except (ImageNotFound, APIError, DockerException) as e:
            raise SandboxError(f"Failed to remove image {spec.full_ref}: {e}") from e

    def tag_image(self, source_spec: ImageSpec, target_spec: ImageSpec) -> None:
        try:
            image = self._client.images.get(source_spec.full_ref)
            image.tag(target_spec.repository, tag=target_spec.tag)
            logger.info("Tagged %s as %s", source_spec.full_ref, target_spec.short_ref)
        except (ImageNotFound, APIError, DockerException) as e:
            raise SandboxError(f"Failed to tag image: {e}") from e

    def create(self, tag: str = "default", env_override: Optional[Dict[str, str]] = None) -> str:
        with self._lock:
            cid = self._container_id(tag)
            if cid in self._containers:
                raise SandboxError(f"Container {cid} already exists")

            env = dict(self.config.env_vars)
            if env_override:
                env.update(env_override)

            volumes = {}
            for mount in self.config.volume_mounts:
                parts = mount.split(":", 1)
                if len(parts) == 2:
                    host_path = os.path.abspath(os.path.expanduser(parts[0]))
                    if not os.path.exists(host_path):
                        os.makedirs(host_path, exist_ok=True)
                    volumes[host_path] = {"bind": parts[1], "mode": "rw"}

            port_bindings = {}
            for container_port, host_port in self.config.exposed_ports.items():
                port_bindings[container_port] = host_port

            try:
                container = self._client.containers.run(
                    image=self.config.image.full_ref,
                    name=cid,
                    command=self.config.keep_alive_cmd,
                    detach=True,
                    network=self.config.network_name,
                    volumes=volumes,
                    ports=port_bindings if port_bindings else None,
                    cpu_quota=int(self.config.cpu_limit * 100000),
                    cpu_period=100000,
                    mem_limit=self.config.memory_limit,
                    memswap_limit=self.config.memory_swap_limit,
                    pids_limit=self.config.pids_limit,
                    privileged=self.config.privileged,
                    user=self.config.user,
                    working_dir=self.config.work_dir,
                    read_only=self.config.read_only_rootfs,
                    environment=env,
                    hostname=f"sandbox-{tag}",
                    restart_policy={"Name": "no"},
                    stop_signal="SIGTERM",
                )
                self._containers[cid] = container
                logger.info("Created sandbox container: %s (id=%s)", cid, container.short_id)

                self._apply_network_limits(cid)
                return cid
            except (ImageNotFound, APIError, DockerException) as e:
                raise SandboxError(f"Failed to create container {cid}: {e}") from e

    def start(self, tag: str = "default") -> None:
        cid = self._container_id(tag)
        container = self._containers.get(cid)
        if not container:
            raise SandboxError(f"Container {cid} is not active")
        try:
            container.start()
            logger.info("Started sandbox container: %s", cid)
        except (APIError, DockerException) as e:
            raise SandboxError(f"Failed to start container {cid}: {e}") from e

    def stop(self, tag: str = "default", timeout: int = 10) -> None:
        cid = self._container_id(tag)
        container = self._containers.get(cid)
        if not container:
            raise SandboxError(f"Container {cid} is not active")
        try:
            container.stop(timeout=timeout)
            logger.info("Stopped sandbox container: %s", cid)
        except (NotFound, APIError, DockerException) as e:
            raise SandboxError(f"Failed to stop container {cid}: {e}") from e

    def destroy(self, tag: str = "default") -> None:
        with self._lock:
            cid = self._container_id(tag)
            container = self._containers.pop(cid, None)
            if container is None:
                try:
                    container = self._client.containers.get(cid)
                except NotFound:
                    logger.warning("Container %s not found for destruction", cid)
                    return

            try:
                container.stop(timeout=10)
                container.remove(v=True, force=True)
                logger.info("Destroyed sandbox container: %s", cid)
            except (NotFound, APIError, DockerException) as e:
                raise SandboxError(f"Failed to destroy container {cid}: {e}") from e

    def clean(self, tag: str = "default") -> None:
        cid = self._container_id(tag)
        container = self._containers.get(cid)
        if not container:
            raise SandboxError(f"Container {cid} is not active")
        try:
            result = container.exec_run(
                cmd=["rm", "-rf", f"{self.config.work_dir}/.hivebreach", f"{self.config.work_dir}/tmp"],
                user=self.config.user,
            )
            if result.exit_code != 0:
                logger.warning("Clean command exited %d: %s", result.exit_code, result.output.decode(errors="replace"))
            logger.info("Cleaned sandbox workspace: %s", cid)
        except (APIError, DockerException) as e:
            raise SandboxError(f"Failed to clean container {cid}: {e}") from e

    def reset(self, tag: str = "default") -> str:
        self.destroy(tag)
        return self.create(tag)

    def snapshot(self, tag: str = "default") -> str:
        with self._lock:
            cid = self._container_id(tag)
            container = self._containers.get(cid)
            if not container:
                raise SandboxError(f"Container {cid} is not active")
            try:
                ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                snap_id = f"{cid}-{ts}"
                image = container.commit(repository=f"{cid}-snap", tag=ts)
                self._snapshots[tag] = image.id
                logger.info("Snapshot taken: %s -> %s", snap_id, image.short_id)
                return image.id
            except (APIError, DockerException) as e:
                raise SandboxError(f"Failed to snapshot container {cid}: {e}") from e

    def restore(self, tag: str = "default") -> str:
        with self._lock:
            snap_id = self._snapshots.get(tag)
            if not snap_id:
                raise SandboxError(f"No snapshot found for tag '{tag}'")
            self.destroy(tag)

            cid = self._container_id(tag)
            try:
                image = self._client.images.get(snap_id)
                container = self._client.containers.run(
                    image=image,
                    name=cid,
                    command=self.config.keep_alive_cmd,
                    detach=True,
                    network=self.config.network_name,
                    user=self.config.user,
                    working_dir=self.config.work_dir,
                    read_only=self.config.read_only_rootfs,
                    hostname=f"sandbox-{tag}",
                    restart_policy={"Name": "no"},
                    stop_signal="SIGTERM",
                )
                self._containers[cid] = container
                logger.info("Restored container from snapshot: %s", cid)
                return cid
            except (ImageNotFound, APIError, DockerException) as e:
                raise SandboxError(f"Failed to restore container {cid}: {e}") from e

    def health_check(self, tag: str = "default") -> Dict[str, Any]:
        cid = self._container_id(tag)
        container = self._containers.get(cid)
        if not container:
            return {"status": "not_found", "container": cid}

        try:
            container.reload()
            state = container.attrs.get("State", {})
            status = state.get("Status", "unknown")
            health = state.get("Health", {}).get("Status", None)

            exec_test = container.exec_run(cmd=["echo", "pong"], user=self.config.user)
            reachable = exec_test.exit_code == 0 and exec_test.output.decode(errors="replace").strip() == "pong"

            result = {
                "status": status,
                "health": health,
                "reachable": reachable,
                "container": cid,
                "created": container.attrs.get("Created"),
                "image": container.image.tags,
            }
            return result
        except (NotFound, APIError, DockerException) as e:
            return {"status": "error", "container": cid, "error": str(e)}

    def wait_healthy(self, tag: str = "default", timeout: float = 30.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = self.health_check(tag)
            if result.get("reachable") and result.get("status") == "running":
                return True
            time.sleep(self.config.health_check_interval)
        return False

    def exec_run(self, tag: str, cmd: List[str], **kwargs) -> tuple[int, str]:
        cid = self._container_id(tag)
        container = self._containers.get(cid)
        if not container:
            raise SandboxError(f"Container {cid} is not active")
        try:
            result = container.exec_run(cmd=cmd, **kwargs)
            return result.exit_code, result.output.decode(errors="replace")
        except (APIError, DockerException) as e:
            raise SandboxError(f"Exec failed on {cid}: {e}") from e

    def copy_to(self, tag: str, src: str, dst: str) -> None:
        cid = self._container_id(tag)
        container = self._containers.get(cid)
        if not container:
            raise SandboxError(f"Container {cid} is not active")
        try:
            with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
                tmp_path = tmp.name
            import tarfile
            with tarfile.open(tmp_path, "w") as tar:
                tar.add(src, arcname=os.path.basename(dst))
            with open(tmp_path, "rb") as f:
                container.put_archive(os.path.dirname(dst), f.read())
            os.unlink(tmp_path)
        except (APIError, DockerException, OSError) as e:
            raise SandboxError(f"Failed to copy to container {cid}: {e}") from e

    def copy_from(self, tag: str, src: str, dst: str) -> None:
        cid = self._container_id(tag)
        container = self._containers.get(cid)
        if not container:
            raise SandboxError(f"Container {cid} is not active")
        try:
            data, _ = container.get_archive(src)
            import tarfile
            import io
            buf = io.BytesIO()
            for chunk in data:
                buf.write(chunk)
            buf.seek(0)
            with tarfile.open(fileobj=buf) as tar:
                tar.extractall(path=dst)
        except (NotFound, APIError, DockerException, OSError) as e:
            raise SandboxError(f"Failed to copy from container {cid}: {e}") from e

    def _apply_network_limits(self, cid: str) -> None:
        if platform.system() != "Linux":
            return
        container = self._containers.get(cid)
        if not container:
            return
        try:
            pid = container.attrs["State"]["Pid"]
            iface = "eth0"
            script = (
                f"tc qdisc add dev {iface} root tbf rate {self.config.network_rate}"
                f" burst 65536 latency 50ms peakrate {self.config.network_ceil}"
                f" mtu 1500 2>/dev/null || true"
            )
            os.system(f"nsenter -t {pid} -n -- {script}")
            logger.debug("Applied network limits to %s", cid)
        except (KeyError, OSError) as e:
            logger.warning("Could not apply network limits: %s", e)

    def get_container_ip(self, tag: str = "default") -> Optional[str]:
        cid = self._container_id(tag)
        container = self._containers.get(cid)
        if not container:
            return None
        try:
            container.reload()
            net_settings = container.attrs.get("NetworkSettings", {})
            networks = net_settings.get("Networks", {})
            net_info = networks.get(self.config.network_name, {})
            return net_info.get("IPAddress")
        except (NotFound, APIError, DockerException) as e:
            logger.warning("Failed to get IP for %s: %s", cid, e)
            return None

    def list_containers(self) -> List[Dict[str, Any]]:
        result = []
        for tag, container in list(self._containers.items()):
            try:
                container.reload()
                result.append({
                    "tag": tag,
                    "id": container.short_id,
                    "status": container.attrs.get("State", {}).get("Status"),
                    "ip": self.get_container_ip(tag),
                })
            except (NotFound, APIError, DockerException):
                result.append({"tag": tag, "status": "lost"})
                self._containers.pop(tag, None)
        return result

    def cleanup(self) -> None:
        with self._lock:
            cids = list(self._containers.keys())
            for cid in cids:
                container = self._containers.pop(cid, None)
                if container is None:
                    continue
                try:
                    container.stop(timeout=5)
                except Exception as e:
                    logger.error("Cleanup stop error for %s: %s", cid, e)
                try:
                    container.remove(v=True, force=True)
                except Exception as e:
                    logger.error("Cleanup remove error for %s: %s", cid, e)
            if self._tmp_dir and os.path.isdir(self._tmp_dir):
                shutil.rmtree(self._tmp_dir, ignore_errors=True)
            if self._client:
                try:
                    self._client.close()
                except DockerException:
                    pass
        logger.info("SandboxManager cleaned up")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
