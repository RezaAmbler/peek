"""
Local filesystem storage services for screenshots and tool artifacts.

Designed with a simple interface that can be extended to S3-compatible storage later.

Storage paths:
  - Screenshots: {SCREENSHOT_STORAGE_PATH}/{scan_id}/{port_id}.png
  - Artifacts: {ARTIFACT_STORAGE_PATH}/{scan_id}/{tool_execution_id}.txt
"""
import logging
import shutil
from pathlib import Path
from typing import Optional

from ..core.config import settings

logger = logging.getLogger(__name__)


class ScreenshotStorage:
    """
    Local filesystem storage for screenshots.

    Directory structure:
        {base_path}/
            {scan_id}/
                {port_id}.png
    """

    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path or settings.SCREENSHOT_STORAGE_PATH)

    def _ensure_dir(self, path: Path) -> None:
        """Create directory if it doesn't exist."""
        path.mkdir(parents=True, exist_ok=True)

    def get_scan_dir(self, scan_id: str) -> Path:
        """Get the directory path for a scan's screenshots."""
        return self.base_path / scan_id

    def get_screenshot_path(self, scan_id: str, port_id: str) -> Path:
        """Get the full path for a screenshot file."""
        return self.get_scan_dir(scan_id) / f"{port_id}.png"

    def get_relative_path(self, scan_id: str, port_id: str) -> str:
        """Get the relative path (for database storage)."""
        return f"{scan_id}/{port_id}.png"

    def save_screenshot(self, scan_id: str, port_id: str, source_path: Path) -> Optional[str]:
        """
        Save a screenshot from a temporary file to permanent storage.

        Args:
            scan_id: The scan ID
            port_id: The port ID
            source_path: Path to the temporary screenshot file

        Returns:
            Relative path to saved screenshot, or None if failed
        """
        try:
            if not source_path.exists():
                logger.warning(f"Screenshot source file not found: {source_path}")
                return None

            dest_path = self.get_screenshot_path(scan_id, port_id)
            self._ensure_dir(dest_path.parent)

            # Move file to permanent storage
            shutil.move(str(source_path), str(dest_path))

            relative_path = self.get_relative_path(scan_id, port_id)
            logger.debug(f"Saved screenshot: {relative_path}")
            return relative_path

        except Exception as e:
            logger.error(f"Failed to save screenshot for {scan_id}/{port_id}: {e}")
            return None

    def get_screenshot(self, relative_path: str) -> Optional[Path]:
        """
        Get the full path to a screenshot file.

        Args:
            relative_path: Relative path stored in database (e.g., "scan_id/port_id.png")

        Returns:
            Full path to screenshot, or None if not found
        """
        full_path = self.base_path / relative_path
        if full_path.exists():
            return full_path
        return None

    def delete_scan_screenshots(self, scan_id: str) -> bool:
        """
        Delete all screenshots for a scan.

        Args:
            scan_id: The scan ID

        Returns:
            True if deleted successfully (or didn't exist), False on error
        """
        try:
            scan_dir = self.get_scan_dir(scan_id)
            if scan_dir.exists():
                shutil.rmtree(str(scan_dir))
                logger.info(f"Deleted screenshots for scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete screenshots for scan {scan_id}: {e}")
            return False

    def delete_screenshot(self, relative_path: str) -> bool:
        """
        Delete a single screenshot.

        Args:
            relative_path: Relative path stored in database

        Returns:
            True if deleted successfully (or didn't exist), False on error
        """
        try:
            full_path = self.base_path / relative_path
            if full_path.exists():
                full_path.unlink()
                logger.debug(f"Deleted screenshot: {relative_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete screenshot {relative_path}: {e}")
            return False

    def get_storage_stats(self) -> dict:
        """Get storage statistics."""
        try:
            if not self.base_path.exists():
                return {"total_scans": 0, "total_screenshots": 0, "total_size_bytes": 0}

            total_scans = 0
            total_screenshots = 0
            total_size = 0

            for scan_dir in self.base_path.iterdir():
                if scan_dir.is_dir():
                    total_scans += 1
                    for screenshot in scan_dir.glob("*.png"):
                        total_screenshots += 1
                        total_size += screenshot.stat().st_size

            return {
                "total_scans": total_scans,
                "total_screenshots": total_screenshots,
                "total_size_bytes": total_size
            }
        except Exception as e:
            logger.error(f"Failed to get storage stats: {e}")
            return {"error": str(e)}


class ArtifactStorage:
    """
    Local filesystem storage for tool output artifacts.

    Used to store full raw output when it exceeds the 50KB truncation limit.
    Directory structure:
        {base_path}/
            {scan_id}/
                {tool_execution_id}.txt
    """

    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path or settings.ARTIFACT_STORAGE_PATH)

    def _ensure_dir(self, path: Path) -> None:
        """Create directory if it doesn't exist."""
        path.mkdir(parents=True, exist_ok=True)

    def get_scan_dir(self, scan_id: str) -> Path:
        """Get the directory path for a scan's artifacts."""
        return self.base_path / scan_id

    def get_artifact_path(self, scan_id: str, tool_execution_id: str, extension: str = "txt") -> Path:
        """Get the full path for an artifact file."""
        return self.get_scan_dir(scan_id) / f"{tool_execution_id}.{extension}"

    def get_relative_path(self, scan_id: str, tool_execution_id: str, extension: str = "txt") -> str:
        """Get the relative path (for database storage)."""
        return f"{scan_id}/{tool_execution_id}.{extension}"

    def save_artifact(
        self,
        scan_id: str,
        tool_execution_id: str,
        content: str,
        extension: str = "txt"
    ) -> Optional[str]:
        """
        Save tool output to artifact storage.

        Args:
            scan_id: The scan ID
            tool_execution_id: The tool execution ID
            content: The raw output content to save
            extension: File extension (default: txt)

        Returns:
            Relative path to saved artifact, or None if failed
        """
        try:
            dest_path = self.get_artifact_path(scan_id, tool_execution_id, extension)
            self._ensure_dir(dest_path.parent)

            # Write content to file
            with open(dest_path, 'w', encoding='utf-8') as f:
                f.write(content)

            relative_path = self.get_relative_path(scan_id, tool_execution_id, extension)
            logger.debug(f"Saved artifact: {relative_path} ({len(content)} bytes)")
            return relative_path

        except Exception as e:
            logger.error(f"Failed to save artifact for {scan_id}/{tool_execution_id}: {e}")
            return None

    def save_artifact_from_file(
        self,
        scan_id: str,
        tool_execution_id: str,
        source_path: Path,
        extension: str = "txt"
    ) -> Optional[str]:
        """
        Save tool output from a temporary file to permanent storage.

        Args:
            scan_id: The scan ID
            tool_execution_id: The tool execution ID
            source_path: Path to the temporary output file
            extension: File extension (default: txt)

        Returns:
            Relative path to saved artifact, or None if failed
        """
        try:
            if not source_path.exists():
                logger.warning(f"Artifact source file not found: {source_path}")
                return None

            dest_path = self.get_artifact_path(scan_id, tool_execution_id, extension)
            self._ensure_dir(dest_path.parent)

            # Move file to permanent storage
            shutil.move(str(source_path), str(dest_path))

            relative_path = self.get_relative_path(scan_id, tool_execution_id, extension)
            logger.debug(f"Saved artifact: {relative_path}")
            return relative_path

        except Exception as e:
            logger.error(f"Failed to save artifact for {scan_id}/{tool_execution_id}: {e}")
            return None

    def get_artifact(self, relative_path: str) -> Optional[str]:
        """
        Read artifact content from storage.

        Args:
            relative_path: Relative path stored in database

        Returns:
            Artifact content, or None if not found
        """
        try:
            full_path = self.base_path / relative_path
            if full_path.exists():
                with open(full_path, 'r', encoding='utf-8') as f:
                    return f.read()
            return None
        except Exception as e:
            logger.error(f"Failed to read artifact {relative_path}: {e}")
            return None

    def get_artifact_path_full(self, relative_path: str) -> Optional[Path]:
        """
        Get the full path to an artifact file.

        Args:
            relative_path: Relative path stored in database

        Returns:
            Full path to artifact, or None if not found
        """
        full_path = self.base_path / relative_path
        if full_path.exists():
            return full_path
        return None

    def delete_scan_artifacts(self, scan_id: str) -> bool:
        """
        Delete all artifacts for a scan.

        Args:
            scan_id: The scan ID

        Returns:
            True if deleted successfully (or didn't exist), False on error
        """
        try:
            scan_dir = self.get_scan_dir(scan_id)
            if scan_dir.exists():
                shutil.rmtree(str(scan_dir))
                logger.info(f"Deleted artifacts for scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete artifacts for scan {scan_id}: {e}")
            return False

    def delete_artifact(self, relative_path: str) -> bool:
        """
        Delete a single artifact.

        Args:
            relative_path: Relative path stored in database

        Returns:
            True if deleted successfully (or didn't exist), False on error
        """
        try:
            full_path = self.base_path / relative_path
            if full_path.exists():
                full_path.unlink()
                logger.debug(f"Deleted artifact: {relative_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete artifact {relative_path}: {e}")
            return False

    def get_storage_stats(self) -> dict:
        """Get storage statistics."""
        try:
            if not self.base_path.exists():
                return {"total_scans": 0, "total_artifacts": 0, "total_size_bytes": 0}

            total_scans = 0
            total_artifacts = 0
            total_size = 0

            for scan_dir in self.base_path.iterdir():
                if scan_dir.is_dir():
                    total_scans += 1
                    for artifact in scan_dir.glob("*"):
                        if artifact.is_file():
                            total_artifacts += 1
                            total_size += artifact.stat().st_size

            return {
                "total_scans": total_scans,
                "total_artifacts": total_artifacts,
                "total_size_bytes": total_size
            }
        except Exception as e:
            logger.error(f"Failed to get artifact storage stats: {e}")
            return {"error": str(e)}


# Global instances
screenshot_storage = ScreenshotStorage()
artifact_storage = ArtifactStorage()
