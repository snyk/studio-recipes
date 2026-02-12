#!/usr/bin/env python3
"""
Snyk Cache Module
=================

Manages caching of Snyk scan results to speed up the pre-commit hook.

Cache is stored in the system temp directory to avoid project pollution:
    /tmp/snyk-cache-{workspace_hash}/
    ├── sast/
    │   └── {filename}.{content_hash}.json
    ├── sca/
    │   └── {package}@{version}.json
    └── meta.json

Usage:
    from cache import SnykCache, get_cache_dir
    
    cache = SnykCache(cache_dir=get_cache_dir("/path/to/workspace"))
    
    # SAST
    result = cache.get_sast_result("server.ts")
    cache.set_sast_result("server.ts", vulnerabilities)
    
    # SCA
    result = cache.get_sca_result("lodash", "4.17.21")
    cache.set_sca_result("lodash", "4.17.21", vulnerabilities, severity_counts)
"""

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import fcntl
import time


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_TTL_HOURS = 12
LOCK_TIMEOUT_SECONDS = 5


def get_cache_dir(workspace: str = None) -> str:
    """
    Get cache directory for a workspace.
    
    Uses system temp directory with workspace hash for:
    - No project directory pollution
    - Multi-project isolation
    - No .gitignore entry needed
    
    Note: Cache is cleared on system reboot (temp directory behavior).
    
    Args:
        workspace: Workspace/project root path. Defaults to cwd.
    
    Returns:
        Path to cache directory (e.g., /tmp/snyk-cache-a1b2c3d4)
    """
    if workspace is None:
        workspace = os.getcwd()
    
    # Normalize the workspace path for consistent hashing
    workspace = os.path.abspath(workspace)
    
    # Create workspace-specific hash to avoid collisions between projects
    # SHA256 to match the hash in other places
    workspace_hash = hashlib.sha256(workspace.encode()).hexdigest()[:8]
    
    return os.path.join(tempfile.gettempdir(), f"snyk-cache-{workspace_hash}")


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CachedVulnerability:
    """A cached vulnerability entry."""
    id: str
    title: str
    severity: str
    message: str = ""
    # SAST-specific
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    # SCA-specific
    fixed_version: Optional[str] = None
    cve: Optional[str] = None


@dataclass
class SastCacheEntry:
    """Cached SAST scan result for a single file."""
    file_path: str
    content_hash: str
    scanned_at: str  # ISO format
    expires_at: str  # ISO format
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def is_expired(self) -> bool:
        """Check if this cache entry has expired."""
        expires = datetime.fromisoformat(self.expires_at)
        return datetime.now() > expires
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SastCacheEntry":
        return cls(**data)


@dataclass
class ScaCacheEntry:
    """Cached SCA scan result for a package@version."""
    package: str
    version: str
    scanned_at: str
    expires_at: str
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0
    })
    
    @property
    def is_expired(self) -> bool:
        expires = datetime.fromisoformat(self.expires_at)
        return datetime.now() > expires
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScaCacheEntry":
        return cls(**data)


@dataclass
class CacheMeta:
    """Cache metadata."""
    created_at: str
    last_accessed: str
    version: str = "1.0"
    stats: Dict[str, int] = field(default_factory=lambda: {
        "sast_hits": 0,
        "sast_misses": 0,
        "sca_hits": 0,
        "sca_misses": 0
    })


# =============================================================================
# FILE LOCKING
# =============================================================================

class FileLock:
    """Simple file-based lock for cache operations."""
    
    def __init__(self, lock_path: Path, timeout: float = LOCK_TIMEOUT_SECONDS):
        self.lock_path = lock_path
        self.timeout = timeout
        self.lock_file = None
    
    def __enter__(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_file = open(self.lock_path, 'w')
        
        start_time = time.time()
        while True:
            try:
                fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except (IOError, OSError):
                if time.time() - start_time > self.timeout:
                    raise TimeoutError(f"Could not acquire lock: {self.lock_path}")
                time.sleep(0.1)
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.lock_file:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            self.lock_file.close()


# =============================================================================
# CACHE IMPLEMENTATION
# =============================================================================

class SnykCache:
    """
    Manages Snyk scan result caching.
    
    Thread-safe via file locking.
    """
    
    def __init__(self, cache_dir: str = None, ttl_hours: int = DEFAULT_TTL_HOURS):
        # Use temp directory by default
        if cache_dir is None:
            cache_dir = get_cache_dir()
        self.cache_dir = Path(cache_dir)
        self.ttl = timedelta(hours=ttl_hours)
        self.sast_dir = self.cache_dir / "sast"
        self.sca_dir = self.cache_dir / "sca"
        self.meta_file = self.cache_dir / "meta.json"
        self.lock_file = self.cache_dir / ".lock"
        
        self._ensure_dirs()
    
    def _ensure_dirs(self) -> None:
        """Create cache directories if they don't exist."""
        self.sast_dir.mkdir(parents=True, exist_ok=True)
        self.sca_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize meta if needed
        if not self.meta_file.exists():
            self._write_meta(CacheMeta(
                created_at=datetime.now().isoformat(),
                last_accessed=datetime.now().isoformat()
            ))
    
    def _read_meta(self) -> CacheMeta:
        """Read cache metadata."""
        try:
            with open(self.meta_file, 'r') as f:
                data = json.load(f)
                return CacheMeta(**data)
        except (FileNotFoundError, json.JSONDecodeError):
            return CacheMeta(
                created_at=datetime.now().isoformat(),
                last_accessed=datetime.now().isoformat()
            )
    
    def _write_meta(self, meta: CacheMeta) -> None:
        """Write cache metadata."""
        meta.last_accessed = datetime.now().isoformat()
        with open(self.meta_file, 'w') as f:
            json.dump(asdict(meta), f, indent=2)
    
    def _update_stats(self, stat_key: str) -> None:
        """Update cache statistics."""
        try:
            meta = self._read_meta()
            meta.stats[stat_key] = meta.stats.get(stat_key, 0) + 1
            self._write_meta(meta)
        except Exception:
            pass  # Stats are best-effort
    
    # -------------------------------------------------------------------------
    # SAST Cache Operations
    # -------------------------------------------------------------------------
    
    def compute_file_hash(self, file_path: str) -> str:
        """Compute content hash for a file."""
        path = Path(file_path)
        if not path.exists():
            return ""
        
        hasher = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        
        return hasher.hexdigest()[:16]  # First 16 chars is enough
    
    def _sast_cache_path(self, file_path: str, content_hash: str) -> Path:
        """Get cache file path for a SAST entry."""
        # Sanitize file path for use as filename
        safe_name = Path(file_path).name.replace("/", "_").replace("\\", "_")
        return self.sast_dir / f"{safe_name}.{content_hash}.json"
    
    def get_sast_result(self, file_path: str) -> Optional[SastCacheEntry]:
        """
        Get cached SAST result for a file.
        
        Returns None if:
        - No cache entry exists
        - Cache entry is for different content (file changed)
        - Cache entry has expired
        """
        content_hash = self.compute_file_hash(file_path)
        if not content_hash:
            return None
        
        cache_path = self._sast_cache_path(file_path, content_hash)
        
        try:
            with FileLock(self.lock_file):
                if not cache_path.exists():
                    self._update_stats("sast_misses")
                    return None
                
                with open(cache_path, 'r') as f:
                    data = json.load(f)
                
                entry = SastCacheEntry.from_dict(data)
                
                # Validate hash matches (content hasn't changed)
                if entry.content_hash != content_hash:
                    self._update_stats("sast_misses")
                    return None
                
                # Check expiration
                if entry.is_expired:
                    cache_path.unlink(missing_ok=True)
                    self._update_stats("sast_misses")
                    return None
                
                self._update_stats("sast_hits")
                return entry
                
        except (json.JSONDecodeError, KeyError, FileNotFoundError):
            self._update_stats("sast_misses")
            return None
    
    def set_sast_result(
        self,
        file_path: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> None:
        """Store SAST result in cache."""
        content_hash = self.compute_file_hash(file_path)
        if not content_hash:
            return
        
        now = datetime.now()
        entry = SastCacheEntry(
            file_path=file_path,
            content_hash=content_hash,
            scanned_at=now.isoformat(),
            expires_at=(now + self.ttl).isoformat(),
            vulnerabilities=vulnerabilities
        )
        
        cache_path = self._sast_cache_path(file_path, content_hash)
        
        with FileLock(self.lock_file):
            with open(cache_path, 'w') as f:
                json.dump(entry.to_dict(), f, indent=2)
    
    def invalidate_sast(self, file_path: str) -> None:
        """Remove all cache entries for a file (any hash)."""
        safe_name = Path(file_path).name.replace("/", "_").replace("\\", "_")
        pattern = f"{safe_name}.*.json"
        
        with FileLock(self.lock_file):
            for cache_file in self.sast_dir.glob(pattern):
                cache_file.unlink(missing_ok=True)
    
    # -------------------------------------------------------------------------
    # SCA Cache Operations
    # -------------------------------------------------------------------------
    
    def _sca_cache_path(self, package: str, version: str) -> Path:
        """Get cache file path for an SCA entry."""
        # Remove version specifier chars for filename
        clean_version = version.lstrip('^~>=<')
        safe_name = f"{package}@{clean_version}".replace("/", "_")
        return self.sca_dir / f"{safe_name}.json"
    
    def get_sca_result(self, package: str, version: str) -> Optional[ScaCacheEntry]:
        """
        Get cached SCA result for a package@version.
        
        Returns None if:
        - No cache entry exists
        - Cache entry has expired
        """
        cache_path = self._sca_cache_path(package, version)
        
        try:
            with FileLock(self.lock_file):
                if not cache_path.exists():
                    self._update_stats("sca_misses")
                    return None
                
                with open(cache_path, 'r') as f:
                    data = json.load(f)
                
                entry = ScaCacheEntry.from_dict(data)
                
                # Check expiration
                if entry.is_expired:
                    cache_path.unlink(missing_ok=True)
                    self._update_stats("sca_misses")
                    return None
                
                self._update_stats("sca_hits")
                return entry
                
        except (json.JSONDecodeError, KeyError, FileNotFoundError):
            self._update_stats("sca_misses")
            return None
    
    def set_sca_result(
        self,
        package: str,
        version: str,
        vulnerabilities: List[Dict[str, Any]],
        severity_counts: Optional[Dict[str, int]] = None
    ) -> None:
        """Store SCA result in cache."""
        now = datetime.now()
        
        # Calculate severity counts if not provided
        if severity_counts is None:
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for v in vulnerabilities:
                sev = v.get("severity", "low").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
        
        entry = ScaCacheEntry(
            package=package,
            version=version,
            scanned_at=now.isoformat(),
            expires_at=(now + self.ttl).isoformat(),
            vulnerabilities=vulnerabilities,
            severity_counts=severity_counts
        )
        
        cache_path = self._sca_cache_path(package, version)
        
        with FileLock(self.lock_file):
            with open(cache_path, 'w') as f:
                json.dump(entry.to_dict(), f, indent=2)
    
    def invalidate_sca(self, package: str) -> None:
        """Remove all cache entries for a package (any version)."""
        pattern = f"{package}@*.json"
        
        with FileLock(self.lock_file):
            for cache_file in self.sca_dir.glob(pattern):
                cache_file.unlink(missing_ok=True)
    
    # -------------------------------------------------------------------------
    # Cache Management
    # -------------------------------------------------------------------------
    
    def clear(self) -> int:
        """
        Clear all cache entries.
        
        Returns number of entries cleared.
        """
        count = 0
        
        with FileLock(self.lock_file):
            for cache_file in self.sast_dir.glob("*.json"):
                cache_file.unlink(missing_ok=True)
                count += 1
            
            for cache_file in self.sca_dir.glob("*.json"):
                cache_file.unlink(missing_ok=True)
                count += 1
        
        return count
    
    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries.
        
        Returns number of entries removed.
        """
        count = 0
        now = datetime.now()
        
        with FileLock(self.lock_file):
            # Cleanup SAST
            for cache_file in self.sast_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        data = json.load(f)
                    expires = datetime.fromisoformat(data.get("expires_at", "1970-01-01"))
                    if now > expires:
                        cache_file.unlink()
                        count += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    cache_file.unlink()
                    count += 1
            
            # Cleanup SCA
            for cache_file in self.sca_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        data = json.load(f)
                    expires = datetime.fromisoformat(data.get("expires_at", "1970-01-01"))
                    if now > expires:
                        cache_file.unlink()
                        count += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    cache_file.unlink()
                    count += 1
        
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        meta = self._read_meta()
        
        sast_count = len(list(self.sast_dir.glob("*.json")))
        sca_count = len(list(self.sca_dir.glob("*.json")))
        
        # Calculate cache size
        total_size = 0
        for f in self.cache_dir.rglob("*.json"):
            total_size += f.stat().st_size
        
        return {
            "sast_entries": sast_count,
            "sca_entries": sca_count,
            "total_entries": sast_count + sca_count,
            "size_bytes": total_size,
            "size_human": f"{total_size / 1024:.1f} KB",
            "hits": meta.stats.get("sast_hits", 0) + meta.stats.get("sca_hits", 0),
            "misses": meta.stats.get("sast_misses", 0) + meta.stats.get("sca_misses", 0),
            "created_at": meta.created_at,
            "last_accessed": meta.last_accessed
        }


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == '__main__':
    import argparse
    
    default_cache = get_cache_dir()
    
    parser = argparse.ArgumentParser(description='Snyk cache management')
    parser.add_argument('--stats', action='store_true', help='Show cache statistics')
    parser.add_argument('--clear', action='store_true', help='Clear all cache entries')
    parser.add_argument('--cleanup', action='store_true', help='Remove expired entries')
    parser.add_argument('--cache-dir', default=default_cache, help=f'Cache directory (default: {default_cache})')
    parser.add_argument('--workspace', help='Workspace path (used to compute cache dir)')
    
    args = parser.parse_args()
    
    # Determine cache directory
    if args.workspace:
        cache_dir = get_cache_dir(args.workspace)
    else:
        cache_dir = args.cache_dir
    
    cache = SnykCache(cache_dir=cache_dir)
    
    if args.stats:
        stats = cache.get_stats()
        print("=== Snyk Cache Statistics ===")
        print(f"  Location: {cache_dir}")
        print(f"  SAST entries: {stats['sast_entries']}")
        print(f"  SCA entries: {stats['sca_entries']}")
        print(f"  Total size: {stats['size_human']}")
        print(f"  Cache hits: {stats['hits']}")
        print(f"  Cache misses: {stats['misses']}")
        if stats['hits'] + stats['misses'] > 0:
            hit_rate = stats['hits'] / (stats['hits'] + stats['misses']) * 100
            print(f"  Hit rate: {hit_rate:.1f}%")
    
    elif args.clear:
        count = cache.clear()
        print(f"Cleared {count} cache entries from {cache_dir}")
    
    elif args.cleanup:
        count = cache.cleanup_expired()
        print(f"Removed {count} expired entries from {cache_dir}")
    
    else:
        parser.print_help()

