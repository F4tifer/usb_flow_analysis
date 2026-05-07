"""USB Linux mmap PCAP analysis."""

from usb_analysis.pipeline import ensure_mmap_link, iter_mmap_packets, peek_pcap_globals

__all__ = ["iter_mmap_packets", "ensure_mmap_link", "peek_pcap_globals", "__version__"]


def _read_version() -> str:
    """Resolve version. pyproject.toml is the project's source of truth — we
    prefer it when running from a source checkout (the file is fresher than
    `pip install -e .` metadata, which goes stale across edits). Fall back to
    installed package metadata when no pyproject.toml is reachable (e.g. when
    the package is installed as a wheel into site-packages)."""
    from pathlib import Path
    here = Path(__file__).resolve().parent
    # Walk up looking for a project-root pyproject.toml.
    try:
        import tomllib  # py3.11+
    except ImportError:  # pragma: no cover
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            tomllib = None  # type: ignore[assignment]
    if tomllib is not None:
        for parent in (here, *here.parents):
            pyproject = parent / "pyproject.toml"
            if pyproject.is_file():
                try:
                    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
                    proj = data.get("project") or {}
                    if proj.get("name") == "usb-analysis":
                        v = proj.get("version")
                        if v:
                            return str(v)
                except Exception:
                    pass
                break  # don't keep searching past the first pyproject.toml
    # Wheel / installed-package fallback — metadata is authoritative there.
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("usb-analysis")
        except PackageNotFoundError:
            return "unknown"
    except ImportError:  # pragma: no cover
        return "unknown"


__version__ = _read_version()
