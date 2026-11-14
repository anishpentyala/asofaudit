"""Audit explicit feature selections; no payload evaluation or network access."""

from .core import AuditError, audit

__all__ = ["AuditError", "audit"]
