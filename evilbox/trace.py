"""Auditable log of every rewrite applied during a decode."""

from __future__ import annotations

from dataclasses import dataclass, field

from evilbox.hashutil import sha256_text


@dataclass
class TraceStep:
    """One transformation: pass name, optional detail, before/after digests."""

    pass_name: str
    detail: str
    before_sha256: str
    after_sha256: str
    before_size: int
    after_size: int
    changed: bool

    def to_dict(self) -> dict:
        return {
            "pass": self.pass_name,
            "detail": self.detail,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "before_size": self.before_size,
            "after_size": self.after_size,
            "changed": self.changed,
            "delta_bytes": self.after_size - self.before_size,
        }


@dataclass
class Trace:
    """Ordered list of TraceStep entries for one sample."""

    steps: list[TraceStep] = field(default_factory=list)

    def record(self, pass_name: str, before: str, after: str, *, detail: str = "") -> TraceStep:
        step = TraceStep(
            pass_name=pass_name,
            detail=detail,
            before_sha256=sha256_text(before),
            after_sha256=sha256_text(after),
            before_size=len(before),
            after_size=len(after),
            changed=before != after,
        )
        self.steps.append(step)
        return step

    def record_note(self, pass_name: str, text: str, *, detail: str) -> TraceStep:
        """Log a non-mutating analysis step against a fixed buffer."""
        digest = sha256_text(text)
        step = TraceStep(
            pass_name=pass_name,
            detail=detail,
            before_sha256=digest,
            after_sha256=digest,
            before_size=len(text),
            after_size=len(text),
            changed=False,
        )
        self.steps.append(step)
        return step

    def to_dict(self) -> dict:
        return {
            "steps": [step.to_dict() for step in self.steps],
            "pass_count": len(self.steps),
            "changed_count": sum(1 for step in self.steps if step.changed),
        }
