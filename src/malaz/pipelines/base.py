"""Pipeline base class and shared helpers."""

from __future__ import annotations

import abc

from ..models import AnalysisContext, Indicator


class Pipeline(abc.ABC):
    """Base class for all analysis pipelines.

    A pipeline performs *static* analysis of one file and returns a list of
    :class:`Indicator` objects. Pipelines must never execute payload code and
    should treat all file content as untrusted.
    """

    #: Stable, human-readable pipeline name (also used as ``Indicator.source``).
    name: str = "pipeline"

    @abc.abstractmethod
    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        """Analyse the file described by ``ctx`` and return indicators."""
        raise NotImplementedError

    # -- helpers ------------------------------------------------------------ #

    def _indicator(self, rule_id: str, title: str, **kwargs) -> Indicator:
        kwargs.setdefault("source", self.name)
        return Indicator(rule_id=rule_id, title=title, **kwargs)
