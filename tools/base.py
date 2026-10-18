"""
Base class for all GuardML tools.
Every tool is a thin, safe wrapper with pydantic validation.
"""
from __future__ import annotations
import abc
import time
import logging
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    READ = 'read'
    WRITE_LOW = 'write_low'
    WRITE_HIGH = 'write_high'


class ToolResult(BaseModel):
    ok: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    truncated: bool = False
    elapsed_ms: float = 0.0


MAX_OUTPUT_CHARS = int(8000)


class BaseTool(abc.ABC):
    """Abstract base for all GuardML tools."""

    name: str
    description: str
    parameters_schema: Dict[str, Any]
    risk_level: RiskLevel
    timeout_seconds: float = 30.0

    @abc.abstractmethod
    def _execute(self, **kwargs) -> Any:
        """Core execution logic. Raise on error."""
        ...

    def run(self, **kwargs) -> ToolResult:
        """Validate args, execute with timeout, return structured result."""
        start = time.monotonic()
        try:
            result = self._execute(**kwargs)
            elapsed = (time.monotonic() - start) * 1000
            data_str = str(result) if not isinstance(result, str) else result
            truncated = len(data_str) > MAX_OUTPUT_CHARS
            if truncated:
                data_str = data_str[:MAX_OUTPUT_CHARS] + '\n... [truncated]'
                result = data_str
            return ToolResult(ok=True, data=result, elapsed_ms=elapsed, truncated=truncated)
        except ValidationError as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.error('Validation error in %s: %s', self.name, e)
            return ToolResult(ok=False, error=f'Validation error: {e}', elapsed_ms=elapsed)
        except TimeoutError:
            elapsed = (time.monotonic() - start) * 1000
            return ToolResult(ok=False, error=f'Tool {self.name} timed out after {self.timeout_seconds}s', elapsed_ms=elapsed)
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.error('Error in %s: %s', self.name, e, exc_info=True)
            return ToolResult(ok=False, error=str(e), elapsed_ms=elapsed)

    def to_schema(self) -> Dict[str, Any]:
        """Return the Anthropic-compatible tool schema."""
        return {
            'name': self.name,
            'description': self.description,
            'input_schema': self.parameters_schema,
        }
