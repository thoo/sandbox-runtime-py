"""In-memory store for sandbox violations."""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from .sandbox_utils import encode_sandboxed_command


@dataclass
class SandboxViolationEvent:
    """A sandbox violation event."""

    line: str
    command: str | None = None
    encoded_command: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)


ViolationListener = Callable[[list[SandboxViolationEvent]], None]


class SandboxViolationStore:
    """In-memory tail for sandbox violations."""

    def __init__(self, max_size: int = 100) -> None:
        """
        Initialize the violation store.

        Args:
            max_size: Maximum number of violations to keep in memory
        """
        self._violations: list[SandboxViolationEvent] = []
        self._total_count = 0
        self._max_size = max_size
        self._listeners: set[ViolationListener] = set()

    def add_violation(self, violation: SandboxViolationEvent) -> None:
        """Add a violation to the store."""
        self._violations.append(violation)
        self._total_count += 1

        if len(self._violations) > self._max_size:
            self._violations = self._violations[-self._max_size :]

        self._notify_listeners()

    def get_violations(self, limit: int | None = None) -> list[SandboxViolationEvent]:
        """
        Get violations from the store.

        Args:
            limit: Maximum number of violations to return (from the end)

        Returns:
            List of violations
        """
        if limit is None:
            return list(self._violations)
        return self._violations[-limit:]

    def get_count(self) -> int:
        """Get the current number of violations in the store."""
        return len(self._violations)

    def get_total_count(self) -> int:
        """Get the total number of violations ever recorded."""
        return self._total_count

    def get_violations_for_command(self, command: str) -> list[SandboxViolationEvent]:
        """
        Get violations for a specific command.

        Args:
            command: The command to filter by

        Returns:
            List of violations for the command
        """
        command_base64 = encode_sandboxed_command(command)
        return [v for v in self._violations if v.encoded_command == command_base64]

    def clear(self) -> None:
        """Clear all violations from the store (but keep total count)."""
        self._violations = []
        self._notify_listeners()

    def subscribe(self, listener: ViolationListener) -> Callable[[], None]:
        """
        Subscribe to violation updates.

        Args:
            listener: Callback function that receives the list of violations

        Returns:
            Unsubscribe function
        """
        self._listeners.add(listener)
        # Immediately call with current violations
        listener(self.get_violations())

        def unsubscribe() -> None:
            self._listeners.discard(listener)

        return unsubscribe

    def _notify_listeners(self) -> None:
        """Notify all listeners of changes."""
        violations = self.get_violations()
        for listener in self._listeners:
            listener(violations)
