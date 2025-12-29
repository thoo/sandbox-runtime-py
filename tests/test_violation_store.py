"""Tests for sandbox_runtime.violation_store module."""

from datetime import datetime

from sandbox_runtime.sandbox_utils import encode_sandboxed_command
from sandbox_runtime.violation_store import SandboxViolationEvent, SandboxViolationStore


class TestSandboxViolationEvent:
    """Tests for SandboxViolationEvent dataclass."""

    def test_create_event(self):
        """Test creating a violation event."""
        event = SandboxViolationEvent(
            line="Sandbox violation: file-read-data denied",
            command="cat /etc/passwd",
            encoded_command="Y2F0IC9ldGMvcGFzc3dk",
        )
        assert event.line == "Sandbox violation: file-read-data denied"
        assert event.command == "cat /etc/passwd"
        assert event.encoded_command == "Y2F0IC9ldGMvcGFzc3dk"
        assert isinstance(event.timestamp, datetime)

    def test_event_with_defaults(self):
        """Test creating an event with minimal parameters."""
        event = SandboxViolationEvent(line="Some violation")
        assert event.line == "Some violation"
        assert event.command is None
        assert event.encoded_command is None
        assert isinstance(event.timestamp, datetime)

    def test_event_timestamp(self):
        """Test that timestamp is set correctly."""
        before = datetime.now()
        event = SandboxViolationEvent(line="test")
        after = datetime.now()
        assert before <= event.timestamp <= after


class TestSandboxViolationStore:
    """Tests for SandboxViolationStore class."""

    def test_create_store(self):
        """Test creating a violation store."""
        store = SandboxViolationStore()
        assert store.get_count() == 0
        assert store.get_total_count() == 0

    def test_custom_max_size(self):
        """Test creating a store with custom max size."""
        store = SandboxViolationStore(max_size=50)
        assert store.get_count() == 0

    def test_add_violation(self):
        """Test adding a violation."""
        store = SandboxViolationStore()
        event = SandboxViolationEvent(line="test violation")
        store.add_violation(event)

        assert store.get_count() == 1
        assert store.get_total_count() == 1

    def test_add_multiple_violations(self):
        """Test adding multiple violations."""
        store = SandboxViolationStore()
        for i in range(5):
            store.add_violation(SandboxViolationEvent(line=f"violation {i}"))

        assert store.get_count() == 5
        assert store.get_total_count() == 5

    def test_max_size_enforcement(self):
        """Test that max_size is enforced."""
        store = SandboxViolationStore(max_size=3)
        for i in range(10):
            store.add_violation(SandboxViolationEvent(line=f"violation {i}"))

        assert store.get_count() == 3
        assert store.get_total_count() == 10

        # Check that oldest violations are removed
        violations = store.get_violations()
        assert len(violations) == 3
        assert violations[0].line == "violation 7"
        assert violations[1].line == "violation 8"
        assert violations[2].line == "violation 9"

    def test_get_violations(self):
        """Test getting all violations."""
        store = SandboxViolationStore()
        for i in range(3):
            store.add_violation(SandboxViolationEvent(line=f"violation {i}"))

        violations = store.get_violations()
        assert len(violations) == 3
        assert violations[0].line == "violation 0"
        assert violations[2].line == "violation 2"

    def test_get_violations_with_limit(self):
        """Test getting violations with a limit."""
        store = SandboxViolationStore()
        for i in range(10):
            store.add_violation(SandboxViolationEvent(line=f"violation {i}"))

        violations = store.get_violations(limit=3)
        assert len(violations) == 3
        # Should get the last 3 violations
        assert violations[0].line == "violation 7"
        assert violations[1].line == "violation 8"
        assert violations[2].line == "violation 9"

    def test_get_violations_for_command(self):
        """Test getting violations for a specific command."""
        store = SandboxViolationStore()
        command = "cat /etc/passwd"
        encoded = encode_sandboxed_command(command)

        # Add violations for different commands
        store.add_violation(
            SandboxViolationEvent(
                line="violation 1",
                command=command,
                encoded_command=encoded,
            )
        )
        store.add_violation(
            SandboxViolationEvent(
                line="violation 2",
                command="ls -la",
                encoded_command=encode_sandboxed_command("ls -la"),
            )
        )
        store.add_violation(
            SandboxViolationEvent(
                line="violation 3",
                command=command,
                encoded_command=encoded,
            )
        )

        violations = store.get_violations_for_command(command)
        assert len(violations) == 2
        assert violations[0].line == "violation 1"
        assert violations[1].line == "violation 3"

    def test_clear(self):
        """Test clearing violations."""
        store = SandboxViolationStore()
        for i in range(5):
            store.add_violation(SandboxViolationEvent(line=f"violation {i}"))

        assert store.get_count() == 5
        assert store.get_total_count() == 5

        store.clear()

        assert store.get_count() == 0
        # Total count is preserved
        assert store.get_total_count() == 5

    def test_subscribe(self):
        """Test subscribing to violation updates."""
        store = SandboxViolationStore()
        received_violations: list[list[SandboxViolationEvent]] = []

        def listener(violations: list[SandboxViolationEvent]) -> None:
            received_violations.append(list(violations))

        # Subscribe - should immediately receive current violations
        unsubscribe = store.subscribe(listener)
        assert len(received_violations) == 1
        assert len(received_violations[0]) == 0

        # Add violation - should trigger listener
        store.add_violation(SandboxViolationEvent(line="test"))
        assert len(received_violations) == 2
        assert len(received_violations[1]) == 1

        # Unsubscribe
        unsubscribe()

        # Add another violation - should NOT trigger listener
        store.add_violation(SandboxViolationEvent(line="test 2"))
        assert len(received_violations) == 2  # Still 2

    def test_multiple_subscribers(self):
        """Test multiple subscribers."""
        store = SandboxViolationStore()
        received_a: list[int] = []
        received_b: list[int] = []

        def listener_a(violations: list[SandboxViolationEvent]) -> None:
            received_a.append(len(violations))

        def listener_b(violations: list[SandboxViolationEvent]) -> None:
            received_b.append(len(violations))

        store.subscribe(listener_a)
        store.subscribe(listener_b)

        store.add_violation(SandboxViolationEvent(line="test"))

        assert received_a == [0, 1]  # Initial + after add
        assert received_b == [0, 1]

    def test_listener_called_on_clear(self):
        """Test that listeners are called when violations are cleared."""
        store = SandboxViolationStore()
        received_counts: list[int] = []

        def listener(violations: list[SandboxViolationEvent]) -> None:
            received_counts.append(len(violations))

        store.add_violation(SandboxViolationEvent(line="test"))
        store.subscribe(listener)
        store.clear()

        assert received_counts == [1, 0]  # Initial (1 violation), after clear (0)

    def test_get_violations_returns_copy(self):
        """Test that get_violations returns a copy of the list."""
        store = SandboxViolationStore()
        store.add_violation(SandboxViolationEvent(line="test"))

        violations1 = store.get_violations()
        violations2 = store.get_violations()

        # Should be equal but not the same object
        assert violations1 == violations2
        assert violations1 is not violations2
