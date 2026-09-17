"""User consent guard for every Oracle database connection."""


class DatabaseAccessDenied(PermissionError):
    """Raised when the user declines a database operation."""


def require_database_access(purpose: str) -> None:
    """Ask for explicit consent before opening a database connection.

    Only ``Yes`` opens the connection. ``No`` (or unavailable interactive
    input) blocks it. Invalid answers are asked again so the user always gets
    an unambiguous Yes/No choice before an Oracle connection is attempted.
    """
    while True:
        try:
            answer = input(
                f"Database access is required to {purpose}. Continue? [Yes/No]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt) as error:
            raise DatabaseAccessDenied(
                "Database access was not confirmed."
            ) from error

        if answer == "yes":
            return

        if answer == "no":
            raise DatabaseAccessDenied(
                "Database access was declined by the user."
            )

        print("Please answer Yes or No.")
