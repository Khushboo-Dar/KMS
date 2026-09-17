"""User consent guard for every KMS server request."""


class KmsServerAccessDenied(PermissionError):
    """Raised when the user declines a KMS server operation."""


def require_kms_server_access(host: str, port: int, purpose: str) -> None:
    """Ask for explicit consent before communicating with the KMS server.

    Only ``Yes`` permits the UDP operation. ``No`` cancels it before a socket
    is opened; any other input is asked again so the choice stays unambiguous.
    """
    while True:
        try:
            answer = input(
                "KMS server access is required to "
                f"{purpose} at {host}:{port}. Continue? [Yes/No]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt) as error:
            raise KmsServerAccessDenied(
                "KMS server access was not confirmed."
            ) from error

        if answer == "yes":
            return

        if answer == "no":
            raise KmsServerAccessDenied(
                "KMS server access was declined by the user."
            )

        print("Please answer Yes or No.")
