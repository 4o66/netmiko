from typing import Optional

from paramiko.ssh_exception import SSHException
from paramiko.ssh_exception import AuthenticationException


class NetmikoBaseException(Exception):
    """General base exception except for exceptions that inherit from Paramiko."""

    pass


class ConnectionException(NetmikoBaseException):
    """Generic exception indicating the connection failed."""

    pass


class NetmikoTimeoutException(SSHException):
    """SSH session timed trying to connect to the device."""

    pass


NetMikoTimeoutException = NetmikoTimeoutException


class NetmikoAuthenticationException(AuthenticationException):
    """SSH authentication exception based on Paramiko AuthenticationException."""

    pass


NetMikoAuthenticationException = NetmikoAuthenticationException


class ConfigInvalidException(NetmikoBaseException):
    """Exception raised for invalid configuration error."""

    pass


class ConfigLockedException(NetmikoBaseException, ValueError):
    """Config mode refused because another session holds the configuration lock.

    Also a ValueError, so code that catches the generic config_mode() failure keeps working.
    """

    def __init__(self, message: str, output: str = "", lock_holder: Optional[str] = None) -> None:
        super().__init__(message)
        self.output = output
        self.lock_holder = lock_holder


class WriteException(NetmikoBaseException):
    """General exception indicating an error occurred during a Netmiko write operation."""

    pass


class ReadException(NetmikoBaseException):
    """General exception indicating an error occurred during a Netmiko read operation."""

    pass


class ReadTimeout(ReadException):
    """General exception indicating an error occurred during a Netmiko read operation."""

    pass


class NetmikoParsingException(ReadException):
    """Exception raised when there is a parsing error."""

    pass
