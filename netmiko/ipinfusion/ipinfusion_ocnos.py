import re
import time
from typing import Any, Optional
from socket import socket

from netmiko._telnetlib.telnetlib import (
    IAC,
    DO,
    DONT,
    WILL,
    WONT,
    SB,
    SE,
    TTYPE,
    Telnet,
)
from netmiko.cisco_base_connection import CiscoBaseConnection
from netmiko.exceptions import ConfigLockedException

CONFIG_DATASTORES = ("running", "candidate", "startup")


class IpInfusionOcNOSBase(CiscoBaseConnection):
    """Common Methods for IP Infusion OcNOS support."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if kwargs.get("default_enter") is None:
            kwargs["default_enter"] = "\r"
        super().__init__(**kwargs)

    def session_preparation(self) -> None:
        self._test_channel_read()
        self.set_base_prompt()
        self.disable_paging(command="terminal length 0")
        # Turn off logging for the session as it can spoil analyzing of outputs
        self.send_command("terminal no monitor")
        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    def send_config_set(self, *args: Any, **kwargs: Any) -> str:
        """Send config command(s). Requires separate calling of commit to apply."""

        # Default 'exit_config_mode' to False unless it is explicitly overwritten
        exit_config_mode = kwargs.get("exit_config_mode", False)
        output = super().send_config_set(*args, **kwargs, exit_config_mode=exit_config_mode)
        return output

    def config_mode(
        self,
        config_command: str = "configure terminal",
        pattern: str = "",
        re_flags: int = 0,
        force: bool = False,
    ) -> str:
        """
        Enter configuration mode.

        OcNOS locks the running datastore when 'configure terminal' is entered, so only one
        session can be in config mode at a time. Another session trying to enter gets:

        %% Running configuration store is locked by other client

        That raises ConfigLockedException, which names the session holding the lock.

        force=True releases the lock with 'cml force-unlock config-datastore running', then
        enters config mode, retrying briefly if the device is slow to let go. That preempts the
        other session and DISCARDS its uncommitted transaction. It forces at most once: if
        another session grabs the lock again, ConfigLockedException is raised.
        """
        try:
            return super().config_mode(
                config_command=config_command, pattern=pattern, re_flags=re_flags
            )
        except ValueError as err:
            failure = err
        lock_holder = self.get_config_lock_holder()
        if lock_holder is None:
            # Not a lock problem; report the original failure
            raise failure
        if not force:
            raise ConfigLockedException(
                f"Failed to enter configuration mode: the running datastore is locked by "
                f"another session ({lock_holder}). Use config_mode(force=True) to "
                f"force-unlock it, which discards that session's uncommitted changes.",
                output=str(failure),
                lock_holder=lock_holder,
            ) from failure
        output = self.force_unlock_config()
        # Rarely, 'configure terminal' is refused for a moment after the unlock even though
        # the lock status already reads unlocked, so allow a few short retries. If another
        # session has taken the lock in the meantime, report that rather than force again.
        for attempt in range(1, 4):
            try:
                return output + super().config_mode(
                    config_command=config_command, pattern=pattern, re_flags=re_flags
                )
            except ValueError as err:
                failure = err
            lock_holder = self.get_config_lock_holder()
            if lock_holder is not None:
                raise ConfigLockedException(
                    f"Failed to enter configuration mode after force-unlock: the running "
                    f"datastore was locked again by another session ({lock_holder}).",
                    output=str(failure),
                    lock_holder=lock_holder,
                ) from failure
            if attempt < 3:
                time.sleep(1 * self.global_delay_factor)
        raise failure

    def _exec_command(self, command_string: str, **kwargs: Any) -> str:
        """Run an exec-mode command from either mode; config mode needs a 'do' prefix."""
        if self.check_config_mode():
            command_string = f"do {command_string}"
        return self._send_command_str(command_string, **kwargs)

    def get_config_lock_holder(self, datastore: str = "running") -> Optional[str]:
        """
        Return who holds the lock on a configuration datastore, or None if it is unlocked.

        'show cml config-datastore lock status' names the client and its PID:

         Running datastore is locked by client cmlsh(67219)

        When that PID is a CLI session, its row from 'show users' is appended (user, line,
        idle time, location).
        """
        if datastore not in CONFIG_DATASTORES:
            raise ValueError(f"Invalid datastore {datastore!r}; use one of {CONFIG_DATASTORES}")
        output = self._exec_command("show cml config-datastore lock status")
        match = re.search(
            rf"{datastore} datastore is locked by client (\S+)", output, flags=re.IGNORECASE
        )
        if not match:
            return None
        holder = match.group(1)
        pid = re.search(r"\((\d+)\)", holder)
        if pid:
            users = self._exec_command("show users")
            for line in users.splitlines():
                if re.search(rf"\s{pid.group(1)}\s", f" {line} "):
                    holder += f" [{' '.join(line.split())}]"
                    break
        return holder

    def force_unlock_config(self, datastore: str = "running") -> str:
        """
        Forcibly release the lock on a configuration datastore.

        The session holding it is preempted and its uncommitted transaction is discarded.
        Releasing a datastore that is already unlocked is not an error.
        """
        if datastore not in CONFIG_DATASTORES:
            raise ValueError(f"Invalid datastore {datastore!r}; use one of {CONFIG_DATASTORES}")
        # Success prints nothing; the only expected message is 'already unlocked'
        output = self._exec_command(
            f"cml force-unlock config-datastore {datastore}",
            strip_prompt=False,
            strip_command=False,
        )
        if "already unlocked" in output:
            return output
        lock_holder = self.get_config_lock_holder(datastore=datastore)
        if lock_holder is not None:
            raise ValueError(
                f"Failed to force-unlock the {datastore} datastore; it is still locked by "
                f"{lock_holder}. Device response:\n\n{output}"
            )
        return output

    def commit(
        self,
        confirm: bool = False,
        confirm_delay: Optional[int] = None,
        comment: str = "",
        read_timeout: float = 120.0,
    ) -> str:
        """
        Commit the candidate configuration.

        default (no options):
            command_string = commit
        confirm and confirm_delay:
            command_string = commit confirmed timeout <confirm_delay>
        comment (mapped to 'description' on device):
            command_string = commit description <comment>

        failed commit message example:
        % Failed to commit .. As error(s) encountered during commit operation...
        Uncommitted configurations are retained in the current transaction session,
        check 'show transaction current'.
        Correct the reason for the failure and re-issue the commit.
        Use 'abort transaction' to terminate current transaction session and discard
        all uncommitted changes.
        """

        if confirm_delay and not confirm:
            raise ValueError(
                "Invalid arguments supplied to commit: confirm_delay specified without confirm"
            )

        error_marker = "Failed to commit"

        # Build proper command string based on arguments provided
        command_string = "commit"
        if confirm:
            command_string += " confirmed"
            if confirm_delay:
                command_string += f" timeout {str(confirm_delay)}"
        if comment:
            command_string += f" description {comment}"

        # Enter config mode (if necessary)
        output = self.config_mode()

        new_data = self._send_command_str(
            command_string,
            expect_string=r"#",
            strip_prompt=False,
            strip_command=False,
            read_timeout=read_timeout,
        )
        output += new_data
        if error_marker in output:
            raise ValueError(f"Commit failed with the following errors:\n\n{output}")

        return output

    def _confirm_commit(self, read_timeout: float = 120.0) -> str:
        """Confirm the commit that was previously issued with 'commit confirmed' command"""

        # Enter config mode (if necessary)
        output = self.config_mode()

        command_string = "confirm-commit"
        # If output is empty, it worked, an error looks like this:
        # Error: No confirm-commit in progress OR commit-history feature is Disabled
        new_data = self._send_command_str(
            command_string,
            expect_string=r"(#|Error)",
            strip_prompt=False,
            strip_command=False,
            read_timeout=read_timeout,
        )
        output += new_data
        if "Error" in new_data:
            raise ValueError(
                f"Confirm commit operation failed with the following errors:\n\n{output}"
            )

        return output

    def _cancel_commit(self, read_timeout: float = 120.0) -> str:
        """Cancel ongoing confirmed commit"""

        # Enter config mode (if necessary)
        output = self.config_mode()

        command_string = "cancel-commit"
        # If output is empty, cancel-commit worked, an error looks like this:
        # Error: No confirm-commit in progress OR commit-history feature is Disabled
        new_data = self._send_command_str(
            command_string,
            expect_string=r"(#|Error)",
            strip_prompt=False,
            strip_command=False,
            read_timeout=read_timeout,
        )
        output += new_data
        if "Error" in new_data:
            raise ValueError(
                f"Cancel commit operation failed with the following errors:\n\n{output}"
            )

        return output

    def _abort_transaction(self, read_timeout: float = 120.0) -> str:
        """Abort transaction, thus cancelling the pending changes rather than committing them"""

        if not self.check_config_mode():
            raise ValueError("Device is not in config mode")
        command_string = "abort transaction"
        # If output is empty, it worked; this is usually so (note: if
        # transaction is empty, it still works)
        output = self._send_command_str(
            command_string,
            expect_string=r"#",
            strip_prompt=False,
            strip_command=False,
            read_timeout=read_timeout,
        )
        return output

    def save_config(
        self, cmd: str = "write", confirm: bool = False, confirm_response: str = ""
    ) -> str:
        """Saves config using 'write' command"""
        return super().save_config(cmd=cmd, confirm=confirm, confirm_response=confirm_response)


class IpInfusionOcNOSSSH(IpInfusionOcNOSBase):
    """IP Infusion OcNOS SSH driver."""

    pass


class IpInfusionOcNOSTelnet(IpInfusionOcNOSBase):
    """IP Infusion OcNOS  Telnet driver."""

    def _process_option(self, tsocket: socket, command: bytes, option: bytes) -> None:
        """
        For all telnet options, re-implement the default telnetlib behaviour
        and refuse to handle any options. If the server expresses interest in
        'terminal type' option, then reply back with 'xterm' terminal type.
        """
        if command == DO and option == TTYPE:
            tsocket.sendall(IAC + WILL + TTYPE)
            tsocket.sendall(IAC + SB + TTYPE + b"\0" + b"xterm" + IAC + SE)
        elif command in (DO, DONT):
            tsocket.sendall(IAC + WONT + option)
        elif command in (WILL, WONT):
            tsocket.sendall(IAC + DONT + option)

    def telnet_login(
        self,
        pri_prompt_terminator: str = "#",
        alt_prompt_terminator: str = ">",
        username_pattern: str = r"(?:user:|sername|login|user name)",
        pwd_pattern: str = r"assword:",
        delay_factor: float = 1.0,
        max_loops: int = 20,
    ) -> str:
        # set callback function to handle telnet options.
        assert self.remote_conn is not None
        assert isinstance(self.remote_conn, Telnet)
        self.remote_conn.set_option_negotiation_callback(self._process_option)  # type: ignore
        return super().telnet_login(
            pri_prompt_terminator=pri_prompt_terminator,
            alt_prompt_terminator=alt_prompt_terminator,
            username_pattern=username_pattern,
            pwd_pattern=pwd_pattern,
            delay_factor=delay_factor,
            max_loops=max_loops,
        )
