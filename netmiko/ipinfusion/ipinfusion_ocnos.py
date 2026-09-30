import re
import time
from typing import Any, Dict, List, Optional, Union
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
        force: Union[bool, str] = False,
    ) -> str:
        """
        Enter configuration mode.

        OcNOS locks the running datastore when 'configure terminal' is entered, so only one
        session can be in config mode at a time. Another session trying to enter gets:

        %% Running configuration store is locked by other client

        That raises ConfigLockedException, which names the session holding the lock.

        force="stale" force-unlocks only when the holder is confirmed to be a dead session of
        our own: same username, same source IP as the device sees it, and a TCP connection
        that has stopped acknowledging data. That is the usual aftermath of a dropped
        connection: the device keeps the old session, and its lock, until TCP gives up on it.
        A live session of the same user, e.g. a concurrent job, is never preempted this way.

        force=True releases the lock with 'cml force-unlock config-datastore running', then
        enters config mode, retrying briefly if the device is slow to let go. That preempts the
        other session and DISCARDS its uncommitted transaction. It forces at most once: if
        another session grabs the lock again, ConfigLockedException is raised.
        """
        if force not in (False, True, "stale"):
            raise ValueError(f"Invalid force={force!r}; use False, True or 'stale'")
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
        if force == "stale":
            verdict = self._holder_is_own_dead_session(config_command, lock_holder)
            if verdict == "entered":
                # The lock went away while we probed, and the probe got us in
                return ""
            if verdict != "dead":
                raise ConfigLockedException(
                    f"Failed to enter configuration mode: the running datastore is locked by "
                    f"another session ({lock_holder}), which is not confirmed to be a dead "
                    f"session of ours, so it was left alone. Use config_mode(force=True) to "
                    f"force-unlock it anyway.",
                    output=str(failure),
                    lock_holder=lock_holder,
                ) from failure
        elif not force:
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
        """
        Run an exec-mode command from either mode.

        Config mode rejects exec commands without a 'do' prefix, so retry with one on
        "Invalid input". Cheaper than check_config_mode() up front, which costs seconds.
        """
        output = self._send_command_str(command_string, **kwargs)
        if "Invalid input" in output:
            output = self._send_command_str(f"do {command_string}", **kwargs)
        return output

    def _sshd_connections(self) -> List[Dict[str, Any]]:
        """Established SSH connections as the device sees them, with each one's send queue."""
        conns: List[Dict[str, Any]] = []
        # SSH normally runs in the management VRF; look in the default VRF only if it is not there
        for cmd in ("show tcp ipv4 vrf management", "show tcp ipv4"):
            if conns:
                break
            for line in self._exec_command(f"{cmd} | include sshd").splitlines():
                match = re.search(
                    r"^tcp6?\s+\d+\s+(\d+)\s+\S+:22\s+(\S+):(\d+)\s+ESTABLISHED\s+(\d+)/sshd:\s*(\S+)",
                    line.strip(),
                )
                if match:
                    conns.append(
                        {
                            "send_q": int(match.group(1)),
                            "peer": (match.group(2), int(match.group(3))),
                            "sshd_pid": int(match.group(4)),
                            "user": match.group(5),
                        }
                    )
        return conns

    def _cli_session_pids(self) -> List[int]:
        """PIDs of the CLI sessions (cmlsh) listed in 'show users'."""
        pids = []
        for line in self._exec_command("show users").splitlines():
            match = re.search(r"\[\w\]\S+\s+\d+d\d+h\d+m\s+\S+\s+(\d+)\s", line)
            if match:
                pids.append(int(match.group(1)))
        return pids

    @staticmethod
    def _cli_pid_for_sshd(
        sshd_pid: int, sshd_pids: List[int], cli_pids: List[int]
    ) -> Optional[int]:
        """
        The CLI session an SSH connection belongs to, or None if that cannot be told.

        OcNOS shows no parent PIDs, but each login's sshd process is started just before its
        cmlsh, so a connection's session is the first cmlsh PID after its sshd PID, provided
        no other login's sshd started in between (interleaved logins are ambiguous).
        """
        later = [pid for pid in cli_pids if pid > sshd_pid]
        if not later:
            return None
        cli_pid = min(later)
        if any(sshd_pid < other < cli_pid for other in sshd_pids if other != sshd_pid):
            return None
        return cli_pid

    def _holder_is_own_dead_session(self, config_command: str, lock_holder: str) -> str:
        """
        Is the lock holder our own user, from our IP, and no longer acknowledging?

        Returns "dead" if so, "alive" if not (or if it cannot be confirmed), and "entered"
        if the lock was released meanwhile and the probe itself got us into config mode.

        Each refused 'configure terminal' makes OcNOS push "Another user attempted to acquire
        lock" to the holder. A live holder acknowledges it within milliseconds; a dead one
        (lost connection) never does, so its TCP send queue grows with every attempt. Knock
        once more between two snapshots, then confirm that the one connection whose queue
        grew belongs to the lock holder's CLI session. Anything uncertain counts as alive.
        """
        username = self.username or ""
        # lock_holder carries the holder's 'show users' row, e.g. "... vty 1 [C]ocnos ..."
        holder_user = re.search(r"\[\w\](\S+)", lock_holder)
        if not username or not holder_user or holder_user.group(1) != username:
            return "alive"

        def mine(conn: Dict[str, Any]) -> bool:
            # The process name is truncated in 'show tcp', so compare by prefix
            return bool(conn["user"]) and username.startswith(conn["user"])

        before = {c["peer"]: c["send_q"] for c in self._sshd_connections() if mine(c)}
        knock = self._send_command_str(config_command, expect_string=r"#")  # second knock
        if "locked by other client" not in knock:
            if re.search(r"\(config[^)]*\)#", knock):
                return "entered"  # the lock was released meanwhile
            return "alive"
        time.sleep(1 * self.global_delay_factor)
        after = [c for c in self._sshd_connections() if mine(c)]
        grown = [c for c in after if c["send_q"] > before.get(c["peer"], 0)]
        if len(grown) != 1:
            return "alive"
        ghost = grown[0]
        # The queue that grew must belong to the lock holder itself. A dead session that is
        # not the holder (e.g. one preempted earlier) can also be written to at any moment.
        holder_pid = re.search(r"\((\d+)\)", lock_holder)
        all_sshd = [c["sshd_pid"] for c in self._sshd_connections()]
        ghost_cli = self._cli_pid_for_sshd(ghost["sshd_pid"], all_sshd, self._cli_session_pids())
        if not holder_pid or ghost_cli != int(holder_pid.group(1)):
            return "alive"
        # Same IP: every other live connection of this user (ours among them) shares the
        # ghost's source IP. With sessions from more than one IP, 'ours' cannot be confirmed.
        live_ips = {c["peer"][0] for c in after if c is not ghost}
        return "dead" if live_ips == {ghost["peer"][0]} else "alive"

    def _lock_client(self, datastore: str = "running") -> Optional[str]:
        """The client holding a datastore lock, e.g. 'cmlsh(67219)', or None if unlocked."""
        if datastore not in CONFIG_DATASTORES:
            raise ValueError(f"Invalid datastore {datastore!r}; use one of {CONFIG_DATASTORES}")
        output = self._exec_command("show cml config-datastore lock status")
        match = re.search(
            rf"{datastore} datastore is locked by client (\S+)", output, flags=re.IGNORECASE
        )
        return match.group(1) if match else None

    def get_config_lock_holder(self, datastore: str = "running") -> Optional[str]:
        """
        Return who holds the lock on a configuration datastore, or None if it is unlocked.

        'show cml config-datastore lock status' names the client and its PID:

         Running datastore is locked by client cmlsh(67219)

        When that PID is a CLI session, its row from 'show users' is appended (user, line,
        idle time, location).
        """
        holder = self._lock_client(datastore)
        if holder is None:
            return None
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
        lock_client = self._lock_client(datastore=datastore)
        if lock_client is not None:
            raise ValueError(
                f"Failed to force-unlock the {datastore} datastore; it is still locked by "
                f"{self.get_config_lock_holder(datastore=datastore) or lock_client}. "
                f"Device response:\n\n{output}"
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
