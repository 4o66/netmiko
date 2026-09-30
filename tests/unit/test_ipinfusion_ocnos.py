#!/usr/bin/env python
"""OcNOS config-lock handling, against a fake device modeled on OcNOS-SP 6.6.1 output."""

from threading import Lock

import pytest

from netmiko import ConfigLockedException
from netmiko.ipinfusion.ipinfusion_ocnos import IpInfusionOcNOSBase

LOCKED_REPLY = (
    "configure terminal\n\n"
    "Error description : %% Running configuration store is locked by other client \nOcNOS#"
)
STATUS_UNLOCKED = """
 Running datastore is unlocked
 Candidate datastore is unlocked
 Startup datastore is unlocked
"""
STATUS_LOCKED = """
 Running datastore is locked by client cmlsh(67219)
 Candidate datastore is unlocked
 Startup datastore is unlocked
"""
SHOW_USERS = """Current user          : (*).  Lock acquired by user : (#).
CLI user              : [C].  Netconf users         : [N].

              Line        User          Idle         Location/Session  PID     TYPE   Role
          129 vty 0    [C]ocnos       0d00h09m     pts/0             67109   Local  network-admin
(#)       130 vty 1    [C]ocnos       0d00h04m     pts/1             67219   Local  network-admin
   (*)    131 vty 2    [C]ocnos       0d00h00m     pts/2             67240   Local  network-admin
"""


class FakeOcNOS(IpInfusionOcNOSBase):
    """Just enough of a device: one running-datastore lock, held by another session or not."""

    def __init__(self, locked=False, unlock_works=True, other_failure=False, refuse_after_unlock=0):
        self._session_locker = Lock()
        self.global_delay_factor = 0.0
        self.refuse_after_unlock = refuse_after_unlock
        self.relock_by_other = False
        self.username = "ocnos"
        self.holder_user = "ocnos"
        self.holder_dead = True
        self.holder_ip = "70.98.52.34"
        self.old_dead_ghost = False
        self.old_ghost_grows = False
        self.knocks = 0
        self.global_cmd_verify = False
        self.RETURN = "\n"
        self.locked = locked
        self.unlock_works = unlock_works
        self.other_failure = other_failure
        self.in_config = False
        self.sent = []

    def tcp_rows(self):
        """(send_q, peer_ip, peer_port, sshd_pid, user) for each established SSH session."""
        holder_q = 96 * (1 + self.knocks) if self.holder_dead else 0
        rows = [
            (holder_q, self.holder_ip, 41206, 67200, self.holder_user),
            (0, "70.98.52.34", 35602, 67230, "ocnos"),  # our own session
        ]
        if self.old_dead_ghost:  # dead, but not the lock holder
            # Normally gets no new data; old_ghost_grows models a stray write (e.g. an
            # idle-logout warning) landing between the two snapshots
            rows.append(
                (
                    96 + (self.knocks * 150 if self.old_ghost_grows else 0),
                    "70.98.52.34",
                    40000,
                    67100,
                    "ocnos",
                )
            )
        return rows

    def check_config_mode(self, *args, **kwargs):
        return self.in_config

    def write_channel(self, out_data):
        self.sent.append(out_data.strip())

    def read_until_pattern(self, *args, **kwargs):
        return ""

    def read_until_prompt(self, *args, **kwargs):
        if self.other_failure:
            return "configure terminal\n% Permission denied\nOcNOS#"
        if self.locked:
            return LOCKED_REPLY
        if self.refuse_after_unlock:
            # Status already reads unlocked, but entry is still refused for a moment
            self.refuse_after_unlock -= 1
            if self.relock_by_other:
                self.locked = True
            return LOCKED_REPLY
        self.in_config = True
        return "configure terminal\nEnter configuration commands, one per line.\nOcNOS(config)#"

    def _send_command_str(self, command_string, **kwargs):
        self.sent.append(command_string)
        # Like OcNOS, exec commands need a 'do' prefix in config mode
        if self.in_config:
            if not command_string.startswith("do "):
                return "% Invalid input detected at '^' marker.\n"
            command_string = command_string[3:]
        if command_string == "show cml config-datastore lock status":
            return STATUS_LOCKED if self.locked else STATUS_UNLOCKED
        if command_string == "show users":
            return (
                SHOW_USERS
                if self.holder_user == "ocnos"
                else SHOW_USERS.replace(
                    "(#)       130 vty 1    [C]ocnos", "(#)       130 vty 1    [C]alice"
                )
            )
        if command_string.startswith("show tcp ipv4"):
            if "vrf management" not in command_string:
                return ""
            return "\n".join(
                f"tcp        0 {q:>6} 10.70.1.171:22          {ip}:{port}     ESTABLISHED "
                f"{pid}/sshd: {user} [ "
                for (q, ip, port, pid, user) in self.tcp_rows()
            )
        if command_string == "configure terminal":
            # Second knock: a dead holder never acks the lock notice, so its queue grows
            self.knocks += 1
            return LOCKED_REPLY
        if command_string.startswith("cml force-unlock config-datastore"):
            if not self.locked:
                return f"{command_string}\n%% Running configuration store is already unlocked \n"
            if self.unlock_works:
                self.locked = False
            return f"{command_string}\n"
        raise AssertionError(f"unexpected command {command_string!r}")


def test_config_mode_unlocked():
    conn = FakeOcNOS()
    conn.config_mode()
    assert conn.in_config
    assert not any("force-unlock" in c for c in conn.sent)


def test_config_mode_locked_raises_config_locked():
    conn = FakeOcNOS(locked=True)
    with pytest.raises(ConfigLockedException) as exc:
        conn.config_mode()
    assert exc.value.lock_holder.startswith("cmlsh(67219)")
    assert "vty 1" in exc.value.lock_holder
    assert "locked by other client" in exc.value.output
    assert not conn.in_config
    # Never forces unless asked
    assert not any("force-unlock" in c for c in conn.sent)


def test_config_locked_is_still_a_value_error():
    conn = FakeOcNOS(locked=True)
    with pytest.raises(ValueError):
        conn.config_mode()


def test_config_mode_force_unlocks_and_enters():
    conn = FakeOcNOS(locked=True)
    conn.config_mode(force=True)
    assert conn.in_config
    assert "cml force-unlock config-datastore running" in conn.sent


def test_config_mode_force_fails_if_lock_survives():
    conn = FakeOcNOS(locked=True, unlock_works=False)
    with pytest.raises(ValueError, match="still locked by cmlsh"):
        conn.config_mode(force=True)
    assert not conn.in_config


def test_config_mode_other_failure_is_not_a_lock_error():
    conn = FakeOcNOS(other_failure=True)
    with pytest.raises(ValueError) as exc:
        conn.config_mode(force=True)
    assert not isinstance(exc.value, ConfigLockedException)
    assert not any("force-unlock" in c for c in conn.sent)


def test_get_config_lock_holder():
    assert FakeOcNOS().get_config_lock_holder() is None
    assert FakeOcNOS(locked=True).get_config_lock_holder().startswith("cmlsh(67219) [(#) 130")
    assert FakeOcNOS(locked=True).get_config_lock_holder(datastore="candidate") is None


def test_force_unlock_when_already_unlocked():
    assert "already unlocked" in FakeOcNOS().force_unlock_config()


def test_invalid_datastore():
    with pytest.raises(ValueError, match="Invalid datastore"):
        FakeOcNOS().force_unlock_config(datastore="bogus")


def test_get_config_lock_holder_from_config_mode():
    """Our own session holds the lock once it is in config mode."""
    conn = FakeOcNOS()
    conn.config_mode()
    conn.locked = True
    assert conn.get_config_lock_holder().startswith("cmlsh(67219)")
    # Tried plainly first, then with 'do' after "Invalid input"
    assert "do show cml config-datastore lock status" in conn.sent
    assert "do show users" in conn.sent


def test_config_mode_force_retries_brief_refusal_after_unlock():
    conn = FakeOcNOS(locked=True, refuse_after_unlock=2)
    conn.config_mode(force=True)
    assert conn.in_config
    assert sum(c == "configure terminal" for c in conn.sent) == 4  # 1 + 1 refused + 2 retries


def test_config_mode_force_gives_up_after_three_refusals():
    conn = FakeOcNOS(locked=True, refuse_after_unlock=5)
    with pytest.raises(ValueError) as exc:
        conn.config_mode(force=True)
    assert not isinstance(exc.value, ConfigLockedException)
    assert sum("force-unlock" in c for c in conn.sent) == 1  # never forces twice


def test_config_mode_force_reports_relock_by_another_session():
    conn = FakeOcNOS(locked=True, refuse_after_unlock=1)
    conn.relock_by_other = True
    with pytest.raises(ConfigLockedException, match="locked again"):
        conn.config_mode(force=True)
    assert sum("force-unlock" in c for c in conn.sent) == 1


def test_force_stale_reclaims_own_dead_session():
    conn = FakeOcNOS(locked=True)
    conn.config_mode(force="stale")
    assert conn.in_config
    assert "cml force-unlock config-datastore running" in conn.sent


@pytest.mark.parametrize(
    "setup, why",
    [
        (lambda c: setattr(c, "holder_dead", False), "holder is alive (acks its notices)"),
        (lambda c: setattr(c, "holder_user", "alice"), "holder is a different user"),
        (lambda c: setattr(c, "holder_ip", "203.0.113.9"), "holder is from another IP"),
    ],
)
def test_force_stale_leaves_other_sessions_alone(setup, why):
    conn = FakeOcNOS(locked=True)
    setup(conn)
    with pytest.raises(ConfigLockedException, match="not confirmed"):
        conn.config_mode(force="stale")
    assert not any("force-unlock" in c for c in conn.sent), why


def test_force_stale_not_fooled_by_an_old_ghost_that_is_not_the_holder():
    """A dead non-holder already has a queue, but only the holder's grows on the knock."""
    conn = FakeOcNOS(locked=True)
    conn.old_dead_ghost = True
    conn.config_mode(force="stale")
    assert conn.in_config  # holder is dead and ours, the old ghost did not confuse it
    conn2 = FakeOcNOS(locked=True)
    conn2.old_dead_ghost = True
    conn2.holder_dead = False
    with pytest.raises(ConfigLockedException):
        conn2.config_mode(force="stale")


def test_force_invalid_value():
    with pytest.raises(ValueError, match="Invalid force"):
        FakeOcNOS(locked=True).config_mode(force="yes")
    with pytest.raises(ValueError, match="Invalid force"):
        FakeOcNOS().config_mode(force="yes")  # rejected even when nothing is locked


def test_force_stale_not_fooled_when_a_non_holder_ghost_is_written_to():
    """Found live: a preempted ghost's queue grew between snapshots; the holder was alive."""
    conn = FakeOcNOS(locked=True)
    conn.old_dead_ghost = True
    conn.old_ghost_grows = True
    conn.holder_dead = False
    with pytest.raises(ConfigLockedException, match="not confirmed"):
        conn.config_mode(force="stale")
    assert not any("force-unlock" in c for c in conn.sent)


@pytest.mark.parametrize(
    "sshd, sshds, clis, expected",
    [
        (67200, [67200, 67230], [67219, 67240], 67219),  # normal
        (67230, [67200, 67230], [67219, 67240], 67240),
        (67200, [67200, 67210], [67219, 67240], None),  # another login interleaved
        (67300, [67300], [67219, 67240], None),  # no session after it
    ],
)
def test_cli_pid_for_sshd(sshd, sshds, clis, expected):
    assert IpInfusionOcNOSBase._cli_pid_for_sshd(sshd, sshds, clis) == expected
