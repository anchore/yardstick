//go:build unix

package research

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// stopProcessGroup runs the command in its own process group and makes cancelling it signal the
// whole group, so whatever sh starts stops with it.
func stopProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}

// survivingGroup returns the command's process group if anything in it is still alive after the
// command exited, giving members a moment to exit after the signal. A group signal succeeds when it
// reaches any one member, so its error can't tell; probing the group can: ESRCH means it's gone, and
// nil or EPERM (a sandbox may refuse to signal grandchildren at all) means something survived.
func survivingGroup(cmd *exec.Cmd) int {
	if cmd.Process == nil {
		return 0
	}
	pgid := cmd.Process.Pid // Setpgid makes the group's ID the command's pid
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) {
			return 0
		}
		if time.Now().After(deadline) {
			return pgid
		}
	}
}
