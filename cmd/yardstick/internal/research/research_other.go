//go:build !unix

package research

import "os/exec"

// stopProcessGroup leaves the default: cancelling kills only the command itself.
func stopProcessGroup(*exec.Cmd) {}

// survivingGroup can't tell on this platform.
func survivingGroup(*exec.Cmd) int { return 0 }
