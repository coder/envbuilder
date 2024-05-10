package devcontainer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sync/errgroup"
)

type LifecycleScript struct {
	shellCommands    map[string]string
	nonShellCommands map[string][]string
}

func (s *LifecycleScript) IsEmpty() bool {
	return len(s.shellCommands) == 0 && len(s.nonShellCommands) == 0
}

func (s *LifecycleScript) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	switch v := v.(type) {
	case string:
		s.shellCommands = map[string]string{
			v: v,
		}
	case []any:
		args, err := argsFromUntypedSlice(v)
		if err != nil {
			return err
		}
		desc := strings.Join(args, " ")
		s.nonShellCommands = map[string][]string{
			desc: args,
		}
	case map[string]any:
		for desc, command := range v {
			switch command := command.(type) {
			case string:
				if s.shellCommands == nil {
					s.shellCommands = make(map[string]string, 1)
				}
				s.shellCommands[desc] = command
			case []any:
				args, err := argsFromUntypedSlice(command)
				if err != nil {
					return err
				}
				if s.nonShellCommands == nil {
					s.nonShellCommands = make(map[string][]string, 1)
				}
				s.nonShellCommands[desc] = args
			}
		}
	}
	return nil
}

func argsFromUntypedSlice(args []any) ([]string, error) {
	if len(args) == 0 {
		return nil, errors.New("empty command array")
	}
	s := make([]string, 0, len(args))
	for _, arg := range args {
		arg, ok := arg.(string)
		if !ok {
			return nil, fmt.Errorf("invalid command arg with non-string type: %v", arg)
		}
		s = append(s, arg)
	}
	return s, nil
}

func (s *LifecycleScript) Execute(ctx context.Context, uid, gid int) error {
	procAttr := &syscall.ProcAttr{
		Env:   os.Environ(),
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Sys: &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(gid),
			},
		},
	}

	var eg errgroup.Group
	for desc, command := range s.shellCommands {
		desc := desc
		command := command
		eg.Go(func() error {
			pid, err := syscall.ForkExec("/bin/sh", []string{"/bin/sh", "-c", command}, procAttr)
			if err != nil {
				return fmt.Errorf("lifecycle command %q failed: %v", desc, err)
			}
			return waitForCommand(desc, pid)
		})
	}

	for desc, commandAndArgs := range s.nonShellCommands {
		desc := desc
		commandAndArgs := commandAndArgs
		eg.Go(func() error {
			path, err := exec.LookPath(commandAndArgs[0])
			if err != nil {
				return err
			}
			pid, err := syscall.ForkExec(path, commandAndArgs, procAttr)
			if err != nil {
				return fmt.Errorf("failed to exec lifecycle command %q: %v", desc, err)
			}
			return waitForCommand(desc, pid)
		})
	}

	return eg.Wait()
}

func waitForCommand(desc string, pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to look up process for lifecycle command %q: %v", desc, err)
	}
	status, err := process.Wait()
	if err != nil {
		return fmt.Errorf("failed to wait for lifecycle command %q: %v", desc, err)
	}
	if exitCode := status.ExitCode(); exitCode != 0 {
		return fmt.Errorf("lifecycle command %q failed with status %d", desc, exitCode)
	}
	return nil
}

// ScriptLines returns shell syntax for executing the commands in the
// LifecycleScript.
//
// TODO: Technically the commands could be executed in parallel, but that would
// add a bit of complexity to do portably.
func (s *LifecycleScript) ScriptLines() string {
	var lines string
	for _, command := range s.shellCommands {
		lines += command + "\n"
	}
	for _, commandAndArgs := range s.nonShellCommands {
		// Quote the command arguments to prevent shell interpretation.
		quotedCommandAndArgs := make([]string, len(commandAndArgs))
		for i := range commandAndArgs {
			// Surround each argument with single quotes. If the
			// argument contains any single quotes, they are escaped
			// by replacing them with the sequence '"'"'. This
			// sequence ends the current single-quoted string,
			// starts and immediately ends a double-quoted string
			// containing a single quote, and then restarts the
			// single-quoted string. This approach works because in
			// shell syntax, adjacent strings are concatenated, so
			// 'arg'"'"'arg' is interpreted as arg'arg.
			quotedCommandAndArgs[i] = "'" + strings.ReplaceAll(commandAndArgs[i], "'", "'\"'\"'") + "'"
		}
		lines += strings.Join(quotedCommandAndArgs, " ") + "\n"
	}
	return lines
}
