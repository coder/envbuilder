package devcontainer

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

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

func (s *LifecycleScript) Execute(ctx context.Context) error {
	var eg errgroup.Group
	for desc, command := range s.shellCommands {
		desc := desc
		command := command
		eg.Go(func() error {
			if err := exec.CommandContext(ctx, "/bin/sh", "-c", command).Run(); err != nil {
				return fmt.Errorf("lifecycle command %q failed: %v", desc, err)
			}
			return nil
		})
	}

	for desc, command := range s.nonShellCommands {
		desc := desc
		command := command
		eg.Go(func() error {
			if err := exec.CommandContext(ctx, command[0], command[1:]...).Run(); err != nil {
				return fmt.Errorf("lifecycle command %q failed: %v", desc, err)
			}
			return nil
		})
	}

	return eg.Wait()
}
