package devcontainer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnmarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want LifecycleScript
	}{
		{
			name: "command string",
			in:   `"echo hello"`,
			want: LifecycleScript{
				shellCommands: map[string]string{
					"echo hello": "echo hello",
				},
			},
		},
		{
			name: "command array",
			in:   `["echo", "hello"]`,
			want: LifecycleScript{
				nonShellCommands: map[string][]string{
					"echo hello": {"echo", "hello"},
				},
			},
		},
		{
			name: "command map",
			in:   `{"script 1": ["echo", "hello"], "script 2": ["echo", "world"], "script 3": "echo hello world"}`,
			want: LifecycleScript{
				shellCommands: map[string]string{
					"script 3": "echo hello world",
				},
				nonShellCommands: map[string][]string{
					"script 1": {"echo", "hello"},
					"script 2": {"echo", "world"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got LifecycleScript
			if err := json.Unmarshal([]byte(tt.in), &got); err != nil {
				t.Fatal(err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
