package agentsdk

import (
	"strings"

	"golang.org/x/xerrors"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/coder/envbuilder/internal/codervendor/agent/proto"
)

func ProtoFromLog(log Log) (*proto.Log, error) {
	lvl, ok := proto.Log_Level_value[strings.ToUpper(string(log.Level))]
	if !ok {
		return nil, xerrors.Errorf("unknown log level: %s", log.Level)
	}
	return &proto.Log{
		CreatedAt: timestamppb.New(log.CreatedAt),
		Output:    strings.ToValidUTF8(log.Output, "❌"),
		Level:     proto.Log_Level(lvl),
	}, nil
}
