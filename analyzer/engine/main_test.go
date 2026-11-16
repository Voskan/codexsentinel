package engine

import (
	"os"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func TestMain(m *testing.M) { os.Exit(testutil.RunIsolated(m)) }
