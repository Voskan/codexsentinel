package analyzer_test

import (
	"os"
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer/testutil"
)

func TestMain(m *testing.M) { os.Exit(testutil.RunIsolated(m)) }
