package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pivotaltracker"
)

func TestCustomFalsePositives(t *testing.T) {
	dir := "/tmp/trufflehog_test_engine"
	filename := filepath.Join(dir, "test_falsepositives.txt")
	contents := "12345678901234567890123456789012"
	if err := common.WriteTestFile(filename, []byte(contents)); err != nil {
		t.Fatalf("failed to create test file: %s", err)
	}
	defer os.Remove(filename)

	log.SetLevel(logrus.DebugLevel) // DELETE

	ctx := context.TODO()
	e := Start(ctx, WithDetectors(true, pivotaltracker.Scanner{}))
	t.Errorf("***** TEST, results A") // DELETE
	e.ScanFileSystem(ctx, []string{dir})
	t.Errorf("***** TEST, results B") // DELETE
}
