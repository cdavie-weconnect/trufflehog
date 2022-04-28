package detectors

import (
	"os"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

func TestIsFalsePositive(t *testing.T) {
	type args struct {
		match          string
		falsePositives []FalsePositive
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "fp",
			args: args{
				match:          "example",
				falsePositives: DefaultFalsePositives,
			},
			want: true,
		},
		{
			name: "not fp",
			args: args{
				match:          "notafp123",
				falsePositives: DefaultFalsePositives,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsKnownFalsePositive(tt.args.match, tt.args.falsePositives, false); got != tt.want {
				t.Errorf("IsKnownFalsePositive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCustomFalsePositivesFilter(t *testing.T) {
	t.Run("UsesFilterNoRulesWhenNoFilename", func(t *testing.T) {
		want := common.FilterNoRules()
		got := GetCustomFalsePositivesFilter()
		if diff := pretty.Compare(got, want); diff != "" {
			t.Errorf("expected FilterNoRules: (-got +want)\n%s", diff)
		}
	})

	t.Run("LoadsFromFilename", func(t *testing.T) {
		filename := "/tmp/trufflehog_test_falsepositives.txt"
		contents := "teststring"
		if err := common.WriteTestFile(filename, []byte(contents)); err != nil {
			t.Fatalf("failed to create test file: %s", err)
		}
		defer os.Remove(filename)

		want := common.FilterFromStrings([]string{`teststring`}, []string{})

		SetCustomFalsePositivesFilename(filename)
		got := GetCustomFalsePositivesFilter()

		if diff := pretty.Compare(got, want); diff != "" {
			t.Errorf("(-got +want)\n%s", diff)
		}
	})

	t.Run("OnlyLoadsFileOnce", func(t *testing.T) {
		filename := "/tmp/trufflehog_test_falsepositives.txt"
		contents := "teststring"
		if err := common.WriteTestFile(filename, []byte(contents)); err != nil {
			t.Fatalf("failed to create test file: %s", err)
		}

		SetCustomFalsePositivesFilename(filename)
		got1 := GetCustomFalsePositivesFilter()

		// It should be safe to delete the file and get the filter again, because
		// the contents should only have been read the first time, then saved.
		os.Remove(filename)
		got2 := GetCustomFalsePositivesFilter()

		if got1 != got2 {
			diff := pretty.Compare(got1, got2)
			t.Errorf("(-got +want)\n%s", diff)
		}
	})
}
