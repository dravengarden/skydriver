package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestControlCLISeparatesManagementFromFilesystemCommands(t *testing.T) {
	t.Parallel()

	var controlOutput bytes.Buffer
	if err := RunControl(context.Background(), []string{"--help"}, &controlOutput, &controlOutput); err != nil {
		t.Fatalf("render carrackctl help: %v", err)
	}

	for _, command := range []string{"snapshot", "directory", "driver", "token", "acl", "placement"} {
		if !strings.Contains(controlOutput.String(), command) {
			t.Errorf("carrackctl help omitted %q", command)
		}
	}

	for _, command := range []string{"put", "restore", "gc"} {
		if strings.Contains(controlOutput.String(), "  "+command+" ") {
			t.Errorf("carrackctl exposed payload command %q", command)
		}
	}

	var filesystemOutput bytes.Buffer
	if err := Run(context.Background(), []string{"--help"}, &filesystemOutput, &filesystemOutput); err != nil {
		t.Fatalf("render carrack help: %v", err)
	}

	if strings.Contains(filesystemOutput.String(), "  admin ") {
		t.Fatal("carrack still exposed the management command tree")
	}
}
