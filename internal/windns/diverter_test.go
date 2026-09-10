package windns

import (
	"path/filepath"
	"testing"
)

func TestDiverterCreation(t *testing.T) {
	dllDir, _ := filepath.Abs("../../tools/zapret-winws")
	d, err := New(dllDir, "")
	if err != nil {
		t.Fatalf("failed to create diverter: %v", err)
	}
	if d == nil {
		t.Fatal("diverter is nil")
	}
	t.Logf("Diverter created successfully!")
}
