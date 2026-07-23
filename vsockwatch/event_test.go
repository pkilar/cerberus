package vsockwatch

import "testing"

func TestVerdict_Blockworthy(t *testing.T) {
	tests := []struct {
		v    Verdict
		want bool
	}{
		{Expected, false},
		{Anomalous, true},
		{Indeterminate, false}, // see Blockworthy's doc comment: never block on an unresolvable allowlist
	}
	for _, tt := range tests {
		if got := tt.v.Blockworthy(); got != tt.want {
			t.Errorf("%v.Blockworthy() = %v, want %v", tt.v, got, tt.want)
		}
	}
}
