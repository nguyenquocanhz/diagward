package disk

import "testing"

// The SSD wear counter reads "hao mòn" in Vietnamese: "đã dùng 85%" next
// to the size column reads as "85% full".
func TestCounterCells(t *testing.T) {
	if got := usedCell(85); got.EN != "used 85%" || got.VI != "hao mòn 85%" {
		t.Errorf("usedCell = %+v", got)
	}
	if got := countCell("realloc", "sector đã thay", 4080); got.EN != "realloc 4,080" || got.VI != "sector đã thay 4.080" {
		t.Errorf("countCell = %+v", got)
	}
}
