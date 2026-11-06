package nfc17

import "sort"

// Assigned is frozen Unicode17 repertoire membership, excluding surrogate and
// unassigned code points (including noncharacters), not a printing whitelist.
func Assigned(r rune) bool {
	i := sort.Search(len(assignedRanges), func(i int) bool { return assignedRanges[i][1] >= r })
	return i < len(assignedRanges) && r >= assignedRanges[i][0]
}

// Canonical validates the selected stabilized repertoire before ordinary NFC.
func Canonical(b []byte) ([]byte, error) {
	// Bytes performs strict UTF8 and resource validation before normalization;
	// validate original repertoire first without replacement decoding.
	if len(b) > MaxBytes {
		return nil, ErrInput
	}
	for _, r := range string(b) {
		if !Assigned(r) {
			return nil, ErrInput
		}
	}
	return Bytes(b)
}
