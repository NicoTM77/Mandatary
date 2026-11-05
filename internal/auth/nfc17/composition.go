// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nfc17

import "unicode/utf8"

const (
	maxNonStarters = 2048
	// Whole-input canonical decomposition is at most 2048 scalars. Retain two
	// spare upstream slots; neither is used for synthesized stream-safe CGJ.
	maxBufferSize     = maxNonStarters + 2
	maxByteBufferSize = utf8.UTFMax * maxBufferSize
)

// ssState is used for reporting the segment state after inserting a rune.
// It is returned by streamSafe.next.
type ssState int

const (
	// Indicates a rune was successfully added to the segment.
	ssSuccess ssState = iota
	// Indicates a rune starts a new segment and should not be added.
	ssStarter
	// Indicates an invariant/resource failure; callers return no partial output.
	ssOverflow
)

// streamSafe retains upstream segment accounting, widened above the proven
// admitted-input bound. Overflow fails closed rather than inserting CGJ.
type streamSafe int

// insert returns a ssState value to indicate whether a rune represented by p
// can be inserted.
func (ss *streamSafe) next(p Properties) ssState {
	if *ss > maxNonStarters {
		return ssOverflow
	}
	n := p.nLeadingNonStarters()
	if *ss += streamSafe(n); *ss > maxNonStarters {
		*ss = 0
		return ssOverflow
	}
	// The Stream-Safe Text Processing prescribes that the counting can stop
	// as soon as a starter is encountered. However, there are some starters,
	// like Jamo V and T, that can combine with other runes, leaving their
	// successive non-starters appended to the previous, possibly causing an
	// overflow. We will therefore consider any rune with a non-zero nLead to
	// be a non-starter. Note that it always hold that if nLead > 0 then
	// nLead == nTrail.
	if n == 0 {
		*ss = streamSafe(p.nTrailingNonStarters())
		return ssStarter
	}
	return ssSuccess
}

// reorderBuffer is used to normalize a single segment.  Characters inserted with
// insert are decomposed and reordered based on CCC. The compose method can
// be used to recombine characters.  Note that the byte buffer does not hold
// the UTF-8 characters in order.  Only the rune array is maintained in sorted
// order. flush writes the resulting segment to a byte array.
type reorderBuffer struct {
	rune  [maxBufferSize]Properties // Per character info.
	byte  [maxByteBufferSize]byte   // UTF-8 buffer. Referenced by runeInfo.pos.
	nbyte int                       // Number or bytes.
	ss    streamSafe                // For limiting length of non-starter sequence.
	nrune int                       // Number of runeInfos.
	f     formInfo

	src      input
	nsrc     int
	tmpBytes input

	out                           []byte
	flushF                        func(*reorderBuffer) bool
	err                           bool
	slots, bytes, output, counter int
}

// reset discards all characters from the buffer.
func (rb *reorderBuffer) reset() {
	rb.nrune = 0
	rb.nbyte = 0
}

func (rb *reorderBuffer) doFlush() bool {
	if !rb.valid() {
		return false
	}
	if rb.f.composing {
		rb.compose()
	}
	if rb.err {
		return false
	}
	res := rb.flushF(rb)
	rb.reset()
	return res
}

// appendFlush appends the normalized segment to rb.out.
func appendFlush(rb *reorderBuffer) bool {
	for i := 0; i < rb.nrune; i++ {
		start := rb.rune[i].pos
		end := start + int(rb.rune[i].size)
		if end < start || start < 0 || end > rb.bytes || end-start > rb.output-len(rb.out) {
			rb.err = true
			return false
		}
		rb.out = append(rb.out, rb.byte[start:end]...)
	}
	return true
}

// insertOrdered inserts a rune in the buffer, ordered by Canonical Combining Class.
// It returns false if the buffer is not large enough to hold the rune.
// It is used internally by insert and insertString only.
func (rb *reorderBuffer) insertOrdered(info Properties) {
	if !rb.reserve(1) {
		return
	}
	n := rb.nrune
	b := rb.rune[:]
	cc := info.ccc
	if cc > 0 {
		// Find insertion position + move elements to make room.
		for ; n > 0; n-- {
			if b[n-1].ccc <= cc {
				break
			}
			b[n] = b[n-1]
		}
	}
	rb.nrune += 1
	pos := rb.nbyte
	rb.nbyte += utf8.UTFMax
	info.pos = pos
	b[n] = info
}

// insertErr is an error code returned by insert. Using this type instead
// of error improves performance up to 20% for many of the benchmarks.
type insertErr int

const (
	iSuccess insertErr = -iota
	iShortDst
	iShortSrc
)

// insertFlush inserts the given rune in the buffer ordered by CCC.
// If a decomposition with multiple segments are encountered, they leading
// ones are flushed.
// It returns a non-zero error code if the rune was not inserted.
func (rb *reorderBuffer) insertFlush(src input, i int, info Properties) insertErr {
	if rb.err || int(rb.ss) > rb.counter {
		rb.err = true
		return iShortDst
	}
	if rune := src.hangul(i); rune != 0 {
		rb.decomposeHangul(rune)
		if rb.err {
			return iShortDst
		}
		return iSuccess
	}
	if info.hasDecomposition() {
		return rb.insertDecomposed(info.Decomposition())
	}
	rb.insertSingle(src, i, info)
	if rb.err {
		return iShortDst
	}
	return iSuccess
}

// insertDecomposed inserts an entry in to the reorderBuffer for each rune
// in dcomp. dcomp must be a sequence of decomposed UTF-8-encoded runes.
// It flushes the buffer on each new segment start.
func (rb *reorderBuffer) insertDecomposed(dcomp []byte) insertErr {
	if !utf8.Valid(dcomp) || !rb.reserve(utf8.RuneCount(dcomp)) {
		return iShortDst
	}
	rb.tmpBytes.setBytes(dcomp)
	// As the streamSafe accounting already handles the counting for modifiers,
	// we don't have to call next. However, we do need to keep the accounting
	// intact when flushing the buffer.
	for i := 0; i < len(dcomp); {
		info := rb.f.info(rb.tmpBytes, i)
		if info.BoundaryBefore() && rb.nrune > 0 && !rb.doFlush() {
			return iShortDst
		}
		if info.isInvalid() || info.size == 0 || int(info.size) > len(dcomp)-i || !rb.reserve(1) {
			rb.err = true
			return iShortDst
		}
		copy(rb.byte[rb.nbyte:rb.nbyte+int(info.size)], dcomp[i:i+int(info.size)])
		i += int(info.size)
		rb.insertOrdered(info)
	}
	return iSuccess
}

// insertSingle inserts an entry in the reorderBuffer for the rune at
// position i. info is the runeInfo for the rune at position i.
func (rb *reorderBuffer) insertSingle(src input, i int, info Properties) {
	if !rb.reserve(1) || i < 0 || info.size == 0 || int(info.size) > src.length()-i {
		rb.err = true
		return
	}
	if src.copySlice(rb.byte[rb.nbyte:rb.nbyte+int(info.size)], i, i+int(info.size)) != int(info.size) {
		rb.err = true
		return
	}
	rb.insertOrdered(info)
}

// appendRune inserts a rune at the end of the buffer. It is used for Hangul.
func (rb *reorderBuffer) appendRune(r rune) {
	if !rb.reserve(1) || !utf8.ValidRune(r) {
		rb.err = true
		return
	}
	bn := rb.nbyte
	sz := utf8.EncodeRune(rb.byte[bn:], rune(r))
	rb.nbyte += utf8.UTFMax
	rb.rune[rb.nrune] = Properties{pos: bn, size: uint8(sz & 7)} // EncodeRune returns 1..4.
	rb.nrune++
}

// assignRune sets a rune at position pos. It is used for Hangul and recomposition.
func (rb *reorderBuffer) assignRune(pos int, r rune) {
	if !rb.validIndex(pos) || !utf8.ValidRune(r) {
		rb.err = true
		return
	}
	bn := rb.rune[pos].pos
	sz := utf8.EncodeRune(rb.byte[bn:], rune(r))
	rb.rune[pos] = Properties{pos: bn, size: uint8(sz & 7)} // EncodeRune returns 1..4.
}

// runeAt returns the rune at position n. It is used for Hangul and recomposition.
func (rb *reorderBuffer) runeAt(n int) rune {
	if !rb.validIndex(n) {
		rb.err = true
		return utf8.RuneError
	}
	inf := rb.rune[n]
	r, _ := utf8.DecodeRune(rb.byte[inf.pos : inf.pos+int(inf.size)])
	return r
}

// bytesAt returns the UTF-8 encoding of the rune at position n.
// It is used for Hangul and recomposition.
func (rb *reorderBuffer) bytesAt(n int) []byte {
	if !rb.validIndex(n) {
		rb.err = true
		return nil
	}
	inf := rb.rune[n]
	return rb.byte[inf.pos : int(inf.pos)+int(inf.size)]
}

// For Hangul we combine algorithmically, instead of using tables.
const (
	hangulBase  = 0xAC00 // UTF-8(hangulBase) -> EA B0 80
	hangulBase0 = 0xEA
	hangulBase1 = 0xB0
	hangulBase2 = 0x80

	hangulEnd  = hangulBase + jamoLVTCount // UTF-8(0xD7A4) -> ED 9E A4
	hangulEnd0 = 0xED
	hangulEnd1 = 0x9E
	hangulEnd2 = 0xA4

	jamoLBase  = 0x1100 // UTF-8(jamoLBase) -> E1 84 00
	jamoLBase0 = 0xE1
	jamoLBase1 = 0x84
	jamoLEnd   = 0x1113
	jamoVBase  = 0x1161
	jamoVEnd   = 0x1176
	jamoTBase  = 0x11A7
	jamoTEnd   = 0x11C3

	jamoTCount   = 28
	jamoVCount   = 21
	jamoVTCount  = 21 * 28
	jamoLVTCount = 19 * 21 * 28
)
const hangulUTF8Size = 3

func isHangul(b []byte) bool {
	if len(b) < hangulUTF8Size {
		return false
	}
	b0 := b[0]
	if b0 < hangulBase0 {
		return false
	}
	b1 := b[1]
	switch {
	case b0 == hangulBase0:
		return b1 >= hangulBase1
	case b0 < hangulEnd0:
		return true
	case b0 > hangulEnd0:
		return false
	case b1 < hangulEnd1:
		return true
	}
	return b1 == hangulEnd1 && b[2] < hangulEnd2
}

func isHangulString(b string) bool {
	if len(b) < hangulUTF8Size {
		return false
	}
	b0 := b[0]
	if b0 < hangulBase0 {
		return false
	}
	b1 := b[1]
	switch {
	case b0 == hangulBase0:
		return b1 >= hangulBase1
	case b0 < hangulEnd0:
		return true
	case b0 > hangulEnd0:
		return false
	case b1 < hangulEnd1:
		return true
	}
	return b1 == hangulEnd1 && b[2] < hangulEnd2
}

// Caller must ensure len(b) >= 2.
func isJamoVT(b []byte) bool {
	// True if (rune & 0xff00) == jamoLBase
	return len(b) >= 2 && b[0] == jamoLBase0 && (b[1]&0xFC) == jamoLBase1
}

// decomposeHangul algorithmically decomposes a Hangul rune into
// its Jamo components.
// See https://unicode.org/reports/tr15/#Hangul for details on decomposing Hangul.
func (rb *reorderBuffer) decomposeHangul(r rune) {
	if !rb.reserve(3) {
		return
	}
	r -= hangulBase
	x := r % jamoTCount
	r /= jamoTCount
	rb.appendRune(jamoLBase + r/jamoVCount)
	rb.appendRune(jamoVBase + r%jamoVCount)
	if x != 0 {
		rb.appendRune(jamoTBase + x)
	}
}

// combineHangul algorithmically combines Jamo character components into Hangul.
// See https://unicode.org/reports/tr15/#Hangul for details on combining Hangul.
func (rb *reorderBuffer) combineHangul(s, i, k int) {
	b := rb.rune[:]
	bn := rb.nrune
	for ; i < bn; i++ {
		cccB := b[k-1].ccc
		cccC := b[i].ccc
		if cccB == 0 {
			s = k - 1
		}
		if s != k-1 && cccB >= cccC {
			// b[i] is blocked by greater-equal cccX below it
			b[k] = b[i]
			k++
		} else {
			l := rb.runeAt(s) // also used to compare to hangulBase
			v := rb.runeAt(i) // also used to compare to jamoT
			switch {
			case jamoLBase <= l && l < jamoLEnd &&
				jamoVBase <= v && v < jamoVEnd:
				// 11xx plus 116x to LV
				rb.assignRune(s, hangulBase+
					(l-jamoLBase)*jamoVTCount+(v-jamoVBase)*jamoTCount)
			case hangulBase <= l && l < hangulEnd &&
				jamoTBase < v && v < jamoTEnd &&
				((l-hangulBase)%jamoTCount) == 0:
				// ACxx plus 11Ax to LVT
				rb.assignRune(s, l+v-jamoTBase)
			default:
				// Not a Hangul composition. The segment may still
				// contain regular canonical compositions, such as
				// combining marks following a Hangul syllable, so
				// fall back to the composition table.
				if b[i].combinesBackward() {
					if combined := combine(l, v); combined != 0 {
						rb.assignRune(s, combined)
						continue
					}
				}
				b[k] = b[i]
				k++
			}
		}
	}
	rb.nrune = k
}

// compose recombines the runes in the buffer.
// It should only be used to recompose a single segment, as it will not
// handle alternations between Hangul and non-Hangul characters correctly.
func (rb *reorderBuffer) compose() {
	// Lazily load the map used by the combine func below, but do
	// it outside of the loop.
	recompMapOnce.Do(buildRecompMap)

	// UAX #15, section X5 , including Corrigendum #5
	// "In any character sequence beginning with starter S, a character C is
	//  blocked from S if and only if there is some character B between S
	//  and C, and either B is a starter or it has the same or higher
	//  combining class as C."
	bn := rb.nrune
	if bn == 0 {
		return
	}
	k := 1
	b := rb.rune[:]
	for s, i := 0, 1; i < bn; i++ {
		if isJamoVT(rb.bytesAt(i)) {
			// Redo from start in Hangul mode. Necessary to support
			// U+320E..U+321E in NFKC mode.
			rb.combineHangul(s, i, k)
			return
		}
		ii := b[i]
		// Track the last starter unconditionally: b[i] must be blocked by
		// any starter between it and s, even one that b[i] itself cannot
		// combine with, and even if the runes in between never enter the
		// combinesBackward branch below.
		cccB := b[k-1].ccc
		cccC := ii.ccc
		blocked := false // b[i] blocked by starter or greater or equal CCC?
		if cccB == 0 {
			s = k - 1
		} else {
			blocked = s != k-1 && cccB >= cccC
		}
		// We can only use combineForward as a filter if we later
		// get the info for the combined character. This is more
		// expensive than using the filter. Using combinesBackward()
		// is safe.
		if ii.combinesBackward() && !blocked {
			combined := combine(rb.runeAt(s), rb.runeAt(i))
			if combined != 0 {
				rb.assignRune(s, combined)
				continue
			}
		}
		b[k] = b[i]
		k++
	}
	rb.nrune = k
}

// Independent bounds protect every retained write; stream accounting is NOT
// the memory-safety guard. Test-only callers can reduce each per-call budget.
func (rb *reorderBuffer) reserve(n int) bool {
	if rb.err || n < 0 || rb.slots < 0 || rb.slots > len(rb.rune) || rb.bytes < 0 || rb.bytes > len(rb.byte) || rb.nrune < 0 || rb.nrune > rb.slots || rb.nbyte < 0 || rb.nbyte > rb.bytes || n > rb.slots-rb.nrune || n > (rb.bytes-rb.nbyte)/4 {
		rb.err = true
		return false
	}
	return true
}
func (rb *reorderBuffer) validIndex(i int) bool {
	if i < 0 || i >= rb.nrune || i >= rb.slots || i >= len(rb.rune) {
		return false
	}
	p := rb.rune[i]
	return p.pos >= 0 && p.pos <= rb.bytes-4 && p.size > 0 && p.size <= 4 && p.pos <= rb.nbyte-4
}
func (rb *reorderBuffer) valid() bool {
	if !rb.reserve(0) || rb.output < 0 || len(rb.out) > rb.output {
		rb.err = true
		return false
	}
	for i := 0; i < rb.nrune; i++ {
		if !rb.validIndex(i) {
			rb.err = true
			return false
		}
	}
	return true
}
