// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nfc17

import (
	"errors"
	"unicode/utf8"
)

var ErrInput = errors.New("password encoding, repertoire or resource limit invalid")

const MaxBytes = 4096
const MaxScalars = 512
const MaxOutput = 8192

type Form int

const NFC Form = 0

// Bytes is a bounded one-shot ordinary Unicode17 NFC operation. It returns
// no partial output and never aliases its input. Repertoire is validated by
// Canonical, separately from the official normalization-conformance core.
func Bytes(b []byte) ([]byte, error) {
	return bounded(b, maxBufferSize, maxByteBufferSize, MaxOutput, maxNonStarters)
}
func bounded(b []byte, slots, byteBudget, output, counter int) ([]byte, error) {
	if len(b) > MaxBytes || !utf8.Valid(b) || utf8.RuneCount(b) > MaxScalars || slots < 0 || slots > maxBufferSize || byteBudget < 0 || byteBudget > maxByteBufferSize || output < 0 || output > MaxOutput || counter < 0 || counter > maxNonStarters {
		return nil, ErrInput
	}
	src := inputBytes(b)
	ft := formTable[NFC]
	n, ok := ft.quickSpan(src, 0, len(b), true)
	if n < 0 || n > len(b) || n > output {
		return nil, ErrInput
	}
	if ok {
		return append([]byte{}, b...), nil
	}
	out := make([]byte, n, output)
	copy(out, b[:n])
	rb := reorderBuffer{f: *ft, src: src, nsrc: len(b), out: out, flushF: appendFlush, slots: slots, bytes: byteBudget, output: output, counter: counter}
	result := doAppendInner(&rb, n)
	if rb.err {
		return nil, ErrInput
	}
	return result, nil
}

func appendQuick(rb *reorderBuffer, i int) int {
	if rb.nsrc == i {
		return i
	}
	end, _ := rb.f.quickSpan(rb.src, i, rb.nsrc, true)
	if i < 0 || end < i || end > rb.nsrc || end-i > rb.output-len(rb.out) {
		rb.err = true
		return -1
	}
	rb.out = rb.src.appendSlice(rb.out, i, end)
	return end
}
func doAppendInner(rb *reorderBuffer, p int) []byte {
	for n := rb.nsrc; p < n; {
		old := p
		p = decomposeSegment(rb, p, true)
		if p < 0 || p <= old || rb.err {
			rb.err = true
			return nil
		}
		p = appendQuick(rb, p)
		if p < 0 || rb.err {
			rb.err = true
			return nil
		}
	}
	return rb.out
}

// quickSpan returns a boundary n such that src[0:n] == f(src[0:n]) and
// whether any non-normalized parts were found. If atEOF is false, n will
// not point past the last segment if this segment might be become
// non-normalized by appending other runes.
func (f *formInfo) quickSpan(src input, i, end int, atEOF bool) (n int, ok bool) {
	var lastCC uint8
	ss := streamSafe(0)
	lastSegStart := i
	for n = end; i < n; {
		if j := src.skipASCII(i, n); i != j {
			i = j
			lastSegStart = i - 1
			lastCC = 0
			ss = 0
			continue
		}
		info := f.info(src, i)
		if info.isInvalid() {
			if atEOF {
				// include incomplete runes
				return n, true
			}
			return lastSegStart, true
		}
		// This block needs to be before the next, because it is possible to
		// have an overflow for runes that are starters (e.g. with U+FF9E).
		switch ss.next(info) {
		case ssStarter:
			lastSegStart = i
		case ssOverflow:
			return lastSegStart, false
		case ssSuccess:
			if lastCC > info.ccc {
				return lastSegStart, false
			}
		}
		if f.composing {
			if !info.isYesC() {
				break
			}
		} else {
			if !info.isYesD() {
				break
			}
		}
		lastCC = info.ccc
		i += int(info.size)
	}
	if i == n {
		if !atEOF {
			n = lastSegStart
		}
		return n, true
	}
	return lastSegStart, false
}

// decomposeSegment retains upstream ordering/composition boundaries. Overflow
// is an invariant failure, never a stream-safe CGJ insertion.
func decomposeSegment(rb *reorderBuffer, sp int, atEOF bool) int {
	// Force one character to be consumed.
	info := rb.f.info(rb.src, sp)
	if info.isInvalid() {
		// Consume the invalid character.
		// Perhaps this should return iShortSrc instead?
		// May not matter, this path does not appear to be reachable in practice.
		rb.err = true
		return int(iShortSrc)
	}
	if s := rb.ss.next(info); s == ssStarter {
		// TODO: this could be removed if we don't support merging.
		if rb.nrune > 0 {
			goto end
		}
	} else if s == ssOverflow {
		rb.err = true
		return int(iShortDst)
	}
	if err := rb.insertFlush(rb.src, sp, info); err != iSuccess {
		return int(err)
	}
	for {
		sp += int(info.size)
		if sp >= rb.nsrc {
			if !atEOF && !info.BoundaryAfter() {
				return int(iShortSrc)
			}
			break
		}
		info = rb.f.info(rb.src, sp)
		if info.isInvalid() {
			if !atEOF {
				return int(iShortSrc)
			}
			break
		}
		if s := rb.ss.next(info); s == ssStarter {
			break
		} else if s == ssOverflow {
			rb.err = true
			return int(iShortDst)
		}
		if err := rb.insertFlush(rb.src, sp, info); err != iSuccess {
			return int(err)
		}
	}
end:
	if !rb.doFlush() {
		return int(iShortDst)
	}
	return sp
}
