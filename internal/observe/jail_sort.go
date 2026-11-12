package observe

import (
	"slices"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
)

// orderJails sorts our private copy numerically (IPv4 before IPv6). Large maps
// use stable byte radix passes, not O(N log N) repeated 16-byte comparisons.
// Constant address bytes need no scattering, common for shared IPv6 prefixes.
func orderJails(jails []contract.JailRecord) {
	if len(jails) < 4096 {
		slices.SortFunc(jails, func(a, b contract.JailRecord) int { return compareAddress(a.Src, b.Src) })
		return
	}
	var counts [17][256]int
	for _, j := range jails {
		for b, v := range j.Src.Bytes {
			counts[b][v]++
		}
		counts[16][j.Src.Family]++
	}
	var scratch []contract.JailRecord
	src, dst := jails, scratch
	// Family is the most significant sort byte, after the address LSD passes.
	for pass := 15; pass >= -1; pass-- {
		index := pass
		if pass == -1 {
			index = 16
		}
		var offsets [256]int
		total, nonzero := 0, 0
		for b, count := range counts[index] {
			offsets[b] = total
			total += count
			if count > 0 {
				nonzero++
			}
		}
		if nonzero < 2 {
			continue
		}
		if scratch == nil {
			scratch = make([]contract.JailRecord, len(jails))
			dst = scratch
		}
		for _, j := range src {
			b := j.Src.Family
			if pass >= 0 {
				b = j.Src.Bytes[pass]
			}
			dst[offsets[b]] = j
			offsets[b]++
		}
		src, dst = dst, src
	}
	if len(src) > 0 && &src[0] != &jails[0] {
		copy(jails, src)
	}
}
