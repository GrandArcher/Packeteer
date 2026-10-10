package flow

import (
	"encoding/binary"
	"testing"
)

func BenchmarkDecodeV5(b *testing.B) {
	p := make([]byte, 24+48)
	binary.BigEndian.PutUint16(p[0:2], 5)
	binary.BigEndian.PutUint16(p[2:4], 1)
	rec := p[24:]
	copy(rec[0:4], []byte{192, 0, 2, 1})
	copy(rec[4:8], []byte{198, 51, 100, 9})
	binary.BigEndian.PutUint32(rec[20:24], 1000)
	rec[37] = 0x02
	rec[38] = 6
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		obs, err := decodeV5(p)
		if err != nil {
			b.Fatal(err)
		}
		if len(obs) != 1 {
			b.Fatalf("obs = %d", len(obs))
		}
		putObs(obs)
	}
}
