// behalf-bench is the demo-hardware measurement run (architecture open item
// #1; Linear ENG-10). It measures, on the real Append path:
//
//   - durable-ack latency (Q75) sequentially and under concurrent load, the
//     numbers that set the Q47 Add-latency threshold;
//   - ack-to-checkpoint-cover time, the number that validates the 10 s MMD
//     on receipt promises (Q57).
//
// The numbers are interface measurements on macOS (O_SYNC issues no
// drive-cache barrier for file data there); Linux carries full integrity
// semantics, which is why it is the production recommendation (D1, Q75).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/testkeys"
	"github.com/behalf-sh/behalf/internal/tlog"
)

type phaseResult struct {
	Name        string    `json:"name"`
	Concurrency int       `json:"concurrency"`
	Appends     int       `json:"appends"`
	SecondsWall float64   `json:"seconds_wall"`
	PerSecond   float64   `json:"appends_per_second"`
	P50Ms       float64   `json:"p50_ms"`
	P90Ms       float64   `json:"p90_ms"`
	P99Ms       float64   `json:"p99_ms"`
	MaxMs       float64   `json:"max_ms"`
	Samples     []float64 `json:"-"`
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p*float64(len(sorted))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func summarize(name string, conc int, wall time.Duration, lat []time.Duration) phaseResult {
	ms := make([]float64, len(lat))
	for i, d := range lat {
		ms[i] = float64(d.Microseconds()) / 1000.0
	}
	sort.Float64s(ms)
	return phaseResult{
		Name:        name,
		Concurrency: conc,
		Appends:     len(lat),
		SecondsWall: wall.Seconds(),
		PerSecond:   float64(len(lat)) / wall.Seconds(),
		P50Ms:       percentile(ms, 0.50),
		P90Ms:       percentile(ms, 0.90),
		P99Ms:       percentile(ms, 0.99),
		MaxMs:       ms[len(ms)-1],
		Samples:     ms,
	}
}

// benchPayload builds a receipt-shaped payload of roughly the fixture
// receipts' size, with a unique receipt_id per call.
func benchPayload(i int, pad string) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":"behalf.sh/receipt/v1","otel_conventions_version":"1.29.0","receipt_id":"BENCH%021d","kind":"tool_call","risk_class":"low","risk_policy_digest":"%064d","captured_at":"2026-08-27T12:00:00Z","emitter":{"jkt":"bench","surface":"cli","counter":%d},"operation":{"name":"bench.append","outcome":{"status":"ok"}},"run_id":"run_bench","run_id_provenance":"caller","attribution":{"verification":"asserted","class":"direct"},"provenance":{"source":"native"},"pad":"%s"}`,
		i, 0, i, pad))
}

func main() {
	dir := flag.String("dir", "", "log dir (default: fresh temp dir)")
	n := flag.Int("n", 1500, "appends per phase")
	payloadPad := flag.Int("pad", 2048, "payload padding bytes (approximates real receipt size)")
	mmdSamples := flag.Int("mmd-samples", 40, "ack-to-checkpoint-cover samples")
	jsonOut := flag.String("json", "", "write full results JSON to this file")
	flag.Parse()

	if *dir == "" {
		d, err := os.MkdirTemp("", "behalf-bench-*")
		if err != nil {
			log.Fatal(err)
		}
		defer os.RemoveAll(d)
		*dir = d
	}

	ctx := context.Background()
	key, err := tlog.GenerateCheckpointKey("behalf.sh/log/bench")
	if err != nil {
		log.Fatal(err)
	}
	l, err := tlog.Open(ctx, *dir, key, tlog.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close(ctx)

	emitter := testkeys.Emitter()
	pad := strings.Repeat("x", *payloadPad)
	seq := 0
	envelope := func() []byte {
		seq++
		payload := benchPayload(seq, pad)
		pae := dsse.PAE(exportv1.PayloadTypeReceipt, payload)
		sig := ed25519.Sign(emitter.Private, pae)
		return tlog.BuildEnvelope(exportv1.PayloadTypeReceipt, payload, emitter.JKT, sig)
	}
	// Pre-build all envelopes so signing cost never pollutes append latency.
	var mu sync.Mutex
	prebuild := func(count int) [][]byte {
		out := make([][]byte, count)
		for i := range out {
			out[i] = envelope()
		}
		return out
	}

	var results []phaseResult

	runPhase := func(name string, conc int) {
		envs := prebuild(*n)
		lat := make([]time.Duration, 0, *n)
		var wg sync.WaitGroup
		start := time.Now()
		per := *n / conc
		for w := 0; w < conc; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				local := make([]time.Duration, 0, per)
				for i := 0; i < per; i++ {
					e := envs[w*per+i]
					t0 := time.Now()
					if _, err := l.Append(ctx, e); err != nil {
						log.Fatalf("%s append: %v", name, err)
					}
					local = append(local, time.Since(t0))
				}
				mu.Lock()
				lat = append(lat, local...)
				mu.Unlock()
			}(w)
		}
		wg.Wait()
		wall := time.Since(start)
		r := summarize(name, conc, wall, lat)
		results = append(results, r)
		fmt.Printf("%-14s conc=%-3d n=%-5d  %8.1f/s   p50 %7.3f ms   p90 %7.3f ms   p99 %7.3f ms   max %8.1f ms\n",
			name, conc, r.Appends, r.PerSecond, r.P50Ms, r.P90Ms, r.P99Ms, r.MaxMs)
	}

	fmt.Printf("behalf-bench  %s/%s  %d CPU  dir=%s\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), *dir)
	runPhase("sequential", 1)
	runPhase("burst-4", 4)
	runPhase("burst-16", 16)
	runPhase("burst-64", 64)

	// MMD phase: ack → first published checkpoint whose size covers the
	// index. This is the number the 10 s promise MMD must dominate.
	covers := make([]time.Duration, 0, *mmdSamples)
	for i := 0; i < *mmdSamples; i++ {
		e := envelope()
		t0 := time.Now()
		res, err := l.Append(ctx, e)
		if err != nil {
			log.Fatal(err)
		}
		for {
			cp, err := l.ReadCheckpoint(ctx)
			if err == nil && cp != nil {
				lines := strings.SplitN(string(cp), "\n", 3)
				if len(lines) >= 2 {
					if size, perr := strconv.ParseUint(lines[1], 10, 64); perr == nil && size > res.Index {
						break
					}
				}
			}
			if time.Since(t0) > 15*time.Second {
				log.Fatalf("checkpoint did not cover index %d within 15s", res.Index)
			}
			time.Sleep(10 * time.Millisecond)
		}
		covers = append(covers, time.Since(t0))
		// Space samples out so they land in distinct checkpoint windows.
		time.Sleep(120 * time.Millisecond)
	}
	mmd := summarize("ack-to-checkpoint", 1, time.Duration(0), covers)
	mmd.PerSecond = 0
	mmd.SecondsWall = 0
	results = append(results, mmd)
	fmt.Printf("%-14s n=%-5d                  p50 %7.1f ms   p90 %7.1f ms   p99 %7.1f ms   max %8.1f ms\n",
		"ack→checkpoint", mmd.Appends, mmd.P50Ms, mmd.P90Ms, mmd.P99Ms, mmd.MaxMs)

	size, _ := l.TreeSize(ctx)
	fmt.Printf("final tree size: %d\n", size)

	if *jsonOut != "" {
		blob, _ := json.MarshalIndent(struct {
			GOOS    string        `json:"goos"`
			GOARCH  string        `json:"goarch"`
			NumCPU  int           `json:"num_cpu"`
			Results []phaseResult `json:"results"`
		}{runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), results}, "", "  ")
		if err := os.WriteFile(*jsonOut, blob, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
