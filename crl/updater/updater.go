package updater

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	capb "github.com/letsencrypt/boulder/ca/proto"
	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type crlUpdater struct {
	issuers           map[issuance.IssuerNameID]*issuance.Certificate
	numShards         int64
	lookbackPeriod    time.Duration
	lookforwardPeriod time.Duration
	updatePeriod      time.Duration

	sa sapb.StorageAuthorityClient
	ca capb.CRLGeneratorClient
	cs cspb.CRLStorerClient

	tickHistogram    *prometheus.HistogramVec
	generatedCounter *prometheus.CounterVec

	log blog.Logger
	clk clock.Clock
}

func NewUpdater(
	issuers []*issuance.Certificate,
	numShards int64,
	lookbackPeriod time.Duration,
	lookforwardPeriod time.Duration,
	updatePeriod time.Duration,
	sa sapb.StorageAuthorityClient,
	ca capb.CRLGeneratorClient,
	cs cspb.CRLStorerClient,
	stats prometheus.Registerer,
	log blog.Logger,
	clk clock.Clock,
) (*crlUpdater, error) {
	issuersByNameID := make(map[issuance.IssuerNameID]*issuance.Certificate, len(issuers))
	for _, issuer := range issuers {
		issuersByNameID[issuer.NameID()] = issuer
	}

	if numShards < 1 {
		return nil, fmt.Errorf("must have positive number of shards, got: %d", numShards)
	}

	if updatePeriod >= 7*24*time.Hour {
		return nil, fmt.Errorf("must update CRLs at least every 7 days, got: %s", updatePeriod)
	}

	window := lookbackPeriod + lookforwardPeriod
	if window.Nanoseconds()%numShards != 0 {
		return nil, fmt.Errorf("total window (lookback+lookforward=%dns) must be evenly divisible by numShards (%d)",
			window.Nanoseconds(), numShards)
	}

	tickHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "crl_updater_ticks",
		Help:    "A histogram of crl-updater tick latencies labeled by issuer and result",
		Buckets: []float64{0.01, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000},
	}, []string{"issuer", "result"})
	stats.MustRegister(tickHistogram)

	generatedCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "crl_updater_generated",
		Help: "A counter of CRL generation calls labeled by result",
	}, []string{"result"})
	stats.MustRegister(generatedCounter)

	// TODO: add a storedCounter

	return &crlUpdater{
		issuersByNameID,
		numShards,
		lookbackPeriod,
		lookforwardPeriod,
		updatePeriod,
		sa,
		ca,
		cs,
		tickHistogram,
		generatedCounter,
		log,
		clk,
	}, nil
}

// Run causes the crl-updater to run immediately, and then re-run continuously
// on the frequency specified by crlUpdater.updatePeriod.
func (cu *crlUpdater) Run() {
	cu.tick(context.Background())
	ticker := time.Tick(cu.updatePeriod)
	for range ticker {
		cu.tick(context.Background())
	}
}

func (cu *crlUpdater) tick(ctx context.Context) {
	start := cu.clk.Now()
	result := "success"
	defer func() {
		cu.tickHistogram.WithLabelValues("all", result).Observe(cu.clk.Now().Sub(start).Seconds())
	}()

	for id, iss := range cu.issuers {
		// For now, process each issuer serially. This prevents us from trying to
		// load multiple issuers-worth of CRL entries simultaneously.
		atTime := cu.clk.Now()
		cu.log.Debugf("Updating CRLs for %q at time %s", iss.Subject.CommonName, atTime)
		err := cu.tickIssuer(ctx, atTime, id)
		if err != nil {
			cu.log.AuditErrf(
				"tick for issuer %s at time %s failed: %s",
				iss.Subject.CommonName,
				atTime.Format(time.RFC3339Nano),
				err)
			result = "failed"
		}
	}
}

// tickIssuer performs the full crl issuance cycle for a single issuer cert.
func (cu *crlUpdater) tickIssuer(ctx context.Context, atTime time.Time, issuerID issuance.IssuerNameID) error {
	start := cu.clk.Now()
	result := "success"
	defer func() {
		cu.tickHistogram.WithLabelValues(cu.issuers[issuerID].Subject.CommonName+" (Overall)", result).Observe(cu.clk.Now().Sub(start).Seconds())
	}()

	for shardID := int64(0); shardID < cu.numShards; shardID++ {
		cu.log.Debugf("Updating shard %d", shardID)
		// For now, process each shard serially. This prevents us fromt trying to
		// load multiple shards-worth of CRL entries simultaneously.
		err := cu.tickShard(ctx, atTime, issuerID, shardID)
		if err != nil {
			result = "failed"
			return fmt.Errorf("error updating shard %d: %w", shardID, err)
		}
	}

	return nil
}

func (cu *crlUpdater) tickShard(ctx context.Context, atTime time.Time, issuerID issuance.IssuerNameID, shardID int64) error {
	start := cu.clk.Now()
	result := "success"
	defer func() {
		cu.tickHistogram.WithLabelValues(cu.issuers[issuerID].Subject.CommonName, result).Observe(cu.clk.Now().Sub(start).Seconds())
	}()

	expiresAfter, expiresBefore := cu.getShardBoundaries(atTime, shardID)

	cu.log.Debugf("Connecting to SA")
	saStream, err := cu.sa.GetRevokedCerts(ctx, &sapb.GetRevokedCertsRequest{
		IssuerNameID:  int64(issuerID),
		ExpiresAfter:  expiresAfter.UnixNano(),
		ExpiresBefore: expiresBefore.UnixNano(),
		RevokedBefore: atTime.UnixNano(),
	})
	if err != nil {
		result = "failed"
		return fmt.Errorf("error connecting to SA for shard %d: %w", shardID, err)
	}

	cu.log.Debugf("Connecting to CA")
	caStream, err := cu.ca.GenerateCRL(ctx)
	if err != nil {
		result = "failed"
		return fmt.Errorf("error connecting to CA for shard %d: %w", shardID, err)
	}

	err = caStream.Send(&capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Metadata{
			Metadata: &capb.CRLMetadata{
				IssuerNameID: int64(issuerID),
				ThisUpdate:   atTime.UnixNano(),
			},
		},
	})
	if err != nil {
		result = "failed"
		return fmt.Errorf("error sending CA metadata for shard %d: %w", shardID, err)
	}

	for {
		entry, err := saStream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			result = "failed"
			return fmt.Errorf("error retrieving entry from SA for shard %d: %w", shardID, err)
		}

		err = caStream.Send(&capb.GenerateCRLRequest{
			Payload: &capb.GenerateCRLRequest_Entry{
				Entry: entry,
			},
		})
		if err != nil {
			result = "failed"
			return fmt.Errorf("error sending entry to CA for shard %d: %w", shardID, err)
		}
	}

	err = caStream.CloseSend()
	if err != nil {
		result = "failed"
		return fmt.Errorf("error closing CA request stream for shard %d: %w", shardID, err)
	}

	cu.log.Debugf("Connecting to CS")
	csStream, err := cu.cs.UploadCRL(ctx)
	if err != nil {
		result = "failed"
		return fmt.Errorf("error connecting to CRLStorer for shard %d: %w", shardID, err)
	}

	err = csStream.Send(&cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(issuerID),
				ShardID:      shardID,
				Number:       atTime.UnixNano(),
			},
		},
	})
	if err != nil {
		result = "failed"
		return fmt.Errorf("error sending CRLStorer metadata for shard %d: %w", shardID, err)
	}

	// Open question: this currently streams bytes directly from the CA to the
	// Storer. Should it instead consume bytes from the CA, parse and validate
	// the CRL here and now, and *then* forward the bytes to the Storer?
	for {
		out, err := caStream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			result = "failed"
			return fmt.Errorf("failed to read CRL bytes for shard %d: %w", shardID, err)
		}

		err = csStream.Send(&cspb.UploadCRLRequest{
			Payload: &cspb.UploadCRLRequest_CrlChunk{
				CrlChunk: out.Chunk,
			},
		})
		if err != nil {
			result = "failed"
			return fmt.Errorf("error sending CRL bytes for shard %d: %w", shardID, err)
		}
	}

	err = csStream.CloseSend()
	if err != nil {
		result = "failed"
		return fmt.Errorf("error closing storage upload stream for shard %d: %w", shardID, err)
	}

	return nil
}

// getShardBoundaries computes the start (inclusive) and end (exclusive) times
// for a given integer-indexed CRL shard. The idea here is that shards should be
// stable. Picture a timeline, divided into chunks. Number those chunks from 0
// to cu.numShards, then repeat the cycle when you run out of numbers:
//
//    chunk:  5     0     1     2     3     4     5     0     1     2     3
// ...-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//                          ^  ^-atTime                         ^
//    atTime-lookbackPeriod-┘          atTime+lookforwardPeriod-┘
//
// The width of each chunk is determined by dividing the total time window we
// care about (lookbackPeriod+lookforwardPeriod) by the number of shards we
// want (numShards).
//
// Even as "now" (atTime) moves forward, and the total window of expiration
// times that we care about moves forward, the boundaries of each chunk remain
// stable:
//
//    chunk:  5     0     1     2     3     4     5     0     1     2     3
// ...-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//                                  ^  ^-atTime                         ^
//            atTime-lookbackPeriod-┘          atTime+lookforwardPeriod-┘
//
// However, note that at essentially all times the window includes parts of two
// different instances of the chunk which appears at its ends. For example,
// in the second diagram above, the window includes almost all of the middle
// chunk labeled "3", but also includes just a little bit of the rightmost chunk
// also labeled "3".
//
// In order to handle this case, this function always treats the *leftmost*
// (i.e. earliest) chunk with the given ID that has *any* overlap with the
// current window as the current shard. It returns the boundaries of this chunk
// as the boundaries of the desired shard. In the diagram below, even though
// there is another chunk with ID "1" near the right-hand edge of the window,
// that chunk is ignored.
//
//    shard:           |  1  |  2  |  3  |  4  |  5  |  0  |
// ...-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//                          ^  ^-atTime                         ^
//    atTime-lookbackPeriod-┘          atTime+lookforwardPeriod-┘
//
// This means that the lookforwardPeriod MUST be configured large enough that
// there is a buffer of at least one whole chunk width between the actual
// furthest-future expiration (generally atTime+90d) and the right-hand edge of
// the window (atTime+lookforwardPeriod).
func (cu *crlUpdater) getShardBoundaries(atTime time.Time, shardID int64) (time.Time, time.Time) {
	// Ensure that the given shardID falls within the space of acceptable IDs.
	shardID = shardID % cu.numShards

	// Compute the width of the full window.
	windowWidth := cu.lookbackPeriod + cu.lookforwardPeriod
	// Compute the amount of time between the left-hand edge of the most recent
	// "0" chunk and the current time.
	atTimeOffset := time.Duration(atTime.Sub(time.Time{}).Nanoseconds() % windowWidth.Nanoseconds())
	// Compute the left-hand edge of the most recent "0" chunk.
	zeroStart := atTime.Add(-atTimeOffset)

	// Compute the width of a single shard.
	shardWidth := time.Duration(windowWidth.Nanoseconds() / cu.numShards)
	// Compute the amount of time between the left-hand edge of the most recent
	// "0" chunk and the left-hand edge of the desired chunk.
	shardOffset := time.Duration(shardID * shardWidth.Nanoseconds())
	// Compute the left-hand edge of the most recent chunk with the given ID.
	shardStart := zeroStart.Add(shardOffset)
	// Compute the right-hand edge of the most recent chunk with the given ID.
	shardEnd := shardStart.Add(shardWidth)

	// But the shard boundaries we just computed might be for a chunk that is
	// completely behind the left-hand edge of our current window. If they are,
	// bump them forward by one window width to bring them inside our window.
	if shardEnd.Before(atTime.Add(-cu.lookbackPeriod)) {
		shardStart = shardStart.Add(windowWidth)
		shardEnd = shardEnd.Add(windowWidth)
	}
	return shardStart, shardEnd
}
