package updater

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type crlUpdater struct {
	issuers        map[issuance.IssuerNameID]*issuance.Certificate
	numShards      int64
	lookbackPeriod time.Duration
	updatePeriod   time.Duration

	sa sapb.StorageAuthorityClient
	ca capb.CRLGeneratorClient

	tickHistogram    *prometheus.HistogramVec
	generatedCounter *prometheus.CounterVec

	log blog.Logger
	clk clock.Clock
}

func NewUpdater(
	issuers []*issuance.Certificate,
	numShards int64,
	lookbackPeriod time.Duration,
	updatePeriod time.Duration,
	sa sapb.StorageAuthorityClient,
	ca capb.CRLGeneratorClient,
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

	if lookbackPeriod.Nanoseconds()%numShards != 0 {
		return nil, fmt.Errorf("lookbackPeriod (%d) must be evenly divisible by numShards (%d)",
			lookbackPeriod.Nanoseconds(), numShards)
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
		updatePeriod,
		sa,
		ca,
		tickHistogram,
		generatedCounter,
		log,
		clk,
	}, nil
}

func (cu *crlUpdater) Run() {
	ticker := time.Tick(cu.updatePeriod)
	for range ticker {
		ctx := context.Background()
		cu.tick(ctx)
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

// Given:
// - the number of CRL shards we want to maintain; and
// - the number of days of historical issuance we want to cover by those shards
// we can compute the "width" (number of nanoseconds covered by) each shard.
// From there, given:
// - a fixed point in time (here taken to be the 0 value of time.Time);
// - the current time (or, rather, atTime); and
// - the integer ID of a shard
// we can compute the left-hand "edge" (starting point in time) of that shard.
// Finally, we can compute the end time as the start time plus the width.
// The first two items are data members on the crlUpdater. The last two are the
// two arguments to this function.
func (cu *crlUpdater) getWindowForShard(atTime time.Time, shardID int64) (time.Time, time.Time) {
	shardID = shardID % cu.numShards
	shardWidth := cu.lookbackPeriod.Nanoseconds() / cu.numShards
	offset := (atTime.UnixNano() - (shardID * shardWidth)) % cu.lookbackPeriod.Nanoseconds()
	start := atTime.Add(-time.Duration(offset))
	end := start.Add(time.Duration(shardWidth))
	if end.After(atTime) {
		end = end.Add(-cu.lookbackPeriod)
	}
	return start, end
}

func (cu *crlUpdater) tickIssuer(ctx context.Context, atTime time.Time, id issuance.IssuerNameID) error {
	start := cu.clk.Now()
	result := "success"
	defer func() {
		cu.tickHistogram.WithLabelValues(cu.issuers[id].Subject.CommonName, result).Observe(cu.clk.Now().Sub(start).Seconds())
	}()

	for shardID := int64(0); shardID < cu.numShards; shardID++ {
		// For now, process each shard serially. This prevents us fromt trying to
		// load multiple shards-worth of CRL entries simultaneously.
		issuedAfter, issuedBefore := cu.getWindowForShard(atTime, shardID)

		saStream, err := cu.sa.GetRevokedCerts(ctx, &sapb.GetRevokedCertsRequest{
			IssuerNameID:  int64(id),
			IssuedAfter:   issuedAfter.UnixNano(),
			IssuedBefore:  issuedBefore.UnixNano(),
			RevokedBefore: atTime.UnixNano(),
		})
		if err != nil {
			result = "failed"
			return fmt.Errorf("error connecting to SA for shard %d: %s", shardID, err)
		}

		caStream, err := cu.ca.GenerateCRL(ctx)
		if err != nil {
			result = "failed"
			return fmt.Errorf("error connecting to CA for shard %d: %s", shardID, err)
		}

		err = caStream.Send(&capb.GenerateCRLRequest{
			Payload: &capb.GenerateCRLRequest_Metadata{
				Metadata: &capb.CRLMetadata{
					IssuerNameID: int64(id),
					ThisUpdate:   atTime.UnixNano(),
				},
			},
		})
		if err != nil {
			result = "failed"
			return fmt.Errorf("error sending CA metadata for shard %d: %s", shardID, err)
		}

		for {
			entry, err := saStream.Recv()
			if err != nil {
				if err == io.EOF {
					break
				}
				result = "failed"
				return fmt.Errorf("error retrieving entry from SA for shard %d: %s", shardID, err)
			}

			err = caStream.Send(&capb.GenerateCRLRequest{
				Payload: &capb.GenerateCRLRequest_Entry{
					Entry: entry,
				},
			})
			if err != nil {
				result = "failed"
				return fmt.Errorf("error sending entry to CA for shard %d: %s", shardID, err)
			}
		}

		crlBytes := make([]byte, 0)
		for {
			out, err := caStream.Recv()
			if err != nil {
				if err == io.EOF {
					break
				}
				result = "failed"
				return fmt.Errorf("failed to read CRL bytes for shard %d: %s", shardID, err)
			}

			crlBytes = append(crlBytes, out.Chunk...)
		}

		crl, err := x509.ParseDERCRL(crlBytes)
		if err != nil {
			result = "failed"
			return fmt.Errorf("failed to parse CRL bytes for shard %d: %s", shardID, err)
		}

		err = cu.issuers[id].CheckCRLSignature(crl)
		if err != nil {
			result = "failed"
			return fmt.Errorf("failed to validate signature for shard %d: %s", shardID, err)
		}

		// TODO: Upload the CRL to flat-file storage somewhere.
		cu.log.Debugf("got complete CRL for issuer %s, shard %d with %d entries", cu.issuers[id].Subject.CommonName, shardID, len(crl.TBSCertList.RevokedCertificates))
	}

	return nil
}
