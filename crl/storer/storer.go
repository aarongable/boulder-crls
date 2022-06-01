package storer

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
)

// s3Putter matches the subset of the s3.Client interface which we use, to allow
// simpler mocking in tests.
type s3Putter interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type crlStorer struct {
	cspb.UnimplementedCRLStorerServer
	awsClient        s3Putter
	issuers          map[issuance.IssuerNameID]*issuance.Certificate
	sizeHistogram    *prometheus.HistogramVec
	latencyHistogram *prometheus.HistogramVec
	log              blog.Logger
	clk              clock.Clock
}

func New(
	issuers []*issuance.Certificate,
	s3client s3Putter,
	stats prometheus.Registerer,
	log blog.Logger,
	clk clock.Clock,
) (*crlStorer, error) {
	issuersByNameID := make(map[issuance.IssuerNameID]*issuance.Certificate, len(issuers))
	for _, issuer := range issuers {
		issuersByNameID[issuer.NameID()] = issuer
	}

	sizeHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "crl_storer_sizes",
		Help:    "A histogram of the sizes (in bytes) of CRLs uploaded by crl-storer",
		Buckets: []float64{0, 256, 1024, 4096, 16384, 65536},
	}, []string{"issuer"})
	stats.MustRegister(sizeHistogram)

	latencyHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "crl_storer_upload_times",
		Help:    "A histogram of the time (in seconds) it took crl-storer to upload CRLs",
		Buckets: []float64{0.01, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000},
	}, []string{"issuer"})
	stats.MustRegister(latencyHistogram)

	return &crlStorer{
		issuers:          issuersByNameID,
		awsClient:        s3client,
		sizeHistogram:    sizeHistogram,
		latencyHistogram: latencyHistogram,
		log:              log,
		clk:              clk,
	}, nil
}

func (cs *crlStorer) UploadCRL(stream cspb.CRLStorer_UploadCRLServer) error {
	var issuer *issuance.Certificate
	var shardID int64
	var crlNumber *big.Int
	crlBytes := make([]byte, 0)

	for {
		in, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		switch payload := in.Payload.(type) {
		case *cspb.UploadCRLRequest_Metadata:
			if crlNumber != nil || issuer != nil {
				return errors.New("got more than one metadata message")
			}
			if payload.Metadata.Number == 0 || payload.Metadata.IssuerNameID == 0 {
				return errors.New("got incomplete metadata message")
			}

			shardID = payload.Metadata.ShardID
			crlNumber = big.NewInt(payload.Metadata.Number)

			var ok bool
			issuer, ok = cs.issuers[issuance.IssuerNameID(payload.Metadata.IssuerNameID)]
			if !ok {
				return fmt.Errorf("got unrecognized IssuerNameID: %d", payload.Metadata.IssuerNameID)
			}

		case *cspb.UploadCRLRequest_CrlChunk:
			crlBytes = append(crlBytes, payload.CrlChunk...)
		}

	}

	cs.sizeHistogram.WithLabelValues(issuer.Subject.CommonName).Observe(float64(len(crlBytes)))

	// Open question: should it be the responsibility of the Storer to do this
	// validation, or should the Updater do it?
	crl, err := x509.ParseDERCRL(crlBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CRL bytes for shard %d: %w", shardID, err)
	}

	err = issuer.CheckCRLSignature(crl)
	if err != nil {
		return fmt.Errorf("failed to validate signature for shard %d: %w", shardID, err)
	}

	// TODO: Actually send the bytes elsewhere.
	start := cs.clk.Now()
	cs.log.Debugf("got complete CRL for issuer %s, shard %d with %d entries", issuer.Subject.CommonName, shardID, len(crl.TBSCertList.RevokedCertificates))
	latency := cs.clk.Now().Sub(start)
	cs.latencyHistogram.WithLabelValues(issuer.Subject.CommonName).Observe(latency.Seconds())

	return nil
}
