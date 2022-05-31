package storer

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"

	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
)

type crlStorer struct {
	cspb.UnimplementedCRLStorerServer
	endpoint string
	issuers  map[issuance.IssuerNameID]*issuance.Certificate
	log      blog.Logger
}

func (cs *crlStorer) UploadCRL(stream cspb.CRLStorer_UploadCRLServer) error {
	for {
		in, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		var issuer *issuance.Certificate
		var shardID int64
		var crlNumber *big.Int
		crlBytes := make([]byte, 0)

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
		cs.log.Debugf("got complete CRL for issuer %s, shard %d with %d entries", issuer.Subject.CommonName, shardID, len(crl.TBSCertList.RevokedCertificates))
	}
	return nil
}
