package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beeker1121/goque"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/linter"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/policy"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

var (
	// * Random public key
	// * CN = not-example.com
	// * DNSNames = not-example.com, www.not-example.com
	CNandSANCSR = mustRead("./testdata/cn_and_san.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes an extensionRequest attribute for a well-formed TLS Feature extension
	MustStapleCSR = mustRead("./testdata/must_staple.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes extensionRequest attributes for *two* must-staple extensions
	DuplicateMustStapleCSR = mustRead("./testdata/duplicate_must_staple.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes an extensionRequest attribute for an unknown extension with an
	//   empty value. That extension's OID, 2.25.123456789, is on the UUID arc.
	//   It isn't a real randomly-generated UUID because Go represents the
	//   components of the OID as 32-bit integers, which aren't large enough to
	//   hold a real 128-bit UUID; this doesn't matter as far as what we're
	//   testing here is concerned.
	UnsupportedExtensionCSR = mustRead("./testdata/unsupported_extension.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes an extensionRequest attribute for the CT poison extension
	//   with a valid NULL value.
	CTPoisonExtensionCSR = mustRead("./testdata/ct_poison_extension.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes an extensionRequest attribute for the CT poison extension
	//   with an invalid empty value.
	CTPoisonExtensionEmptyCSR = mustRead("./testdata/ct_poison_extension_empty.der.csr")

	// CSR generated by Go:
	// * Random ECDSA public key.
	// * CN = [none]
	// * DNSNames = example.com, example2.com
	ECDSACSR = mustRead("./testdata/ecdsa.der.csr")

	// OIDExtensionCTPoison is defined in RFC 6962 s3.1.
	OIDExtensionCTPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

	// OIDExtensionSCTList is defined in RFC 6962 s3.3.
	OIDExtensionSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

const arbitraryRegID int64 = 1001
const yamlLoadErrMsg = "Error loading YAML bytes for ECDSA allow list:"

// Useful key and certificate files.
const caKeyFile = "../test/test-ca.key"
const caCertFile = "../test/test-ca.pem"
const caCertFile2 = "../test/test-ca2.pem"

func mustRead(path string) []byte {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("unable to read %#v: %s", path, err))
	}
	return b
}

type testCtx struct {
	pa             core.PolicyAuthority
	ocsp           *ocspImpl
	crl            *crlImpl
	certExpiry     time.Duration
	certBackdate   time.Duration
	serialPrefix   int
	maxNames       int
	boulderIssuers []*issuance.Issuer
	keyPolicy      goodkey.KeyPolicy
	fc             clock.FakeClock
	stats          prometheus.Registerer
	signatureCount *prometheus.CounterVec
	signErrorCount *prometheus.CounterVec
	logger         *blog.Mock
}

type mockSA struct {
	certificate core.Certificate
}

func (m *mockSA) AddCertificate(ctx context.Context, req *sapb.AddCertificateRequest, _ ...grpc.CallOption) (*sapb.AddCertificateResponse, error) {
	m.certificate.DER = req.Der
	return nil, nil
}

func (m *mockSA) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (m *mockSA) AddSerial(ctx context.Context, req *sapb.AddSerialRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (m *mockSA) GetCertificate(ctx context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*corepb.Certificate, error) {
	return nil, berrors.NotFoundError("cannot find the cert")
}

func (m *mockSA) GetPrecertificate(ctx context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*corepb.Certificate, error) {
	return nil, berrors.NotFoundError("cannot find the precert")
}

var caKey crypto.Signer
var caCert *issuance.Certificate
var caCert2 *issuance.Certificate
var caLinter *linter.Linter
var caLinter2 *linter.Linter
var ctx = context.Background()

func init() {
	var err error
	caCert, caKey, err = issuance.LoadIssuer(issuance.IssuerLoc{
		File:     caKeyFile,
		CertFile: caCertFile,
	})
	if err != nil {
		panic(fmt.Sprintf("Unable to load %q and %q: %s", caKeyFile, caCertFile, err))
	}
	caCert2, err = issuance.LoadCertificate(caCertFile2)
	if err != nil {
		panic(fmt.Sprintf("Unable to parse %q: %s", caCertFile2, err))
	}
	caLinter, _ = linter.New(caCert.Certificate, caKey, []string{"n_subject_common_name_included"})
	caLinter2, _ = linter.New(caCert2.Certificate, caKey, []string{"n_subject_common_name_included"})
}

func setup(t *testing.T) *testCtx {
	features.Reset()
	fc := clock.NewFake()
	fc.Add(1 * time.Hour)

	pa, err := policy.New(nil)
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.SetHostnamePolicyFile("../test/hostname-policy.yaml")
	test.AssertNotError(t, err, "Couldn't set hostname policy")

	boulderProfile := func(rsa, ecdsa bool) *issuance.Profile {
		res, _ := issuance.NewProfile(
			issuance.ProfileConfig{
				AllowMustStaple: true,
				AllowCTPoison:   true,
				AllowSCTList:    true,
				AllowCommonName: true,
				Policies: []issuance.PolicyInformation{
					{OID: "2.23.140.1.2.1"},
				},
				MaxValidityPeriod:   cmd.ConfigDuration{Duration: time.Hour * 8760},
				MaxValidityBackdate: cmd.ConfigDuration{Duration: time.Hour},
			},
			issuance.IssuerConfig{
				UseForECDSALeaves: ecdsa,
				UseForRSALeaves:   rsa,
				IssuerURL:         "http://not-example.com/issuer-url",
				OCSPURL:           "http://not-example.com/ocsp",
				CRLURL:            "http://not-example.com/crl",
			},
		)
		return res
	}
	boulderIssuers := []*issuance.Issuer{
		// Must list ECDSA-only issuer first, so it is the default for ECDSA.
		{
			Cert:    caCert2,
			Signer:  caKey,
			Profile: boulderProfile(false, true),
			Linter:  caLinter2,
			Clk:     fc,
		},
		{
			Cert:    caCert,
			Signer:  caKey,
			Profile: boulderProfile(true, true),
			Linter:  caLinter,
			Clk:     fc,
		},
	}

	keyPolicy := goodkey.KeyPolicy{
		AllowRSA:           true,
		AllowECDSANISTP256: true,
		AllowECDSANISTP384: true,
	}
	signatureCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signatures",
			Help: "Number of signatures",
		},
		[]string{"purpose", "issuer"})
	signErrorCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "signature_errors",
		Help: "A counter of signature errors labelled by error type",
	}, []string{"type"})

	ocsp, err := NewOCSPImpl(
		boulderIssuers,
		time.Hour,
		0,
		time.Second,
		blog.NewMock(),
		metrics.NoopRegisterer,
		signatureCount,
		signErrorCount,
		fc,
	)
	test.AssertNotError(t, err, "Failed to create ocsp impl")

	crl, err := NewCRLImpl(
		boulderIssuers,
		time.Hour,
		blog.NewMock(),
	)
	test.AssertNotError(t, err, "Failed to create crl impl")

	return &testCtx{
		pa:             pa,
		ocsp:           ocsp,
		crl:            crl,
		certExpiry:     8760 * time.Hour,
		certBackdate:   time.Hour,
		serialPrefix:   17,
		maxNames:       2,
		boulderIssuers: boulderIssuers,
		keyPolicy:      keyPolicy,
		fc:             fc,
		stats:          metrics.NoopRegisterer,
		signatureCount: signatureCount,
		signErrorCount: signErrorCount,
		logger:         blog.NewMock(),
	}
}

func TestFailNoSerialPrefix(t *testing.T) {
	testCtx := setup(t)

	_, err := NewCertificateAuthorityImpl(
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		testCtx.certExpiry,
		testCtx.certBackdate,
		0,
		testCtx.maxNames,
		testCtx.keyPolicy,
		nil,
		testCtx.logger,
		testCtx.stats,
		nil,
		nil,
		testCtx.fc)
	test.AssertError(t, err, "CA should have failed with no SerialPrefix")
}

type TestCertificateIssuance struct {
	ca      *certificateAuthorityImpl
	sa      *mockSA
	req     *x509.CertificateRequest
	certDER []byte
	cert    *x509.Certificate
}

func TestIssuePrecertificate(t *testing.T) {
	testCases := []struct {
		name    string
		csr     []byte
		subTest func(t *testing.T, i *TestCertificateIssuance)
	}{
		{"IssuePrecertificate", CNandSANCSR, issueCertificateSubTestIssuePrecertificate},
		{"ValidityUsesCAClock", CNandSANCSR, issueCertificateSubTestValidityUsesCAClock},
		{"ProfileSelectionRSA", CNandSANCSR, issueCertificateSubTestProfileSelectionRSA},
		{"ProfileSelectionECDSA", ECDSACSR, issueCertificateSubTestProfileSelectionECDSA},
		{"MustStaple", MustStapleCSR, issueCertificateSubTestMustStaple},
		{"MustStapleDuplicate", DuplicateMustStapleCSR, issueCertificateSubTestMustStaple},
		{"UnknownExtension", UnsupportedExtensionCSR, issueCertificateSubTestUnknownExtension},
		{"CTPoisonExtension", CTPoisonExtensionCSR, issueCertificateSubTestCTPoisonExtension},
		{"CTPoisonExtensionEmpty", CTPoisonExtensionEmptyCSR, issueCertificateSubTestCTPoisonExtension},
	}

	for _, testCase := range testCases {
		// The loop through the issuance modes must be inside the loop through
		// |testCases| because the "certificate-for-precertificate" tests use
		// the precertificates previously generated from the preceding
		// "precertificate" test.
		for _, mode := range []string{"precertificate", "certificate-for-precertificate"} {
			ca, sa := issueCertificateSubTestSetup(t)

			t.Run(fmt.Sprintf("%s - %s", mode, testCase.name), func(t *testing.T) {
				req, err := x509.ParseCertificateRequest(testCase.csr)
				test.AssertNotError(t, err, "Certificate request failed to parse")

				issueReq := &capb.IssueCertificateRequest{Csr: testCase.csr, RegistrationID: arbitraryRegID}

				var certDER []byte
				response, err := ca.IssuePrecertificate(ctx, issueReq)

				test.AssertNotError(t, err, "Failed to issue precertificate")
				certDER = response.DER

				cert, err := x509.ParseCertificate(certDER)
				test.AssertNotError(t, err, "Certificate failed to parse")

				poisonExtension := findExtension(cert.Extensions, OIDExtensionCTPoison)
				test.AssertEquals(t, true, poisonExtension != nil)
				if poisonExtension != nil {
					test.AssertEquals(t, poisonExtension.Critical, true)
					test.AssertDeepEquals(t, poisonExtension.Value, []byte{0x05, 0x00}) // ASN.1 DER NULL
				}

				i := TestCertificateIssuance{
					ca:      ca,
					sa:      sa,
					req:     req,
					certDER: certDER,
					cert:    cert,
				}

				testCase.subTest(t, &i)
			})
		}
	}
}

func makeECDSAAllowListBytes(regID int64) []byte {
	regIDBytes := []byte(fmt.Sprintf("%d", regID))
	contents := []byte(`
- `)
	return append(contents, regIDBytes...)
}

func issueCertificateSubTestSetup(t *testing.T) (*certificateAuthorityImpl, *mockSA) {
	testCtx := setup(t)
	sa := &mockSA{}
	ca, err := NewCertificateAuthorityImpl(
		sa,
		testCtx.pa,
		testCtx.ocsp,
		testCtx.crl,
		testCtx.boulderIssuers,
		&ECDSAAllowList{},
		testCtx.certExpiry,
		testCtx.certBackdate,
		testCtx.serialPrefix,
		testCtx.maxNames,
		testCtx.keyPolicy,
		nil,
		testCtx.logger,
		testCtx.stats,
		testCtx.signatureCount,
		testCtx.signErrorCount,
		testCtx.fc)
	test.AssertNotError(t, err, "Failed to create CA")
	return ca, sa
}

func issueCertificateSubTestIssuePrecertificate(t *testing.T, i *TestCertificateIssuance) {
	cert := i.cert

	test.AssertEquals(t, cert.Subject.CommonName, "not-example.com")

	if len(cert.DNSNames) == 1 {
		if cert.DNSNames[0] != "not-example.com" {
			t.Errorf("Improper list of domain names %v", cert.DNSNames)
		}
		t.Errorf("Improper list of domain names %v", cert.DNSNames)
	}

	if len(cert.Subject.Country) > 0 {
		t.Errorf("Subject contained unauthorized values: %v", cert.Subject)
	}
}

func issueCertificateSubTestValidityUsesCAClock(t *testing.T, i *TestCertificateIssuance) {
	test.AssertEquals(t, i.cert.NotBefore, i.ca.clk.Now().Add(-1*i.ca.backdate))
	test.AssertEquals(t, i.cert.NotAfter.Add(time.Second).Sub(i.cert.NotBefore), i.ca.validityPeriod)
}

// Test issuing when multiple issuers are present.
func TestMultipleIssuers(t *testing.T) {
	testCtx := setup(t)
	sa := &mockSA{}
	ca, err := NewCertificateAuthorityImpl(
		sa,
		testCtx.pa,
		testCtx.ocsp,
		testCtx.crl,
		testCtx.boulderIssuers,
		nil,
		testCtx.certExpiry,
		testCtx.certBackdate,
		testCtx.serialPrefix,
		testCtx.maxNames,
		testCtx.keyPolicy,
		nil,
		testCtx.logger,
		testCtx.stats,
		testCtx.signatureCount,
		testCtx.signErrorCount,
		testCtx.fc)
	test.AssertNotError(t, err, "Failed to remake CA")

	// Test that an RSA CSR gets issuance from the RSA issuer, caCert.
	issuedCert, err := ca.IssuePrecertificate(ctx, &capb.IssueCertificateRequest{Csr: CNandSANCSR, RegistrationID: arbitraryRegID})
	test.AssertNotError(t, err, "Failed to issue certificate")
	cert, err := x509.ParseCertificate(issuedCert.DER)
	test.AssertNotError(t, err, "Certificate failed to parse")
	err = cert.CheckSignatureFrom(caCert2.Certificate)
	test.AssertNotError(t, err, "Certificate failed signature validation")

	// Test that an ECDSA CSR gets issuance from the ECDSA issuer, caCert2.
	issuedCert, err = ca.IssuePrecertificate(ctx, &capb.IssueCertificateRequest{Csr: ECDSACSR, RegistrationID: arbitraryRegID})
	test.AssertNotError(t, err, "Failed to issue certificate")
	cert, err = x509.ParseCertificate(issuedCert.DER)
	test.AssertNotError(t, err, "Certificate failed to parse")
	err = cert.CheckSignatureFrom(caCert2.Certificate)
	test.AssertNotError(t, err, "Certificate failed signature validation")
}

func TestECDSAAllowList(t *testing.T) {
	req := &capb.IssueCertificateRequest{Csr: ECDSACSR, RegistrationID: arbitraryRegID}

	// With allowlist containing arbitraryRegID, issuance should come from ECDSA issuer.
	ca, _ := issueCertificateSubTestSetup(t)
	contents := makeECDSAAllowListBytes(arbitraryRegID)
	err := ca.ecdsaAllowList.Update(contents)
	if err != nil {
		t.Errorf("%s %s", yamlLoadErrMsg, err)
		t.FailNow()
	}
	result, err := ca.IssuePrecertificate(ctx, req)
	test.AssertNotError(t, err, "Failed to issue certificate")
	cert, err := x509.ParseCertificate(result.DER)
	test.AssertNotError(t, err, "Certificate failed to parse")
	test.AssertByteEquals(t, cert.RawIssuer, caCert2.RawSubject)

	// Attempts to update the allow list with malformed YAML should
	// fail, but the allowlist should still contain arbitraryRegID, so
	// issuance should come from ECDSA issuer
	malformed_yaml := []byte(`
)(\/=`)
	err = ca.ecdsaAllowList.Update(malformed_yaml)
	test.AssertError(t, err, "Update method accepted malformed YAML")
	result, err = ca.IssuePrecertificate(ctx, req)
	test.AssertNotError(t, err, "Failed to issue certificate after Update was called with malformed YAML")
	cert, err = x509.ParseCertificate(result.DER)
	test.AssertNotError(t, err, "Certificate failed to parse")
	test.AssertByteEquals(t, cert.RawIssuer, caCert2.RawSubject)

	// With allowlist not containing arbitraryRegID, issuance should fall back to RSA issuer.
	contents = makeECDSAAllowListBytes(int64(2002))
	err = ca.ecdsaAllowList.Update(contents)
	if err != nil {
		t.Errorf("%s %s", yamlLoadErrMsg, err)
		t.FailNow()
	}
	result, err = ca.IssuePrecertificate(ctx, req)
	test.AssertNotError(t, err, "Failed to issue certificate")
	cert, err = x509.ParseCertificate(result.DER)
	test.AssertNotError(t, err, "Certificate failed to parse")
	test.AssertByteEquals(t, cert.RawIssuer, caCert.RawSubject)

	// With empty allowlist but ECDSAForAll enabled, issuance should come from ECDSA issuer.
	ca, _ = issueCertificateSubTestSetup(t)
	_ = features.Set(map[string]bool{"ECDSAForAll": true})
	defer features.Reset()
	result, err = ca.IssuePrecertificate(ctx, req)
	test.AssertNotError(t, err, "Failed to issue certificate")
	cert, err = x509.ParseCertificate(result.DER)
	test.AssertNotError(t, err, "Certificate failed to parse")
	test.AssertByteEquals(t, cert.RawIssuer, caCert2.RawSubject)
}

func TestInvalidCSRs(t *testing.T) {
	testCases := []struct {
		name         string
		csrPath      string
		check        func(t *testing.T, ca *certificateAuthorityImpl, sa *mockSA)
		errorMessage string
		errorType    berrors.ErrorType
	}{
		// Test that the CA rejects CSRs that have no names.
		//
		// CSR generated by Go:
		// * Random RSA public key.
		// * CN = [none]
		// * DNSNames = [none]
		{"RejectNoHostnames", "./testdata/no_names.der.csr", nil, "Issued certificate with no names", berrors.BadCSR},

		// Test that the CA rejects CSRs that have too many names.
		//
		// CSR generated by Go:
		// * Random public key
		// * CN = [none]
		// * DNSNames = not-example.com, www.not-example.com, mail.example.com
		{"RejectTooManyHostnames", "./testdata/too_many_names.der.csr", nil, "Issued certificate with too many names", berrors.BadCSR},

		// Test that the CA rejects CSRs that have public keys that are too short.
		//
		// CSR generated by Go:
		// * Random public key -- 512 bits long
		// * CN = (none)
		// * DNSNames = not-example.com, www.not-example.com, mail.not-example.com
		{"RejectShortKey", "./testdata/short_key.der.csr", nil, "Issued a certificate with too short a key.", berrors.BadCSR},

		// CSR generated by Go:
		// * Random RSA public key.
		// * CN = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com
		// * DNSNames = [none]
		{"RejectLongCommonName", "./testdata/long_cn.der.csr", nil, "Issued a certificate with a CN over 64 bytes.", berrors.BadCSR},

		// CSR generated by OpenSSL:
		// Edited signature to become invalid.
		{"RejectWrongSignature", "./testdata/invalid_signature.der.csr", nil, "Issued a certificate based on a CSR with an invalid signature.", berrors.BadCSR},
	}

	for _, testCase := range testCases {
		testCtx := setup(t)
		sa := &mockSA{}
		ca, err := NewCertificateAuthorityImpl(
			sa,
			testCtx.pa,
			testCtx.ocsp,
			testCtx.crl,
			testCtx.boulderIssuers,
			nil,
			testCtx.certExpiry,
			testCtx.certBackdate,
			testCtx.serialPrefix,
			testCtx.maxNames,
			testCtx.keyPolicy,
			nil,
			testCtx.logger,
			testCtx.stats,
			testCtx.signatureCount,
			testCtx.signErrorCount,
			testCtx.fc)
		test.AssertNotError(t, err, "Failed to create CA")

		t.Run(testCase.name, func(t *testing.T) {
			serializedCSR := mustRead(testCase.csrPath)
			issueReq := &capb.IssueCertificateRequest{Csr: serializedCSR, RegistrationID: arbitraryRegID}
			_, err = ca.IssuePrecertificate(ctx, issueReq)

			test.AssertErrorIs(t, err, testCase.errorType)
			test.AssertMetricWithLabelsEquals(t, ca.signatureCount, prometheus.Labels{"purpose": "cert"}, 0)

			test.AssertError(t, err, testCase.errorMessage)
			if testCase.check != nil {
				testCase.check(t, ca, sa)
			}
		})
	}
}

func TestRejectValidityTooLong(t *testing.T) {
	testCtx := setup(t)
	sa := &mockSA{}
	ca, err := NewCertificateAuthorityImpl(
		sa,
		testCtx.pa,
		testCtx.ocsp,
		testCtx.crl,
		testCtx.boulderIssuers,
		nil,
		testCtx.certExpiry,
		testCtx.certBackdate,
		testCtx.serialPrefix,
		testCtx.maxNames,
		testCtx.keyPolicy,
		nil,
		testCtx.logger,
		testCtx.stats,
		nil,
		nil,
		testCtx.fc)
	test.AssertNotError(t, err, "Failed to create CA")

	// This time is a few minutes before the notAfter in testdata/ca_cert.pem
	future, err := time.Parse(time.RFC3339, "2025-02-10T00:30:00Z")

	test.AssertNotError(t, err, "Failed to parse time")
	testCtx.fc.Set(future)
	// Test that the CA rejects CSRs that would expire after the intermediate cert
	_, err = ca.IssuePrecertificate(ctx, &capb.IssueCertificateRequest{Csr: CNandSANCSR, RegistrationID: arbitraryRegID})
	test.AssertError(t, err, "Cannot issue a certificate that expires after the intermediate certificate")
	test.AssertErrorIs(t, err, berrors.InternalServer)
}

func issueCertificateSubTestProfileSelectionRSA(t *testing.T, i *TestCertificateIssuance) {
	// Certificates for RSA keys should be marked as usable for signatures and encryption.
	expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	t.Logf("expected key usage %v, got %v", expectedKeyUsage, i.cert.KeyUsage)
	test.AssertEquals(t, i.cert.KeyUsage, expectedKeyUsage)
}

func issueCertificateSubTestProfileSelectionECDSA(t *testing.T, i *TestCertificateIssuance) {
	// Certificates for ECDSA keys should be marked as usable for only signatures.
	expectedKeyUsage := x509.KeyUsageDigitalSignature
	t.Logf("expected key usage %v, got %v", expectedKeyUsage, i.cert.KeyUsage)
	test.AssertEquals(t, i.cert.KeyUsage, expectedKeyUsage)
}

func countMustStaple(t *testing.T, cert *x509.Certificate) (count int) {
	oidTLSFeature := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	mustStapleFeatureValue := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidTLSFeature) {
			test.Assert(t, !ext.Critical, "Extension was marked critical")
			test.AssertByteEquals(t, ext.Value, mustStapleFeatureValue)
			count++
		}
	}
	return count
}

func issueCertificateSubTestMustStaple(t *testing.T, i *TestCertificateIssuance) {
	test.AssertMetricWithLabelsEquals(t, i.ca.signatureCount, prometheus.Labels{"purpose": "precertificate"}, 1)
	test.AssertEquals(t, countMustStaple(t, i.cert), 1)
}

func issueCertificateSubTestUnknownExtension(t *testing.T, i *TestCertificateIssuance) {
	test.AssertMetricWithLabelsEquals(t, i.ca.signatureCount, prometheus.Labels{"purpose": "precertificate"}, 1)

	// NOTE: The hard-coded value here will have to change over time as Boulder
	// adds new (unrequested) extensions to certificates.
	expectedExtensionCount := 10
	test.AssertEquals(t, len(i.cert.Extensions), expectedExtensionCount)
}

func issueCertificateSubTestCTPoisonExtension(t *testing.T, i *TestCertificateIssuance) {
	test.AssertMetricWithLabelsEquals(t, i.ca.signatureCount, prometheus.Labels{"purpose": "precertificate"}, 1)
}

func findExtension(extensions []pkix.Extension, id asn1.ObjectIdentifier) *pkix.Extension {
	for _, ext := range extensions {
		if ext.Id.Equal(id) {
			return &ext
		}
	}
	return nil
}

func makeSCTs() ([][]byte, error) {
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: 0,
		Timestamp:  2020,
		Signature: ct.DigitallySigned{
			Signature: []byte{0},
		},
	}
	sctBytes, err := cttls.Marshal(sct)
	if err != nil {
		return nil, err
	}
	return [][]byte{sctBytes}, err
}

func TestIssueCertificateForPrecertificate(t *testing.T) {
	testCtx := setup(t)
	sa := &mockSA{}
	ca, err := NewCertificateAuthorityImpl(
		sa,
		testCtx.pa,
		testCtx.ocsp,
		testCtx.crl,
		testCtx.boulderIssuers,
		nil,
		testCtx.certExpiry,
		testCtx.certBackdate,
		testCtx.serialPrefix,
		testCtx.maxNames,
		testCtx.keyPolicy,
		nil,
		testCtx.logger,
		testCtx.stats,
		testCtx.signatureCount,
		testCtx.signErrorCount,
		testCtx.fc)
	test.AssertNotError(t, err, "Failed to create CA")

	issueReq := capb.IssueCertificateRequest{Csr: CNandSANCSR, RegistrationID: arbitraryRegID, OrderID: 0}
	precert, err := ca.IssuePrecertificate(ctx, &issueReq)
	test.AssertNotError(t, err, "Failed to issue precert")
	parsedPrecert, err := x509.ParseCertificate(precert.DER)
	test.AssertNotError(t, err, "Failed to parse precert")

	// Check for poison extension
	poisonExtension := findExtension(parsedPrecert.Extensions, OIDExtensionCTPoison)
	test.AssertNotNil(t, poisonExtension, "Couldn't find CTPoison extension")
	test.AssertEquals(t, poisonExtension.Critical, true)
	test.AssertDeepEquals(t, poisonExtension.Value, []byte{0x05, 0x00}) // ASN.1 DER NULL

	sctBytes, err := makeSCTs()
	if err != nil {
		t.Fatal(err)
	}

	test.AssertNotError(t, err, "Failed to marshal SCT")
	cert, err := ca.IssueCertificateForPrecertificate(ctx, &capb.IssueCertificateForPrecertificateRequest{
		DER:            precert.DER,
		SCTs:           sctBytes,
		RegistrationID: arbitraryRegID,
		OrderID:        0,
	})
	test.AssertNotError(t, err, "Failed to issue cert from precert")
	parsedCert, err := x509.ParseCertificate(cert.Der)
	test.AssertNotError(t, err, "Failed to parse cert")

	// Check for SCT list extension
	sctListExtension := findExtension(parsedCert.Extensions, OIDExtensionSCTList)
	test.AssertNotNil(t, sctListExtension, "Couldn't find SCTList extension")
	test.AssertEquals(t, sctListExtension.Critical, false)
	var rawValue []byte
	_, err = asn1.Unmarshal(sctListExtension.Value, &rawValue)
	test.AssertNotError(t, err, "Failed to unmarshal extension value")
	sctList, err := deserializeSCTList(rawValue)
	test.AssertNotError(t, err, "Failed to deserialize SCT list")
	test.Assert(t, len(sctList) == 1, fmt.Sprintf("Wrong number of SCTs, wanted: 1, got: %d", len(sctList)))
}

// deserializeSCTList deserializes a list of SCTs.
// Forked from github.com/cloudflare/cfssl/helpers
func deserializeSCTList(serializedSCTList []byte) ([]ct.SignedCertificateTimestamp, error) {
	var sctList ctx509.SignedCertificateTimestampList
	rest, err := cttls.Unmarshal(serializedSCTList, &sctList)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("serialized SCT list contained trailing garbage")
	}
	list := make([]ct.SignedCertificateTimestamp, len(sctList.SCTList))
	for i, serializedSCT := range sctList.SCTList {
		var sct ct.SignedCertificateTimestamp
		rest, err := cttls.Unmarshal(serializedSCT.Val, &sct)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("serialized SCT contained trailing garbage")
		}
		list[i] = sct
	}
	return list, nil
}

// dupeSA returns a non-error to GetCertificate in order to simulate a request
// to issue a final certificate with a duplicate serial.
type dupeSA struct {
	mockSA
}

func (m *dupeSA) GetCertificate(ctx context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*corepb.Certificate, error) {
	return nil, nil
}

// getCertErrorSA always returns an error for GetCertificate
type getCertErrorSA struct {
	mockSA
}

func (m *getCertErrorSA) GetCertificate(ctx context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*corepb.Certificate, error) {
	return nil, fmt.Errorf("i don't like it")
}

func TestIssueCertificateForPrecertificateDuplicateSerial(t *testing.T) {
	testCtx := setup(t)
	sa := &dupeSA{}
	ca, err := NewCertificateAuthorityImpl(
		sa,
		testCtx.pa,
		testCtx.ocsp,
		testCtx.crl,
		testCtx.boulderIssuers,
		nil,
		testCtx.certExpiry,
		testCtx.certBackdate,
		testCtx.serialPrefix,
		testCtx.maxNames,
		testCtx.keyPolicy,
		nil,
		testCtx.logger,
		testCtx.stats,
		testCtx.signatureCount,
		testCtx.signErrorCount,
		testCtx.fc)
	test.AssertNotError(t, err, "Failed to create CA")

	sctBytes, err := makeSCTs()
	if err != nil {
		t.Fatal(err)
	}

	issueReq := capb.IssueCertificateRequest{Csr: CNandSANCSR, RegistrationID: arbitraryRegID, OrderID: 0}
	precert, err := ca.IssuePrecertificate(ctx, &issueReq)
	test.AssertNotError(t, err, "Failed to issue precert")
	_, err = ca.IssueCertificateForPrecertificate(ctx, &capb.IssueCertificateForPrecertificateRequest{
		DER:            precert.DER,
		SCTs:           sctBytes,
		RegistrationID: arbitraryRegID,
		OrderID:        0,
	})
	if err == nil {
		t.Error("Expected error issuing duplicate serial but got none.")
	}
	if !strings.Contains(err.Error(), "issuance of duplicate final certificate requested") {
		t.Errorf("Wrong type of error issuing duplicate serial. Expected 'issuance of duplicate', got '%s'", err)
	}

	// Now check what happens if there is an error (e.g. timeout) while checking
	// for the duplicate.
	errorsa := &getCertErrorSA{}
	errorca, err := NewCertificateAuthorityImpl(
		errorsa,
		testCtx.pa,
		testCtx.ocsp,
		testCtx.crl,
		testCtx.boulderIssuers,
		nil,
		testCtx.certExpiry,
		testCtx.certBackdate,
		testCtx.serialPrefix,
		testCtx.maxNames,
		testCtx.keyPolicy,
		nil,
		testCtx.logger,
		testCtx.stats,
		testCtx.signatureCount,
		testCtx.signErrorCount,
		testCtx.fc)
	test.AssertNotError(t, err, "Failed to create CA")

	_, err = errorca.IssueCertificateForPrecertificate(ctx, &capb.IssueCertificateForPrecertificateRequest{
		DER:            precert.DER,
		SCTs:           sctBytes,
		RegistrationID: arbitraryRegID,
		OrderID:        0,
	})
	if err == nil {
		t.Fatal("Expected error issuing duplicate serial but got none.")
	}
	if !strings.Contains(err.Error(), "error checking for duplicate") {
		t.Fatalf("Wrong type of error issuing duplicate serial. Expected 'error checking for duplicate', got '%s'", err)
	}
}

type queueSA struct {
	mockSA

	fail      bool
	duplicate bool

	issued        time.Time
	issuedPrecert time.Time
}

func (qsa *queueSA) AddCertificate(_ context.Context, req *sapb.AddCertificateRequest, _ ...grpc.CallOption) (*sapb.AddCertificateResponse, error) {
	if qsa.fail {
		return nil, errors.New("bad")
	} else if qsa.duplicate {
		return nil, berrors.DuplicateError("is a dupe")
	}
	qsa.issued = time.Unix(0, req.Issued).UTC()
	return nil, nil
}

func (qsa *queueSA) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	if qsa.fail {
		return nil, errors.New("bad")
	} else if qsa.duplicate {
		return nil, berrors.DuplicateError("is a dupe")
	}
	qsa.issuedPrecert = time.Unix(0, req.Issued).UTC()
	return nil, nil
}

// TestPrecertOrphanQueue tests that IssuePrecertificate writes precertificates
// to the orphan queue if storage fails, and that `integrateOrphan` later
// successfully writes those precertificates to the database. To do this, it
// uses the `queueSA` mock, which allows us to flip on and off a "fail" bit that
// decides whether it errors in response to storage requests.
func TestPrecertOrphanQueue(t *testing.T) {
	tmpDir := t.TempDir()
	orphanQueue, err := goque.OpenQueue(tmpDir)
	test.AssertNotError(t, err, "Failed to open orphaned certificate queue")

	qsa := &queueSA{fail: true}
	testCtx := setup(t)
	fakeNow := time.Date(2019, 9, 20, 0, 0, 0, 0, time.UTC)
	testCtx.fc.Set(fakeNow)
	ca, err := NewCertificateAuthorityImpl(
		qsa,
		testCtx.pa,
		testCtx.ocsp,
		testCtx.crl,
		testCtx.boulderIssuers,
		nil,
		testCtx.certExpiry,
		testCtx.certBackdate,
		testCtx.serialPrefix,
		testCtx.maxNames,
		testCtx.keyPolicy,
		orphanQueue,
		testCtx.logger,
		testCtx.stats,
		testCtx.signatureCount,
		testCtx.signErrorCount,
		testCtx.fc)
	test.AssertNotError(t, err, "Failed to create CA")

	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}

	_, err = ca.IssuePrecertificate(context.Background(), &capb.IssueCertificateRequest{
		RegistrationID: 1,
		OrderID:        1,
		Csr:            CNandSANCSR,
	})
	test.AssertError(t, err, "Expected IssuePrecertificate to fail with `qsa.fail = true`")

	matches := testCtx.logger.GetAllMatching(`orphaning precertificate.* regID=\[1\], orderID=\[1\]`)
	if len(matches) != 1 {
		t.Errorf("no log line, or incorrect log line for orphaned precertificate:\n%s",
			strings.Join(testCtx.logger.GetAllMatching(".*"), "\n"))
	}

	test.AssertMetricWithLabelsEquals(
		t, ca.orphanCount, prometheus.Labels{"type": "precert"}, 1)

	qsa.fail = false
	err = ca.integrateOrphan()
	test.AssertNotError(t, err, "integrateOrphan failed")
	if !qsa.issuedPrecert.Equal(fakeNow) {
		t.Errorf("expected issued time to be %s, got %s", fakeNow, qsa.issuedPrecert)
	}
	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}

	test.AssertMetricWithLabelsEquals(
		t, ca.adoptedOrphanCount, prometheus.Labels{"type": "precert"}, 1)
}

func TestOrphanQueue(t *testing.T) {
	tmpDir := t.TempDir()
	orphanQueue, err := goque.OpenQueue(tmpDir)
	test.AssertNotError(t, err, "Failed to open orphaned certificate queue")

	qsa := &queueSA{fail: true}
	testCtx := setup(t)
	fakeNow, err := time.Parse("Mon Jan 2 15:04:05 2006", "Mon Jan 2 15:04:05 2006")
	if err != nil {
		t.Fatal(err)
	}
	testCtx.fc.Set(fakeNow)
	ca, err := NewCertificateAuthorityImpl(
		qsa,
		testCtx.pa,
		testCtx.ocsp,
		testCtx.crl,
		testCtx.boulderIssuers,
		nil,
		testCtx.certExpiry,
		testCtx.certBackdate,
		testCtx.serialPrefix,
		testCtx.maxNames,
		testCtx.keyPolicy,
		orphanQueue,
		testCtx.logger,
		testCtx.stats,
		nil,
		nil,
		testCtx.fc)
	test.AssertNotError(t, err, "Failed to create CA")

	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}

	// generate basic test cert
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Failed to generate test key")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"test.invalid"},
		NotBefore:    fakeNow.Add(-time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	test.AssertNotError(t, err, "Failed to generate test cert")
	err = ca.storeCertificate(
		context.Background(),
		1,
		1,
		tmpl.SerialNumber,
		certDER,
		1,
	)
	test.AssertError(t, err, "storeCertificate didn't fail when AddCertificate failed")

	qsa.fail = false
	err = ca.integrateOrphan()
	test.AssertNotError(t, err, "integrateOrphan failed")
	if !qsa.issued.Equal(fakeNow) {
		t.Errorf("expected issued time to be %s, got %s", fakeNow, qsa.issued)
	}
	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}

	// test with a duplicate cert
	ca.queueOrphan(&orphanedCert{
		DER:      certDER,
		OCSPResp: []byte{},
		RegID:    1,
	})

	qsa.duplicate = true
	err = ca.integrateOrphan()
	test.AssertNotError(t, err, "integrateOrphan failed with duplicate cert")
	if !qsa.issued.Equal(fakeNow) {
		t.Errorf("expected issued time to be %s, got %s", fakeNow, qsa.issued)
	}
	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}

	// add cert to queue, and recreate queue to make sure it still has the cert
	qsa.fail = true
	qsa.duplicate = false
	err = ca.storeCertificate(
		context.Background(),
		1,
		1,
		tmpl.SerialNumber,
		certDER,
		1,
	)
	test.AssertError(t, err, "storeCertificate didn't fail when AddCertificate failed")
	err = orphanQueue.Close()
	test.AssertNotError(t, err, "Failed to close the queue cleanly")
	orphanQueue, err = goque.OpenQueue(tmpDir)
	test.AssertNotError(t, err, "Failed to open orphaned certificate queue")
	defer func() { _ = orphanQueue.Close() }()
	ca.orphanQueue = orphanQueue

	qsa.fail = false
	err = ca.integrateOrphan()
	test.AssertNotError(t, err, "integrateOrphan failed")
	if !qsa.issued.Equal(fakeNow) {
		t.Errorf("expected issued time to be %s, got %s", fakeNow, qsa.issued)
	}
	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}
}
