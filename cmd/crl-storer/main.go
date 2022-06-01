package notmain

import (
	"context"
	"flag"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awsl "github.com/aws/smithy-go/logging"
	"github.com/honeycombio/beeline-go"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/crl/storer"
	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
)

type Config struct {
	CRLStorer struct {
		cmd.ServiceConfig

		// IssuerCerts is a list of paths to issuer certificates on disk. These will
		// be used to validate the CRLs received by this service before uploading
		// them.
		IssuerCerts []string

		// S3Region is the AWS Region (e.g. us-west-1) that uploads should go to.
		S3Region string
		// S3Bucket is the AWS Bucket that uploads should go to. Must be created
		// (and have appropriate permissions set) beforehand.
		S3Bucket string
		// S3AccessKeyID is the AWS access key ID (aka username). See
		// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws#Credentials.
		S3AccessKeyID string
		// S3SecretAccessKey is the secret key (aka password). See
		// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws#Credentials.
		S3SecretAccessKey string

		Features map[string]bool
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

// awsLogger implements the github.com/aws/smithy-go/logging.Logger interface.
type awsLogger struct {
	blog.Logger
}

func (log awsLogger) Logf(c awsl.Classification, format string, v ...interface{}) {
	switch c {
	case awsl.Debug:
		log.Debugf(format, v...)
	case awsl.Warn:
		log.Warningf(format, v...)
	}
}

// awsCreds implements the aws.CredentialsProvider interface.
type awsCreds struct {
	accessKeyId     string
	secretAccessKey string
}

func (c awsCreds) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     c.accessKeyId,
		SecretAccessKey: c.secretAccessKey,
	}, nil
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.CRLStorer.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	tlsConfig, err := c.CRLStorer.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.CRLStorer.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())
	clk := cmd.Clock()

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	issuers := make([]*issuance.Certificate, 0, len(c.CRLStorer.IssuerCerts))
	for _, filepath := range c.CRLStorer.IssuerCerts {
		cert, err := issuance.LoadCertificate(filepath)
		cmd.FailOnError(err, "Failed to load issuer cert")
		issuers = append(issuers, cert)
	}

	s3client := s3.New(s3.Options{
		Region:     c.CRLStorer.S3Region,
		HTTPClient: new(http.Client),
		Credentials: credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     c.CRLStorer.S3AccessKeyID,
				SecretAccessKey: c.CRLStorer.S3SecretAccessKey,
			},
		},
		Logger:        awsLogger{logger},
		ClientLogMode: aws.LogRequestEventMessage | aws.LogResponseEventMessage,
	})

	csi, err := storer.New(issuers, s3client, scope, logger, clk)
	cmd.FailOnError(err, "Failed to create OCSP impl")

	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, listener, err := bgrpc.NewServer(c.CRLStorer.GRPC, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup CRLStorer gRPC server")
	cspb.RegisterCRLStorerServer(grpcSrv, csi)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, hs)

	go cmd.CatchSignals(logger, func() {
		hs.Shutdown()
		grpcSrv.GracefulStop()
	})

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(listener))
	cmd.FailOnError(err, "CRLStorer gRPC service failed")
}

func init() {
	cmd.RegisterCommand("crl-storer", main)
}
