package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/GWBailang553/web-ssh/internal/config"
	"github.com/GWBailang553/web-ssh/internal/server"
	"github.com/GWBailang553/web-ssh/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "web-ssh:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "cert-renew" {
		return renewCertificate(os.Args[2:])
	}

	cfg, err := config.Default()
	if err != nil {
		return err
	}
	if err := config.EnvironmentOverrides(&cfg); err != nil {
		return err
	}

	flags := flag.NewFlagSet("web-ssh", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	listen := flags.String("listen", cfg.Listen, "HTTPS listen address")
	databasePath := flags.String("database", cfg.DatabasePath, "database path")
	certificate := flags.String("cert", cfg.Certificate, "TLS certificate path")
	privateKey := flags.String("key", cfg.PrivateKey, "TLS private key path")
	maxTerminals := flags.Int("max-terminals", cfg.MaxTerminals, "maximum concurrent terminals per account")
	version := flags.Bool("version", false, "print version")
	hosts := flags.String("host", "", "comma-separated certificate hostname or IP")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *version {
		fmt.Println(config.Version)
		return nil
	}
	cfg.Listen = *listen
	cfg.DatabasePath = *databasePath
	cfg.Certificate = *certificate
	cfg.PrivateKey = *privateKey
	cfg.MaxTerminals = *maxTerminals
	if err := cfg.Validate(); err != nil {
		return err
	}

	if err := ensureCertificate(cfg.Certificate, cfg.PrivateKey, splitHosts(*hosts)); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	database, err := store.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()

	application := server.New(cfg, database, logger)
	serverInstance := &http.Server{
		Addr:         cfg.Listen,
		Handler:      application.HTTPHandler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  90 * time.Second,
		TLSConfig:    secureTLSConfig(),
	}

	pruneContext, stopPrune := context.WithCancel(context.Background())
	defer stopPrune()
	go runPruner(pruneContext, application)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("web-ssh listening", "address", cfg.Listen, "version", config.Version)
		serverErrors <- serverInstance.ListenAndServeTLS(cfg.Certificate, cfg.PrivateKey)
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case signalValue := <-shutdown:
		logger.Info("shutdown requested", "signal", signalValue.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return serverInstance.Shutdown(ctx)
	}
}

func renewCertificate(args []string) error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("web-ssh cert-renew", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	certificate := flags.String("cert", cfg.Certificate, "TLS certificate path")
	privateKey := flags.String("key", cfg.PrivateKey, "TLS private key path")
	hosts := flags.String("host", "", "comma-separated certificate hostname or IP")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return renewCertificateIfNeeded(*certificate, *privateKey, splitHosts(*hosts), 365*24*time.Hour)
}

func ensureCertificate(certificatePath, keyPath string, hosts []string) error {
	return renewCertificateIfNeeded(certificatePath, keyPath, hosts, 365*24*time.Hour)
}

func renewCertificateIfNeeded(certificatePath, keyPath string, hosts []string, lifetime time.Duration) error {
	certificatePEM, certificateErr := os.ReadFile(certificatePath)
	keyInfo, keyErr := os.Stat(keyPath)
	if certificateErr == nil && keyErr == nil && keyInfo.Mode().IsRegular() {
		block, _ := pem.Decode(certificatePEM)
		if block != nil {
			certificate, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr == nil && certificate.NotAfter.After(time.Now().Add(30*24*time.Hour)) {
				return nil
			}
		}
	}
	return generateCertificate(certificatePath, keyPath, hosts, lifetime)
}

func generateCertificate(certificatePath, keyPath string, hosts []string, lifetime time.Duration) error {
	if err := os.MkdirAll(filepath.Dir(certificatePath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate TLS key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate certificate serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "web-ssh"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	template.DNSNames, template.IPAddresses = certificateNames(hosts)
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create TLS certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal TLS key: %w", err)
	}
	if err := writePEM(certificatePath, 0o600, "CERTIFICATE", certificateDER); err != nil {
		return err
	}
	return writePEM(keyPath, 0o600, "PRIVATE KEY", keyDER)
}

func writePEM(path string, mode os.FileMode, blockType string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return file.Sync()
}

func certificateNames(hosts []string) ([]string, []net.IP) {
	dnsNames := map[string]struct{}{"localhost": {}, "web-ssh": {}}
	addresses := map[string]net.IP{
		"127.0.0.1": net.ParseIP("127.0.0.1"),
		"::1":       net.ParseIP("::1"),
	}
	if hostname, err := os.Hostname(); err == nil {
		dnsNames[hostname] = struct{}{}
	}
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if address := net.ParseIP(host); address != nil {
			addresses[address.String()] = address
			continue
		}
		dnsNames[strings.ToLower(host)] = struct{}{}
	}
	dnsResult := make([]string, 0, len(dnsNames))
	for name := range dnsNames {
		dnsResult = append(dnsResult, name)
	}
	ipResult := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ipResult = append(ipResult, address)
	}
	return dnsResult, ipResult
}

func splitHosts(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func runPruner(ctx context.Context, application *server.Server) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		application.Prune()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func secureTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
}
