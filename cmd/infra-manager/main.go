package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"infra-manager/internal/remote"
	"infra-manager/internal/store"
	"infra-manager/internal/web"
	webassets "infra-manager/web"
)

// Version is printed by `version` and in the log at start. A build can stamp it
// with -ldflags "-X main.Version=0.1.0".
var Version = "dev"

const (
	// Where the dashboard keeps everything, and where it listens. They are the
	// values the systemd unit uses, so `serve` with no flags is the installed one.
	defaultData   = "/var/lib/infra-manager"
	defaultListen = "127.0.0.1:8095"
)

const usage = `infra manager: manage hosts, Ansible and Terraform from a web page.

Usage:
  infra-manager serve [-data DIR] [-listen ADDR]   run the dashboard
  infra-manager service install [-listen ADDR]     install and start the systemd service (Linux, root)
  infra-manager service uninstall                  stop and remove the service
  infra-manager user create --admin [-data DIR] NAME   create the first admin (asks for the password)
  infra-manager user totp-reset [-data DIR] NAME       reset a user's authenticator and end their sessions
  infra-manager version

Defaults: -data ` + defaultData + `  -listen ` + defaultListen + `
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "service":
		err = service(os.Args[2:])
	case "user":
		err = userCommand(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(Version)
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "infra-manager: %v\n", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := flags.String("data", defaultData, "the folder for the database, keys and secrets")
	listen := flags.String("listen", defaultListen, "address to listen on, as ip:port")
	flags.Parse(args) // ExitOnError: a bad flag prints the usage and stops

	loopback, err := checkListen(*listen)
	if err != nil {
		return err
	}

	warning, err := store.PrepareDir(*dataDir)
	if err != nil {
		return err
	}
	if warning != "" {
		slog.Warn(warning)
	}
	db, err := store.OpenDB(filepath.Join(*dataDir, store.DBFile))
	if err != nil {
		return err
	}
	defer db.Close()

	// The dashboard's own SSH key (made on the first start) and the host keys it
	// trusts, both under <data>/keys.
	rem, err := remote.Open(*dataDir)
	if err != nil {
		return err
	}
	slog.Info("SSH key of the dashboard", "fingerprint", rem.Fingerprint(), "known_hosts", rem.KnownHostsPath())

	static, err := webassets.Static()
	if err != nil {
		return fmt.Errorf("load the web files: %w", err)
	}
	mux := http.NewServeMux()
	// No method in the pattern: "GET /" would clash with the "/api/" catch-all
	// (web.Static refuses other methods itself).
	mux.Handle("/", static)
	// Every /api route checks the session and the role (internal/web/server.go).
	app := web.NewServer(db, rem)
	app.Routes(mux)
	// The check every minute, until the program is told to stop.
	monitorCtx, stopMonitor := context.WithCancel(context.Background())
	defer stopMonitor()
	go app.RunMonitor(monitorCtx)

	if n, err := store.CountUsers(db); err == nil && n == 0 {
		slog.Warn("there are no users yet, so nobody can log in. Create the first admin with: infra-manager user create --admin NAME")
	}

	// Listen before saying so, so "address already in use" is the error, not a
	// log line that claims success.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           web.Secure(mux),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: a job that streams its log (an apply, later) can run
		// for minutes.
	}

	slog.Info("infra manager started", "version", Version, "listen", *listen, "data", *dataDir)
	if !loopback {
		slog.Warn("listening on an address other than this machine's own: the connection is not encrypted, so passwords and sessions would cross the network in clear text, " +
			"and the session cookie is marked Secure, so a browser will not keep it over plain HTTP. " +
			"Keep 127.0.0.1 and put Caddy in front (docs/deploy.md)")
	}

	failed := make(chan error, 1)
	go func() { failed <- srv.Serve(ln) }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-failed:
		return fmt.Errorf("server stopped: %w", err)
	case <-stop:
	}

	slog.Info("shutting down")
	stopMonitor()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}
