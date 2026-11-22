package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// What `service install` puts on the machine. The data directory name has to
// match StateDirectory in the unit, which systemd resolves under /var/lib.
const (
	serviceName = "infra-manager"
	serviceUser = "infra-manager"
	unitPath    = "/etc/systemd/system/infra-manager.service"
	binaryPath  = "/usr/local/bin/infra-manager"
	serviceData = "/var/lib/" + serviceName
)

func service(args []string) error {
	if len(args) == 0 {
		return errors.New("service needs install or uninstall")
	}
	switch args[0] {
	case "install":
		flags := flag.NewFlagSet("service install", flag.ExitOnError)
		listen := flags.String("listen", defaultListen, "address the service listens on, as ip:port")
		flags.Parse(args[1:])
		return installService(*listen)
	case "uninstall":
		return uninstallService()
	}
	return fmt.Errorf("unknown service command %q: use install or uninstall", args[0])
}

// unitFile is the systemd unit. The service runs as its own user, never root:
// it will hold the SSH key that opens every managed host, so a bug in it should
// reach as little as possible. The hardening lines are the ones headnode's unit
// uses (deploy/headnode.service); later milestones must check that what they
// add (ssh, ansible, terraform) still works under them.
func unitFile(binary, listen string) string {
	return fmt.Sprintf(`# infra manager, as a systemd service. Written by "infra-manager service install".
[Unit]
Description=infra manager (web dashboard for hosts, Ansible and Terraform)
After=network-online.target
Wants=network-online.target

[Service]
User=%[1]s
Group=%[1]s

# The dashboard listens on this machine only. Caddy, on the same machine, is the
# only way in from outside, and it brings the HTTPS (docs/deploy.md).
ExecStart=%[2]s serve -data %[3]s -listen %[4]s
Restart=on-failure
RestartSec=5

# The data folder holds the database, keys and secrets: private to the user above.
# UMask makes every file the service creates private as well.
StateDirectory=%[1]s
StateDirectoryMode=0700
UMask=0077

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
`, serviceUser, binary, serviceData, listen)
}

func installService(listen string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("the service is a systemd unit, so it can only be installed on Linux (this is %s)", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("this needs root: run it with sudo")
	}
	loopback, err := checkListen(listen)
	if err != nil {
		return err
	}
	if !loopback {
		fmt.Println("warning: this is not a local address. Plain HTTP exposes passwords and sessions on the network, and Secure session cookies require HTTPS. Use 127.0.0.1 and Caddy.")
	}

	fmt.Printf(">>> User %s\n", serviceUser)
	uid, gid, err := ensureUser()
	if err != nil {
		return err
	}

	// The installer, being root, sets the folder up itself. systemd would create
	// it from StateDirectory too, but only the installer fixes a folder that
	// already exists with the wrong owner (a test run of `serve` as root, say),
	// and a database the service user cannot open is a confusing failure.
	fmt.Printf(">>> Data folder %s (0700, owned by %s)\n", serviceData, serviceUser)
	if err := os.MkdirAll(serviceData, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", serviceData, err)
	}
	if err := os.Chmod(serviceData, 0o700); err != nil {
		return fmt.Errorf("set %s to 0700: %w", serviceData, err)
	}
	if err := chownAll(serviceData, uid, gid); err != nil {
		return fmt.Errorf("give %s to %s: %w", serviceData, serviceUser, err)
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this program: %w", err)
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return fmt.Errorf("resolve the path of this program: %w", err)
	}
	fmt.Printf(">>> Program %s\n", binaryPath)
	if err := installBinary(self, binaryPath); err != nil {
		return err
	}

	fmt.Printf(">>> Unit %s\n", unitPath)
	if err := os.WriteFile(unitPath, []byte(unitFile(binaryPath, listen)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", unitPath, err)
	}
	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := runCmd("systemctl", "enable", serviceName); err != nil {
		return err
	}
	// restart, not "enable --now": that does nothing to a service that already
	// runs, so an upgrade would keep running the old program.
	if err := runCmd("systemctl", "restart", serviceName); err != nil {
		return err
	}

	// "restart" returns as soon as the process is started, so a program that
	// dies on its first lines (the port is taken, say) would look like success.
	time.Sleep(2 * time.Second)
	if err := exec.Command("systemctl", "is-active", "--quiet", serviceName).Run(); err != nil {
		return fmt.Errorf("the service did not stay up: see why with  journalctl -u %s -n 30", serviceName)
	}

	fmt.Println()
	fmt.Println("infra manager is running as a service.")
	fmt.Printf("  listens on : %s (this machine only)\n", listen)
	fmt.Printf("  status     : systemctl status %s\n", serviceName)
	fmt.Printf("  log        : journalctl -u %s -f\n", serviceName)
	fmt.Println("  next       : put Caddy in front for HTTPS (docs/deploy.md)")
	return nil
}

func uninstallService() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("the service is a systemd unit, so it only exists on Linux (this is %s)", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("this needs root: run it with sudo")
	}

	fmt.Printf(">>> Stopping %s\n", serviceName)
	// Each of these fails when the service is not there or not running, which
	// is fine: the goal is that it is gone, not that every step did something.
	_ = runCmd("systemctl", "stop", serviceName)
	_ = runCmd("systemctl", "disable", serviceName)
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", unitPath, err)
	}
	_ = runCmd("systemctl", "daemon-reload")
	_ = runCmd("systemctl", "reset-failed", serviceName)

	// The data is the part that cannot be made again (keys, secrets, history),
	// so removing it is the owner's own act.
	fmt.Println()
	fmt.Println("The service is removed. Left in place on purpose:")
	fmt.Printf("  the program : %s\n", binaryPath)
	fmt.Printf("  the data    : %s\n", serviceData)
	fmt.Printf("  the user    : %s\n", serviceUser)
	fmt.Println("To remove them too, by hand:")
	fmt.Printf("  sudo rm %s && sudo rm -r %s && sudo userdel %s\n", binaryPath, serviceData, serviceUser)
	return nil
}

// ensureUser finds the service user, creating it (a system account with no
// login shell and no password) when it is missing, and returns its ids.
func ensureUser() (uid, gid int, err error) {
	u, err := user.Lookup(serviceUser)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		// --no-create-home: the home is the data folder, which is set up next.
		if err := runCmd("useradd", "--system", "--user-group", "--no-create-home",
			"--home-dir", serviceData, "--shell", "/usr/sbin/nologin", serviceUser); err != nil {
			return 0, 0, err
		}
		u, err = user.Lookup(serviceUser)
	}
	if err != nil {
		return 0, 0, fmt.Errorf("look up the user %s: %w", serviceUser, err)
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return 0, 0, fmt.Errorf("user id %q is not a number", u.Uid)
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return 0, 0, fmt.Errorf("group id %q is not a number", u.Gid)
	}
	return uid, gid, nil
}

// chownAll gives a folder and everything in it to one owner.
func chownAll(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	})
}

// installBinary copies the running program to dst, unless it already is dst.
// It writes a new file and renames it into place: overwriting a program that is
// running (the service, on an upgrade) fails with "text file busy", while a
// rename just replaces the name.
func installBinary(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("look at %s: %w", src, err)
	}
	if dstInfo, err := os.Stat(dst); err == nil && os.SameFile(srcInfo, dstInfo) {
		return nil
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	defer in.Close()

	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("copy to %s: %w", tmp, err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("put the program at %s: %w", dst, err)
	}
	return nil
}

// runCmd runs a program with its arguments given one by one (never through a
// shell) and shows its output.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
