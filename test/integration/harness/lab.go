package harness

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// Lab holds disposable Docker resources for integration tests.
type Lab struct {
	Prefix     string
	cli        *client.Client
	Networks   []string
	Containers []string
}

func newDockerClient() (*client.Client, error) {
	return client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
}

// DaemonOK pings the Docker Engine API.
func DaemonOK(ctx context.Context) error {
	cli, err := newDockerClient()
	if err != nil {
		return err
	}
	defer cli.Close()
	_, err = cli.Ping(ctx)
	return err
}

// ImageExists checks that image ref is present on the daemon.
func ImageExists(ctx context.Context, ref string) error {
	cli, err := newDockerClient()
	if err != nil {
		return err
	}
	defer cli.Close()
	_, err = cli.ImageInspect(ctx, ref)
	return err
}

// NewLab connects to the Docker daemon and returns a lab with the given name prefix.
func NewLab(ctx context.Context, prefix string) (*Lab, error) {
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	if _, err := cli.Ping(ctx); err != nil {
		_ = cli.Close()
		return nil, err
	}
	return &Lab{Prefix: prefix, cli: cli}, nil
}

func (l *Lab) name(s string) string { return l.Prefix + "-" + s }

// NetOpts configures optional network properties. The zero value is IPv4-only,
// which is what every existing lab wants.
type NetOpts struct {
	// Subnet6 is a ULA subnet such as "fd00:10::/64". Empty leaves the network
	// IPv4-only.
	Subnet6 string
}

// CreateNetwork creates an internal bridge network (no host networking).
//
// The options are variadic so the seventeen existing IPv4 call sites keep both
// their spelling and their exact behaviour: EnableIPv6 stays nil rather than
// becoming an explicit false, so the request Docker receives is unchanged.
func (l *Lab) CreateNetwork(ctx context.Context, name, subnet string, opts ...NetOpts) error {
	n := l.name(name)
	cfg := []network.IPAMConfig{{Subnet: subnet}}
	var enable6 *bool
	if len(opts) > 0 && opts[0].Subnet6 != "" {
		cfg = append(cfg, network.IPAMConfig{Subnet: opts[0].Subnet6})
		yes := true
		enable6 = &yes
	}
	_, err := l.cli.NetworkCreate(ctx, n, network.CreateOptions{
		Driver:     "bridge",
		Internal:   true,
		EnableIPv6: enable6,
		IPAM:       &network.IPAM{Config: cfg},
	})
	if err != nil {
		return err
	}
	l.Networks = append(l.Networks, n)
	return nil
}

// RunOpts configures the container process. Zero value keeps sleep infinity.
type RunOpts struct {
	Entrypoint []string // nil → ["sleep"]
	Cmd        []string // nil → ["infinity"] when Entrypoint is nil
	// IP6 is the IPv6 address on the primary network. A non-empty value is
	// what enables IPv6 in the container -- there is deliberately no separate
	// boolean, because setting one without the other produces either a
	// container with IPv6 disabled and a v6 address Docker cannot assign, or a
	// silently v4-only node in a test that believes it is dual-stack.
	IP6 string
	// Extra6 maps an extraNetworks name to this container's IPv6 address there.
	Extra6 map[string]string
}

// RunContainer starts a privileged container with NET_ADMIN on the given network.
func (l *Lab) RunContainer(ctx context.Context, name, image, ip, netName string, extraNetworks map[string]string, opts ...RunOpts) error {
	cname := l.name(name)
	primaryNet := l.name(netName)

	entrypoint := []string{"sleep"}
	cmd := []string{"infinity"}
	var ip6 string
	extra6 := map[string]string{}
	if len(opts) > 0 {
		if opts[0].Entrypoint != nil {
			entrypoint = opts[0].Entrypoint
			cmd = opts[0].Cmd
		} else if opts[0].Cmd != nil {
			cmd = opts[0].Cmd
		}
		ip6 = opts[0].IP6
		if opts[0].Extra6 != nil {
			extra6 = opts[0].Extra6
		}
	}

	// IPv6 is disabled outright unless this node is meant to have it. The two
	// settings are mutually exclusive in practice: Docker applies sysctls
	// before configuring the endpoint, so disable_ipv6=1 makes assigning a
	// static v6 address fail.
	//
	// accept_dad=0 is not tuning. A freshly assigned IPv6 address stays
	// tentative for about a second while duplicate address detection runs, and
	// binding to a tentative address fails with EADDRNOTAVAIL -- a pure
	// timing flake that would get blamed on IPv6 rather than on the lab.
	sysctls := map[string]string{"net.ipv4.ip_forward": "1"}
	if ip6 != "" {
		sysctls["net.ipv6.conf.all.forwarding"] = "1"
		sysctls["net.ipv6.conf.all.accept_dad"] = "0"
		sysctls["net.ipv6.conf.default.accept_dad"] = "0"
	} else {
		sysctls["net.ipv6.conf.all.disable_ipv6"] = "1"
		sysctls["net.ipv6.conf.default.disable_ipv6"] = "1"
	}

	resp, err := l.cli.ContainerCreate(ctx,
		&container.Config{
			Image:      image,
			Entrypoint: entrypoint,
			Cmd:        cmd,
		},
		&container.HostConfig{
			Privileged:  true,
			AutoRemove:  true,
			Sysctls:     sysctls,
			NetworkMode: container.NetworkMode(primaryNet),
		},
		&network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				primaryNet: {
					IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: ip, IPv6Address: ip6},
				},
			},
		},
		nil,
		cname,
	)
	if err != nil {
		return err
	}
	if err := l.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		_ = l.cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return err
	}
	l.Containers = append(l.Containers, cname)

	for net, addr := range extraNetworks {
		ipam := &network.EndpointIPAMConfig{IPv4Address: addr}
		if a6 := extra6[net]; a6 != "" {
			ipam.IPv6Address = a6
		}
		err := l.cli.NetworkConnect(ctx, l.name(net), cname, &network.EndpointSettings{IPAMConfig: ipam})
		if err != nil {
			return err
		}
	}
	return nil
}

// WaitReadyV6 waits until addr is present, global-scope and out of duplicate
// address detection. Without it the IPv6 labs flake on DAD and the blame lands
// on IPv6 rather than on the harness.
func (l *Lab) WaitReadyV6(ctx context.Context, name, addr string) error {
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, err := l.Exec(ctx, name, "ip", "-o", "-6", "addr", "show", "scope", "global")
		if err == nil {
			last = out
			if strings.Contains(out, addr) && !strings.Contains(out, "tentative") {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%s: %s never became usable; last listing: %s", name, addr, last)
}

// SupportsIPv6Networks reports whether this daemon can create an internal IPv6
// network, so a machine without ip6tables says so up front rather than failing
// somewhere deep inside a topology.
func SupportsIPv6Networks(ctx context.Context) error {
	cli, err := newDockerClient()
	if err != nil {
		return err
	}
	defer cli.Close()
	name := fmt.Sprintf("gotun-v6probe-%d", time.Now().UnixNano()%1_000_000)
	yes := true
	_, err = cli.NetworkCreate(ctx, name, network.CreateOptions{
		Driver:     "bridge",
		Internal:   true,
		EnableIPv6: &yes,
		IPAM: &network.IPAM{Config: []network.IPAMConfig{
			{Subnet: "10.254.254.0/24"},
			{Subnet: "fd00:dead:beef::/64"},
		}},
	})
	if err != nil {
		return fmt.Errorf("this docker daemon cannot create an internal IPv6 network: %w", err)
	}
	_ = cli.NetworkRemove(ctx, name)
	return nil
}

// Exec runs a command inside a container and returns combined-looking stdout (stderr on failure).
func (l *Lab) Exec(ctx context.Context, name string, args ...string) (string, error) {
	cname := l.name(name)
	execID, err := l.cli.ContainerExecCreate(ctx, cname, container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          args,
	})
	if err != nil {
		return "", err
	}
	attach, err := l.cli.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{})
	if err != nil {
		return "", err
	}
	defer attach.Close()

	var stdout, stderr bytes.Buffer
	_, err = stdcopy.StdCopy(&stdout, &stderr, attach.Reader)
	if err != nil {
		return stdout.String(), err
	}
	inspect, err := l.cli.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return stdout.String(), err
	}
	out := strings.TrimSpace(stdout.String())
	if inspect.ExitCode != 0 {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = out
		}
		return out, fmt.Errorf("exec %v exit %d: %s", args, inspect.ExitCode, errMsg)
	}
	return out, nil
}

// ExecOK is Exec that ignores empty success.
func (l *Lab) ExecOK(ctx context.Context, name string, args ...string) error {
	_, err := l.Exec(ctx, name, args...)
	return err
}

// Copy copies a local file into the container at dst (absolute path including filename).
func (l *Lab) Copy(ctx context.Context, name, src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	base := filepath.Base(dst)
	dir := filepath.Dir(dst)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name: base,
		Mode: int64(fi.Mode().Perm()),
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return l.cli.CopyToContainer(ctx, l.name(name), dir, &buf, container.CopyToContainerOptions{})
}

// Close removes containers and networks and closes the API client.
func (l *Lab) Close(ctx context.Context) {
	if l == nil || l.cli == nil {
		return
	}
	for i := len(l.Containers) - 1; i >= 0; i-- {
		_ = l.cli.ContainerRemove(ctx, l.Containers[i], container.RemoveOptions{Force: true})
	}
	for i := len(l.Networks) - 1; i >= 0; i-- {
		_ = l.cli.NetworkRemove(ctx, l.Networks[i])
	}
	_ = l.cli.Close()
	l.cli = nil
}

// WaitReady waits until container exec works.
func (l *Lab) WaitReady(ctx context.Context, name string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := l.Exec(ctx, name, "true"); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("container %s not ready", name)
}

// OneShot runs a short-lived privileged container and returns demuxed stdout/stderr.
type OneShot struct {
	Image       string
	Cmd         []string
	Binds       []string // host:container[:ro]
	Privileged  bool
	NetworkMode string // e.g. "none"
	Name        string // optional
}

// RunOneShot creates, starts, waits, collects logs, and removes a one-shot container.
func RunOneShot(ctx context.Context, opts OneShot) (stdout, stderr string, err error) {
	cli, err := newDockerClient()
	if err != nil {
		return "", "", err
	}
	defer cli.Close()

	hostCfg := &container.HostConfig{
		Privileged: opts.Privileged,
		AutoRemove: false, // remove explicitly after logs
		Binds:      opts.Binds,
	}
	if opts.NetworkMode != "" {
		hostCfg.NetworkMode = container.NetworkMode(opts.NetworkMode)
	}

	cfg := &container.Config{
		Image:        opts.Image,
		AttachStdout: true,
		AttachStderr: true,
	}
	// Replace image ENTRYPOINT (lab image defaults to sleep infinity).
	if len(opts.Cmd) > 0 {
		cfg.Entrypoint = opts.Cmd
	}

	resp, err := cli.ContainerCreate(ctx, cfg, hostCfg, nil, nil, opts.Name)
	if err != nil {
		return "", "", err
	}
	id := resp.ID
	defer func() {
		_ = cli.ContainerRemove(context.Background(), id, container.RemoveOptions{Force: true})
	}()

	// Attach to multiplexed stdout/stderr (do not use ContainerLogs — some logging
	// drivers cannot be read via the API).
	attach, err := cli.ContainerAttach(ctx, id, container.AttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return "", "", err
	}
	defer attach.Close()

	if err := cli.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		return "", "", err
	}

	var outBuf, errBuf bytes.Buffer
	copyDone := make(chan error, 1)
	go func() {
		_, err := stdcopy.StdCopy(&outBuf, &errBuf, attach.Reader)
		copyDone <- err
	}()

	statusCh, errCh := cli.ContainerWait(ctx, id, container.WaitConditionNotRunning)
	var st container.WaitResponse
	select {
	case err := <-errCh:
		return "", "", err
	case st = <-statusCh:
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
	if err := <-copyDone; err != nil && err != io.EOF {
		return outBuf.String(), errBuf.String(), err
	}
	if st.Error != nil {
		return outBuf.String(), errBuf.String(), fmt.Errorf("container wait: %s", st.Error.Message)
	}
	stdout, stderr = outBuf.String(), errBuf.String()
	if st.StatusCode != 0 {
		return stdout, stderr, fmt.Errorf("container exit %d: %s", st.StatusCode, strings.TrimSpace(stderr))
	}
	return stdout, stderr, nil
}

// RefuseHostNetwork documents the safety check.
func RefuseHostNetwork(networkMode string) error {
	if networkMode == "host" {
		return fmt.Errorf("host networking is forbidden for gotun lab")
	}
	return nil
}
