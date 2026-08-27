package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	hostileruntime "github.com/MrGray17/Mirage/internal/runtime"
	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

const (
	defaultRunDuration = 8 * time.Second
	operationTimeout   = 30 * time.Second
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "mirage: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "run" || args[1] != "hostile-fixture" {
		return errors.New("usage: mirage run hostile-fixture --image <repository@sha256:digest> [--workspace PATH] [--duration 8s]")
	}

	flags := flag.NewFlagSet("run hostile-fixture", flag.ContinueOnError)
	flags.SetOutput(stderr)
	image := flags.String("image", strings.TrimSpace(os.Getenv("MIRAGE_HOSTILE_IMAGE")), "preloaded digest-pinned Linux image containing /bin/sh and wget")
	realWorkspace := flags.String("workspace", ".", "trusted real repository used only as the bounded snapshot source")
	duration := flags.Duration("duration", defaultRunDuration, "time before Mirage kills the hostile fixture")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *image == "" {
		return errors.New("--image or MIRAGE_HOSTILE_IMAGE is required and must be digest-pinned")
	}
	if *duration < time.Second || *duration > time.Minute {
		return errors.New("--duration must be between 1s and 1m")
	}

	disposable, err := workspace.Prepare(*realWorkspace)
	if err != nil {
		return err
	}
	containerName := "mirage-hostile-" + disposable.Token()[:16]
	launcher, err := runtimedocker.New(runtimedocker.Config{
		Image:          *image,
		ContainerName:  containerName,
		Workspace:      disposable.Path(),
		RealWorkspace:  disposable.RealWorkspace(),
		WorkspaceToken: disposable.Token(),
	})
	if err != nil {
		return errors.Join(err, disposable.Cleanup())
	}
	contractIssuedAt := time.Now().UTC()
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "hostile-fixture-" + disposable.Token()[:16],
		ActorID:   "hostile-fixture",
		ExpiresAt: contractIssuedAt.Add(*duration + 3*operationTimeout),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: []string{"/workspace/README.md"},
		}},
	})
	if err != nil {
		return errors.Join(err, disposable.Cleanup())
	}
	workspaceBinding, err := disposable.Binding()
	if err != nil {
		return errors.Join(err, disposable.Cleanup())
	}
	manifest, err := hostileruntime.NewRunManifest(contract, workspaceBinding, launcher, time.Now)
	if err != nil {
		return errors.Join(err, disposable.Cleanup())
	}
	lifecycle, err := hostileruntime.NewBoundLifecycle(manifest)
	if err != nil {
		return errors.Join(err, disposable.Cleanup())
	}

	commandCtx, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()

	prepareCtx, cancelPrepare := context.WithTimeout(commandCtx, operationTimeout)
	err = lifecycle.Prepare(prepareCtx)
	cancelPrepare()
	if err != nil {
		return errors.Join(err, cleanupRuntime(lifecycle, disposable))
	}
	fmt.Fprintf(stdout, "runtime=%s workspace=disposable\n", lifecycle.State())

	startCtx, cancelStart := context.WithTimeout(commandCtx, operationTimeout)
	err = lifecycle.Start(startCtx)
	cancelStart()
	if err != nil {
		return errors.Join(err, cleanupRuntime(lifecycle, disposable))
	}
	fmt.Fprintf(stdout, "runtime=%s fixture=hostile\n", lifecycle.State())

	timer := time.NewTimer(*duration)
	select {
	case <-timer.C:
		fmt.Fprintln(stdout, "runtime timeout reached; terminating hostile process tree")
	case <-commandCtx.Done():
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		fmt.Fprintln(stdout, "interrupt received; terminating hostile process tree")
	}

	// Freeze uses a fresh trusted timeout even if the run context was canceled.
	freezeCtx, cancelFreeze := context.WithTimeout(context.Background(), operationTimeout)
	err = lifecycle.Freeze(freezeCtx)
	cancelFreeze()
	if err != nil {
		return errors.Join(err, cleanupRuntime(lifecycle, disposable))
	}
	fmt.Fprintf(stdout, "runtime=%s process_tree=stopped\n", lifecycle.State())

	decision, err := lifecycle.Reconcile()
	if err != nil {
		return errors.Join(err, cleanupRuntime(lifecycle, disposable))
	}
	plan, _ := lifecycle.Reconciliation()
	fmt.Fprintf(stdout, "runtime=%s plan=%s mutations=%d violations=%d\n", lifecycle.State(), plan.Hash(), len(plan.Mutations()), len(decision.Violations()))
	for _, violation := range decision.Violations() {
		fmt.Fprintf(stdout, "violation operation=%s resource=%s rule=%s\n", violation.Operation, violation.Resource, violation.RuleID)
	}
	if decision.Allowed {
		// The hostile-fixture command is an attack/rejection demonstration, not
		// an operator commit interface. M4.3 commit authority is exercised only
		// by a bound lifecycle whose verified plan meets the single-file slice.
		if err := lifecycle.Reject(); err != nil {
			return errors.Join(err, cleanupRuntime(lifecycle, disposable))
		}
	}
	if err := cleanupRuntime(lifecycle, disposable); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "runtime=%s commit=disabled reason=hostile-fixture-is-rejection-only\n", lifecycle.State())
	return nil
}

func cleanupRuntime(lifecycle *hostileruntime.Lifecycle, disposable *workspace.Disposable) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	if err := lifecycle.Destroy(cleanupCtx); err != nil {
		return fmt.Errorf("sandbox cleanup failed; disposable workspace retained at %s: %w", disposable.Path(), err)
	}
	if err := disposable.Cleanup(); err != nil {
		return err
	}
	return nil
}
