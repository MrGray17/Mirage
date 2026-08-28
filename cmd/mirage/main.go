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
	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/modelbroker"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

const (
	defaultRunDuration  = 8 * time.Second
	operationTimeout    = 30 * time.Second
	brokerPreflightExit = 78
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "mirage: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "run" {
		return usageError()
	}
	switch args[1] {
	case "hostile-fixture":
		return runHostileFixture(args[2:], stdout, stderr)
	case "agent":
		return runAgent(args[2:], stdout, stderr)
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: mirage run hostile-fixture ... | mirage run agent --image <agent@sha256:digest> --helper-image <helper@sha256:digest> --allow /workspace/FILE [options] -- /absolute/agent command...")
}

func runHostileFixture(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("run hostile-fixture", flag.ContinueOnError)
	flags.SetOutput(stderr)
	image := flags.String("image", strings.TrimSpace(os.Getenv("MIRAGE_HOSTILE_IMAGE")), "preloaded digest-pinned Linux image containing /bin/sh and wget")
	realWorkspace := flags.String("workspace", ".", "trusted real repository used only as the bounded snapshot source")
	duration := flags.Duration("duration", defaultRunDuration, "time before Mirage kills the hostile fixture")
	if err := flags.Parse(args); err != nil {
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

func runAgent(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("run agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	agentImage := flags.String("image", strings.TrimSpace(os.Getenv("MIRAGE_AGENT_IMAGE")), "preloaded digest-pinned coding-agent image")
	helperImage := flags.String("helper-image", strings.TrimSpace(os.Getenv("MIRAGE_HELPER_IMAGE")), "preloaded digest-pinned helper image containing /bin/sh, cat, df, tail, and sleep")
	realWorkspace := flags.String("workspace", ".", "trusted real repository used only as the bounded snapshot source")
	allowedResource := flags.String("allow", "", "the one existing file the M4.3 boundary may modify (for example /workspace/README.md)")
	timeout := flags.Duration("timeout", 10*time.Minute, "maximum coding-agent execution time")
	quota := flags.Int64("workspace-quota-bytes", 64<<20, "hard writable disposable-workspace capacity")
	brokerKind := flags.String("model-broker", "none", "trusted model broker: none, openai, or deepseek")
	model := flags.String("model", "", "exact model allowed by the trusted broker")
	if err := flags.Parse(args); err != nil {
		return err
	}
	command := flags.Args()
	if *agentImage == "" || *helperImage == "" {
		return errors.New("--image and --helper-image are required and must be digest-pinned")
	}
	if strings.TrimSpace(*allowedResource) == "" {
		return errors.New("--allow is required and must identify exactly one existing /workspace file")
	}
	if len(command) == 0 {
		return errors.New("an absolute coding-agent command is required after --")
	}
	if *timeout < time.Second || *timeout > 30*time.Minute {
		return errors.New("--timeout must be between 1s and 30m")
	}
	if *brokerKind != "none" && *brokerKind != "openai" && *brokerKind != "deepseek" {
		return errors.New("--model-broker must be none, openai, or deepseek")
	}
	if *brokerKind == "none" && strings.TrimSpace(*model) != "" {
		return errors.New("--model requires an explicitly enabled model broker")
	}
	if *brokerKind == "deepseek" && strings.TrimSpace(*model) != modelbroker.DeepSeekV4Flash {
		return fmt.Errorf("DeepSeek model must be exactly %s; fallback is disabled", modelbroker.DeepSeekV4Flash)
	}
	if *brokerKind != "none" && strings.TrimSpace(*model) == "" {
		return errors.New("--model is required by the trusted model broker")
	}

	disposable, err := workspace.Prepare(*realWorkspace)
	if err != nil {
		return err
	}
	cleanupDisposable := true
	defer func() {
		if cleanupDisposable {
			_ = disposable.Cleanup()
		}
	}()

	var broker *modelbroker.Broker
	brokerDirectory := ""
	brokerIdentity := ""
	if *brokerKind != "none" {
		keyEnvironment := "OPENAI_API_KEY"
		if *brokerKind == "deepseek" {
			keyEnvironment = "DEEPSEEK_API_KEY"
		}
		apiKey := strings.TrimSpace(os.Getenv(keyEnvironment))
		if apiKey == "" {
			return fmt.Errorf("%s is required by the trusted %s broker; the key remains in the Mirage host process", keyEnvironment, *brokerKind)
		}
		brokerConfig := modelbroker.Config{
			APIKey: apiKey,
			Model:  strings.TrimSpace(*model),
			RunID:  "coding-agent-" + disposable.Token()[:16],
		}
		if *brokerKind == "deepseek" {
			// The live M4.4 acceptance is intentionally tiny. These trusted
			// caps constrain provider spend as well as sandbox abuse.
			brokerConfig.MaxRequests = 6
			brokerConfig.MaxConcurrent = 1
			brokerConfig.MaxRequestBytes = 48 << 10
			brokerConfig.MaxResponseBytes = 4 << 20
			brokerConfig.MaxOutputTokens = 4096
			broker, err = modelbroker.NewDeepSeek(brokerConfig)
		} else {
			broker, err = modelbroker.NewOpenAI(brokerConfig)
		}
		if err != nil {
			return err
		}
		if err := broker.Start(); err != nil {
			return err
		}
		brokerDirectory = broker.Directory()
		brokerIdentity = broker.Identity()
	}
	closeBroker := func() error {
		if broker == nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		return broker.Close(ctx)
	}

	containerName := "mirage-agent-" + disposable.Token()[:16]
	launcher, err := runtimedocker.NewAgent(runtimedocker.AgentConfig{
		AgentImage:          *agentImage,
		HelperImage:         *helperImage,
		ContainerName:       containerName,
		Workspace:           disposable.Path(),
		RealWorkspace:       disposable.RealWorkspace(),
		WorkspaceToken:      disposable.Token(),
		Command:             command,
		WorkspaceQuotaBytes: *quota,
		BrokerDirectory:     brokerDirectory,
		BrokerIdentity:      brokerIdentity,
		BrokerModel:         strings.TrimSpace(*model),
	})
	if err != nil {
		return errors.Join(err, closeBroker())
	}
	issuedAt := time.Now().UTC()
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "coding-agent-" + disposable.Token()[:16],
		ActorID:   "coding-agent",
		ExpiresAt: issuedAt.Add(*timeout + 3*operationTimeout),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: []string{*allowedResource},
		}},
	})
	if err != nil {
		return errors.Join(err, closeBroker())
	}
	binding, err := disposable.Binding()
	if err != nil {
		return errors.Join(err, closeBroker())
	}
	manifest, err := hostileruntime.NewRunManifest(contract, binding, launcher, time.Now)
	if err != nil {
		return errors.Join(err, closeBroker())
	}
	lifecycle, err := hostileruntime.NewBoundLifecycle(manifest)
	if err != nil {
		return errors.Join(err, closeBroker())
	}
	// From here on, disposable cleanup is conditional on proven sandbox
	// destruction. If Docker cleanup is uncertain, retain the workspace and
	// broker rather than letting a defer erase evidence or a live mount.
	cleanupDisposable = false

	commandCtx, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()
	prepareCtx, cancelPrepare := context.WithTimeout(commandCtx, operationTimeout)
	err = lifecycle.Prepare(prepareCtx)
	cancelPrepare()
	if err != nil {
		return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
	}
	fmt.Fprintf(stdout, "runtime=%s workspace=hard-quota-disposable quota_bytes=%d\n", lifecycle.State(), *quota)

	startCtx, cancelStart := context.WithTimeout(commandCtx, operationTimeout)
	err = lifecycle.Start(startCtx)
	cancelStart()
	if err != nil {
		return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
	}
	fmt.Fprintf(stdout, "runtime=%s agent=%s network=none broker=%s\n", lifecycle.State(), command[0], *brokerKind)

	waitCtx, cancelWait := context.WithTimeout(commandCtx, *timeout)
	waitErr := launcher.Wait(waitCtx)
	cancelWait()
	if waitErr != nil {
		fmt.Fprintf(stdout, "agent completion unavailable: %v; freezing without commit authority\n", waitErr)
	}
	freezeCtx, cancelFreeze := context.WithTimeout(context.Background(), operationTimeout)
	freezeErr := lifecycle.Freeze(freezeCtx)
	cancelFreeze()
	if freezeErr != nil {
		return errors.Join(freezeErr, waitErr, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
	}
	fmt.Fprintf(stdout, "runtime=%s process_tree=stopped frozen_tree=exported\n", lifecycle.State())
	var brokerDiagnostic modelbroker.DiagnosticSnapshot
	if broker != nil {
		brokerDiagnostic = broker.Diagnostics()
		fmt.Fprintf(stdout, "broker_preflight_connections=%d broker_requests=%d broker_successful_responses=%d\n", brokerDiagnostic.PreflightConnections, brokerDiagnostic.Requests, brokerDiagnostic.SuccessfulResponses)
	}
	if waitErr != nil {
		emitAgentDiagnostic(stdout, resolveAgentDiagnostic(launcher.Diagnostics(), brokerDiagnostic))
		if err := lifecycle.Reject(); err != nil {
			return errors.Join(waitErr, err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
		}
		cleanupErr := cleanupAgentRuntime(lifecycle, disposable, closeBroker)
		return errors.Join(waitErr, cleanupErr)
	}

	decision, err := lifecycle.Reconcile()
	if err != nil {
		return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
	}
	plan, _ := lifecycle.Reconciliation()
	fmt.Fprintf(stdout, "runtime=%s plan=%s mutations=%d violations=%d\n", lifecycle.State(), plan.Hash(), len(plan.Mutations()), len(decision.Violations()))
	for _, violation := range decision.Violations() {
		fmt.Fprintf(stdout, "violation operation=%s resource=%s rule=%s\n", violation.Operation, violation.Resource, violation.RuleID)
	}
	if !decision.Allowed {
		cleanupErr := cleanupAgentRuntime(lifecycle, disposable, closeBroker)
		return errors.Join(fmt.Errorf("coding-agent final state rejected with %d policy violation(s)", len(decision.Violations())), cleanupErr)
	}
	if _, err := lifecycle.PreCommit(); err != nil {
		return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
	}
	if err := lifecycle.Commit(); err != nil {
		return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
	}
	fmt.Fprintf(stdout, "runtime=%s committed_resource=%s\n", lifecycle.State(), *allowedResource)
	cleanupErr := cleanupAgentRuntime(lifecycle, disposable, closeBroker)
	return cleanupErr
}

func resolveAgentDiagnostic(agent diagnostics.Record, broker modelbroker.DiagnosticSnapshot) diagnostics.Record {
	if broker.Failure.Class != "" {
		result := broker.Failure
		result.Stdout = agent.Stdout
		result.Stderr = agent.Stderr
		result.StdoutTruncated = agent.StdoutTruncated
		result.StderrTruncated = agent.StderrTruncated
		result.AgentExitCode = agent.AgentExitCode
		return result
	}
	if agent.AgentExitCode == brokerPreflightExit && broker.PreflightConnections == 0 {
		agent.Class = diagnostics.BrokerConnect
		agent.Stage = "sandbox_broker_preflight"
		agent.Message = "sandbox could not reach the trusted per-run broker socket before agent launch"
		return agent
	}
	if agent.Class == diagnostics.AgentExit && broker.SuccessfulResponses > 0 {
		agent.Class = diagnostics.AgentProtocol
		agent.Stage = "agent_protocol"
		agent.Message = "provider response passed trusted validation but the coding agent rejected the exchange"
	}
	if agent.Class == "" {
		agent.Class = diagnostics.AgentExit
		agent.Stage = "agent_exit"
		agent.Message = "coding agent failed without a more specific diagnostic"
	}
	return agent
}

func emitAgentDiagnostic(writer io.Writer, diagnostic diagnostics.Record) {
	fmt.Fprintf(writer, "diagnostic class=%s stage=%s provider_status=%d agent_exit=%d stdout_truncated=%t stderr_truncated=%t message=%q\n", diagnostic.Class, diagnostic.Stage, diagnostic.ProviderStatus, diagnostic.AgentExitCode, diagnostic.StdoutTruncated, diagnostic.StderrTruncated, diagnostic.Message)
	if diagnostic.Stdout != "" {
		fmt.Fprintf(writer, "diagnostic_stdout=%q\n", diagnostic.Stdout)
	}
	if diagnostic.Stderr != "" {
		fmt.Fprintf(writer, "diagnostic_stderr=%q\n", diagnostic.Stderr)
	}
}

func cleanupAgentRuntime(lifecycle *hostileruntime.Lifecycle, disposable *workspace.Disposable, closeBroker func() error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	if err := lifecycle.Destroy(cleanupCtx); err != nil {
		return fmt.Errorf("agent sandbox cleanup failed; disposable workspace and broker retained at %s: %w", disposable.Path(), err)
	}
	return errors.Join(disposable.Cleanup(), closeBroker())
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
