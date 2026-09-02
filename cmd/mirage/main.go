package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/demo"
	"github.com/MrGray17/Mirage/internal/effectgraph"
	"github.com/MrGray17/Mirage/internal/gitrefs"
	"github.com/MrGray17/Mirage/internal/observatory"
	"github.com/MrGray17/Mirage/internal/receipt"
	hostileruntime "github.com/MrGray17/Mirage/internal/runtime"
	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/githubbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitpublication"
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
	if len(args) < 2 {
		return usageError()
	}
	switch args[0] {
	case "run":
		switch args[1] {
		case "hostile-fixture":
			return runHostileFixture(args[2:], stdout, stderr)
		case "agent":
			return runAgent(args[2:], stdout, stderr)
		default:
			return usageError()
		}
	case "demo":
		return runDemo(args[1], args[2:], stdout, stderr)
	case "receipt":
		if args[1] != "verify" {
			return usageError()
		}
		return runReceiptVerify(args[2:], stdout, stderr)
	case "observatory":
		return runObservatory(args[1:], stdout, stderr)
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: mirage demo malicious|benign [options] | mirage receipt verify <file> | mirage observatory --out FILE <receipt> | mirage run hostile-fixture ... | mirage run agent --image <agent@sha256:digest> --helper-image <helper@sha256:digest> --allow /workspace/FILE [options] -- /absolute/agent command...")
}

func runDemo(scenario string, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("demo "+scenario, flag.ContinueOnError)
	flags.SetOutput(stderr)
	imageDefault := strings.TrimSpace(os.Getenv("MIRAGE_DEMO_IMAGE"))
	if imageDefault == "" {
		imageDefault = strings.TrimSpace(os.Getenv("MIRAGE_HOSTILE_IMAGE"))
	}
	image := flags.String("image", imageDefault, "preloaded digest-pinned image containing /bin/sh and wget")
	helperImage := flags.String("helper-image", strings.TrimSpace(os.Getenv("MIRAGE_HELPER_IMAGE")), "preloaded digest-pinned helper image; defaults to --image")
	realWorkspace := flags.String("workspace", "", "explicit trusted demo workspace; omitted creates a visible isolated demo workspace")
	evidenceOut := flags.String("evidence-out", "", "new receipt path; defaults beside the generated demo workspace")
	observatoryOut := flags.String("observatory-out", "", "new static Observatory path; defaults beside the receipt")
	timeout := flags.Duration("timeout", 15*time.Second, "maximum fixture execution time")
	quota := flags.Int64("workspace-quota-bytes", 64<<20, "hard writable disposable-workspace capacity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if scenario != demo.ScenarioMalicious && scenario != demo.ScenarioBenign {
		return usageError()
	}
	if strings.TrimSpace(*image) == "" {
		return errors.New("--image or MIRAGE_DEMO_IMAGE is required and must be digest-pinned")
	}
	if strings.TrimSpace(*helperImage) == "" {
		*helperImage = *image
	}
	if strings.TrimSpace(*realWorkspace) == "" {
		created, err := demo.CreateWorkspace()
		if err != nil {
			return err
		}
		*realWorkspace = created
	}

	commandCtx, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()
	result, err := demo.Run(commandCtx, demo.Config{
		Scenario:            scenario,
		AgentImage:          *image,
		HelperImage:         *helperImage,
		RealWorkspace:       *realWorkspace,
		WorkspaceQuotaBytes: *quota,
		Timeout:             *timeout,
	})
	if err != nil {
		return fmt.Errorf("competition demo failed (real workspace %s): %w", *realWorkspace, err)
	}
	graph, executionReceipt, err := buildDemoEvidence(result)
	if err != nil {
		return fmt.Errorf("build competition evidence: %w", err)
	}
	encoded, err := receipt.Marshal(executionReceipt)
	if err != nil {
		return err
	}
	outputPath := strings.TrimSpace(*evidenceOut)
	if outputPath == "" {
		outputPath = filepath.Join(filepath.Dir(result.RealWorkspace), result.RunID+".receipt.json")
	}
	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve evidence output: %w", err)
	}
	if err := writeNewEvidence(outputPath, encoded); err != nil {
		return err
	}
	page, err := observatory.Render(executionReceipt)
	if err != nil {
		return err
	}
	pagePath := strings.TrimSpace(*observatoryOut)
	if pagePath == "" {
		pagePath = strings.TrimSuffix(outputPath, filepath.Ext(outputPath)) + ".observatory.html"
	}
	pagePath, err = filepath.Abs(pagePath)
	if err != nil {
		return fmt.Errorf("resolve Observatory output: %w", err)
	}
	if err := writeNewEvidence(pagePath, page); err != nil {
		return err
	}
	emitDemoResult(stdout, result, graph.Hash, executionReceipt.SHA256, outputPath, pagePath)
	return nil
}

func emitDemoResult(writer io.Writer, result demo.Result, graphHash, receiptHash, receiptPath, observatoryPath string) {
	fmt.Fprintf(writer, "MIRAGE // RUN %s\n\n", strings.ToUpper(result.RunID))
	fmt.Fprintf(writer, "Task:\n%s\n\n", result.Task)
	fmt.Fprintf(writer, "Sandbox:\nREADY  uid=%s  network=%s  quota=%d bytes\n\n", result.SandboxUID, result.SandboxNetwork, result.WorkspaceQuotaBytes)
	fmt.Fprintln(writer, "Agent Effects:")
	authorized, denied := 0, 0
	for _, attempt := range result.Attempts {
		marker := "+"
		if attempt.Disposition == "DENIED" {
			marker = "x"
			denied++
		} else if attempt.Disposition == "AUTHORIZED" {
			authorized++
		}
		fmt.Fprintf(writer, "%s %-6s %-31s %s\n", marker, attempt.Operation, attempt.Resource, attempt.Disposition)
	}
	fmt.Fprintf(writer, "\nObserved:\n%d trusted final-state mutation\n\n", len(result.Mutations))
	fmt.Fprintf(writer, "Verification:\n%s  plan=%s\n\n", result.Verification, result.ReconciliationPlan)
	fmt.Fprintf(writer, "Commit:\n%s  resource=%s  mode=%04o\n\n", result.CommitPlan, result.CommittedResource, result.RealModeAfter)
	fmt.Fprintf(writer, "Evidence:\nprocess_tree_stopped=%t  secret_preserved=%t  cleanup_complete=%t\n", result.ProcessTreeStopped, result.SecretPreserved, result.DisposableCleaned && result.SandboxArtifactsClean)
	fmt.Fprintf(writer, "effect_graph=%s\nreceipt=%s\nreceipt_file=%s\n", graphHash, receiptHash, receiptPath)
	fmt.Fprintf(writer, "observatory=%s\n", observatoryPath)
	fmt.Fprintf(writer, "real_workspace=%s\n\n", result.RealWorkspace)
	fmt.Fprintf(writer, "RESULT:\nAgent attempted %d effects. MIRAGE authorized %d, denied %d, and committed %d.\n", len(result.Attempts), authorized, denied, len(result.Mutations))
}

func buildDemoEvidence(result demo.Result) (*effectgraph.Graph, *receipt.Receipt, error) {
	graphEffects := make([]effectgraph.Effect, 0, len(result.Attempts))
	attempted := make([]receipt.Effect, 0, len(result.Attempts))
	var authorized, denied []receipt.Effect
	for _, attempt := range result.Attempts {
		graphEffects = append(graphEffects, effectgraph.Effect{
			Operation: attempt.Operation, Resource: attempt.Resource, Disposition: attempt.Disposition, EnforcedBy: attempt.EnforcedBy,
		})
		effect := receipt.Effect{Operation: attempt.Operation, Resource: attempt.Resource, EnforcedBy: attempt.EnforcedBy}
		attempted = append(attempted, effect)
		if attempt.Disposition == "AUTHORIZED" {
			authorized = append(authorized, effect)
		} else if attempt.Disposition == "DENIED" {
			denied = append(denied, effect)
		}
	}
	graphMutations := make([]effectgraph.Mutation, 0, len(result.Mutations))
	mutations := make([]receipt.Mutation, 0, len(result.Mutations))
	for _, mutation := range result.Mutations {
		graphMutations = append(graphMutations, effectgraph.Mutation{Operation: mutation.Operation, Resource: mutation.Resource, AfterDigest: mutation.AfterDigest})
		mutations = append(mutations, receipt.Mutation{
			Operation: mutation.Operation, Resource: mutation.Resource, BeforeDigest: mutation.BeforeDigest, AfterDigest: mutation.AfterDigest,
		})
	}
	agent := "deterministic-malicious-fixture"
	if result.Scenario == demo.ScenarioBenign {
		agent = "deterministic-benign-fixture"
	}
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: result.RunID, Task: result.Task, Agent: agent, Effects: graphEffects, Mutations: graphMutations,
		Verification: result.Verification, VerificationPlan: result.ReconciliationPlan, Committed: result.Committed,
		CommitPlan: result.CommitPlan, CommittedResource: result.CommittedResource,
	})
	if err != nil {
		return nil, nil, err
	}
	committed := []receipt.Mutation(nil)
	if result.Committed {
		committed = append(committed, mutations...)
	}
	executionReceipt, err := receipt.New(receipt.Spec{
		RunID: result.RunID, ContractHash: result.ContractHash, StartedAt: result.StartedAt, CompletedAt: result.CompletedAt,
		AttemptedEffects: attempted, AuthorizedEffects: authorized, DeniedEffects: denied,
		ObservedMutations: mutations, Verification: result.Verification, CommittedMutations: committed,
		VerificationPlan: result.ReconciliationPlan, CommitPlan: result.CommitPlan, Graph: graph,
	})
	if err != nil {
		return nil, nil, err
	}
	return graph, executionReceipt, nil
}

func writeNewEvidence(path string, contents []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create evidence file without overwrite: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		return errors.Join(fmt.Errorf("write evidence: %w", err), file.Close())
	}
	return file.Close()
}

func runReceiptVerify(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("receipt verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: mirage receipt verify <file>")
	}
	path, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return err
	}
	encoded, err := readBoundedRegular(path, 4<<20)
	if err != nil {
		return fmt.Errorf("read receipt: %w", err)
	}
	verified, err := receipt.ParseAndVerify(encoded)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "VALID receipt=%s run=%s graph=%s committed=%d\n", verified.SHA256, verified.RunID, verified.EffectGraphHash, len(verified.CommittedMutations))
	return nil
}

func runObservatory(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("observatory", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("out", "", "new static HTML output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 || strings.TrimSpace(*output) == "" {
		return errors.New("usage: mirage observatory --out FILE <receipt>")
	}
	inputPath, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return err
	}
	encoded, err := readBoundedRegular(inputPath, 4<<20)
	if err != nil {
		return fmt.Errorf("read receipt: %w", err)
	}
	evidence, err := receipt.ParseAndVerify(encoded)
	if err != nil {
		return err
	}
	page, err := observatory.Render(evidence)
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	if err := writeNewEvidence(outputPath, page); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "OBSERVATORY_READY run=%s graph=%s file=%s\n", evidence.RunID, evidence.EffectGraphHash, outputPath)
	return nil
}

func readBoundedRegular(path string, limit int64) (contents []byte, returnErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	opened, err := file.Stat()
	current, currentErr := os.Lstat(path)
	if err != nil || currentErr != nil {
		return nil, errors.Join(err, currentErr)
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) || opened.Size() < 1 || opened.Size() > limit {
		return nil, errors.New("receipt must be one stable regular file no larger than 4 MiB")
	}
	contents, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(contents)) > limit {
		return nil, errors.Join(errors.New("receipt exceeds the read limit"), err)
	}
	after, afterErr := file.Stat()
	current, currentErr = os.Lstat(path)
	if afterErr != nil || currentErr != nil || !os.SameFile(opened, after) || !os.SameFile(after, current) || opened.Size() != after.Size() || opened.Mode() != after.Mode() || !opened.ModTime().Equal(after.ModTime()) || after.Size() != int64(len(contents)) {
		return nil, errors.Join(errors.New("receipt changed during acquisition"), afterErr, currentErr)
	}
	return contents, nil
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
	publishGitHub := flags.Bool("publish-github", false, "create the contract-authorized MIRAGE run branch on github.com")
	githubRepository := flags.String("github-repo", "", "canonical GitHub owner/repo; free-form URLs are not accepted")
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
	if !*publishGitHub && strings.TrimSpace(*githubRepository) != "" {
		return errors.New("--github-repo requires explicit --publish-github opt-in")
	}
	if *publishGitHub && strings.TrimSpace(*githubRepository) == "" {
		return errors.New("--publish-github requires exact --github-repo owner/repo authority")
	}
	githubToken := ""
	if *publishGitHub {
		githubToken = strings.TrimSpace(os.Getenv("MIRAGE_GITHUB_TOKEN"))
		if githubToken == "" {
			return errors.New("MIRAGE_GITHUB_TOKEN is required by trusted host-side publication; ambient Git/gh credentials are never used")
		}
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
	runID := "coding-agent-" + disposable.Token()[:16]
	contractVersion := contracts.VersionV1
	publicationPolicy := contracts.GitHubPublicationPolicy{}
	if *publishGitHub {
		contractVersion = contracts.VersionV2
		publicationPolicy = contracts.GitHubPublicationPolicy{RepositoryFullName: *githubRepository, TargetRef: gitrefs.RunTarget(runID), Operation: contracts.GitHubCreateBranch}
	}
	contract, err := contracts.New(contracts.Spec{
		Version:   contractVersion,
		RunID:     runID,
		ActorID:   "coding-agent",
		ExpiresAt: issuedAt.Add(*timeout + 3*operationTimeout),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: []string{*allowedResource},
		}},
		GitHub: publicationPolicy,
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
	var githubClient *githubbinding.HTTPClient
	if *publishGitHub {
		githubClient, err = githubbinding.NewHTTPClient(githubToken)
		if err != nil {
			return errors.Join(err, closeBroker())
		}
		if _, err := lifecycle.BindGitRepository(); err != nil {
			return errors.Join(err, closeBroker())
		}
		bindCtx, cancelBind := context.WithTimeout(context.Background(), operationTimeout)
		_, err = lifecycle.BindGitHubRepository(bindCtx, *githubRepository, githubClient)
		cancelBind()
		if err != nil {
			return errors.Join(err, closeBroker())
		}
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
	if *publishGitHub {
		if _, err := lifecycle.DeriveGitEffectPlan(); err != nil {
			return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
		}
		artifact, err := lifecycle.ConstructGitCommitArtifact()
		if err != nil {
			return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
		}
		publicationPlan, err := lifecycle.DeriveGitPublicationPlan(commandCtx)
		if err != nil {
			return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
		}
		engine, err := gitpublication.NewEngine(githubClient, func() (string, error) {
			value := strings.TrimSpace(os.Getenv("MIRAGE_GITHUB_TOKEN"))
			if value == "" || value != githubToken {
				return "", gitpublication.ErrCredential
			}
			return value, nil
		})
		if err != nil {
			return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
		}
		publishCtx, cancelPublish := context.WithTimeout(commandCtx, operationTimeout)
		record, publishErr := lifecycle.PublishGitHub(publishCtx, engine)
		cancelPublish()
		if record != nil {
			fmt.Fprintf(stdout, "runtime=%s repository_id=%d repository=%s target_ref=%s commit_oid=%s transport_acknowledged=%t reconciled=%t publication_record=%s\n", lifecycle.State(), record.RepositoryID(), record.RepositoryFullName(), record.TargetRef(), record.CommitOID(), record.TransportAcknowledged(), record.ResolvedByReconciliation(), record.Identity())
		}
		if publishErr != nil {
			return errors.Join(publishErr, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
		}
		if record == nil || artifact.CommitOID() != publicationPlan.CommitOID() || record.CommitOID() != artifact.CommitOID() {
			return errors.Join(errors.New("publication evidence does not bind the exact commit artifact"), cleanupAgentRuntime(lifecycle, disposable, closeBroker))
		}
	} else {
		if _, err := lifecycle.PreCommit(); err != nil {
			return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
		}
		if err := lifecycle.Commit(); err != nil {
			return errors.Join(err, cleanupAgentRuntime(lifecycle, disposable, closeBroker))
		}
		fmt.Fprintf(stdout, "runtime=%s committed_resource=%s\n", lifecycle.State(), *allowedResource)
	}
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
