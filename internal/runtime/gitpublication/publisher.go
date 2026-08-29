package gitpublication

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitcommit"
	"github.com/MrGray17/Mirage/internal/runtime/githubbinding"
)

var (
	ErrCredential           = errors.New("dedicated GitHub publication credential unavailable")
	ErrPreexistingRef       = errors.New("GitHub target ref already exists")
	ErrPublication          = errors.New("Git branch publication failed")
	ErrPublicationUncertain = errors.New("Git branch publication outcome uncertain")
)

type CredentialSource func() (string, error)
type FinalAuthority func(context.Context) (time.Time, error)

type pushResult struct{ acknowledged bool }
type pushRunner interface {
	prepare(*workspace, *gitbinding.Binding, string, string, string, string) (func(context.Context) pushResult, error)
}

type Engine struct {
	observer   githubbinding.Client
	credential CredentialSource
	runner     pushRunner
	cleanup    func(*workspace) error
}

func NewEngine(observer githubbinding.Client, credential CredentialSource) (*Engine, error) {
	if observer == nil || credential == nil {
		return nil, fmt.Errorf("%w: observer and credential source are required", ErrPublication)
	}
	return &Engine{observer: observer, credential: credential, runner: gitPushRunner{}}, nil
}

type Result struct {
	Record       *Record
	CleanupError error
	Attempted    bool
}

// Publish performs exactly one mutation attempt. The mandatory callback is
// invoked after all preparation and preflight, at the last possible point
// before starting git push. An artifact alone has no publication method.
func (e *Engine) Publish(ctx context.Context, binding *githubbinding.Binding, plan *Plan, artifact *gitcommit.Artifact, repository *gitbinding.Binding, final FinalAuthority) (Result, error) {
	if e == nil || e.observer == nil || e.credential == nil || e.runner == nil || binding == nil || plan == nil || artifact == nil || repository == nil || final == nil {
		return Result{}, fmt.Errorf("%w: complete lifecycle-mediated inputs are required", ErrPublication)
	}
	if binding.Identity() != plan.GitHubBindingIdentity() || binding.RepositoryID() != plan.GitHubRepositoryID() || binding.FullName() != plan.RepositoryFullName() || binding.BaseRef() != plan.BaseRef() || binding.BaseCommit() != plan.BaseCommit() || repository.Identity() != plan.RepositoryBindingIdentity() || artifact.Identity() != plan.ArtifactIdentity() || artifact.CommitOID() != plan.CommitOID() || artifact.TargetRef() != plan.TargetRef() {
		return Result{}, fmt.Errorf("%w: artifact, plan, local repository, or GitHub binding differs", ErrAuthorityChanged)
	}
	token, err := e.credential()
	if err != nil || strings.TrimSpace(token) == "" {
		return Result{}, ErrCredential
	}
	if err := binding.Revalidate(ctx, e.observer, plan.ContractHash(), plan.ManifestHash()); err != nil {
		return Result{}, err
	}
	preflight, err := e.observer.ExactRef(ctx, binding.FullName(), binding.RepositoryID(), plan.TargetRef(), plan.CommitOID())
	if err != nil || preflight.Status == githubbinding.RefUnavailable {
		return Result{}, fmt.Errorf("%w: remote preflight unavailable", ErrPublication)
	}
	if preflight.Status != githubbinding.RefAbsent {
		return Result{}, fmt.Errorf("%w: status=%s", ErrPreexistingRef, preflight.Status)
	}

	localBefore, err := snapshotGit(repository.GitDir())
	if err != nil {
		return Result{}, err
	}
	publication, err := newWorkspace(repository.Root(), repository.GitDir())
	if err != nil {
		return Result{}, err
	}
	cleanup := func() error {
		if e.cleanup != nil {
			return e.cleanup(publication)
		}
		return publication.cleanup()
	}
	finishWithoutRecord := func(cause error) (Result, error) {
		cleanupErr := cleanup()
		return Result{CleanupError: cleanupErr}, errors.Join(cause, cleanupErr)
	}
	if err := artifact.ExportObjects(publication.objects); err != nil {
		return finishWithoutRecord(err)
	}
	if err := publication.revalidate(); err != nil {
		return finishWithoutRecord(err)
	}
	if err := verifyPublicationView(ctx, publication, repository, artifact); err != nil {
		return finishWithoutRecord(err)
	}
	if err := publication.verifyBounded(); err != nil {
		return finishWithoutRecord(err)
	}
	dispatchPush, err := e.runner.prepare(publication, repository, token, plan.RepositoryFullName(), plan.TargetRef(), plan.CommitOID())
	if err != nil {
		return finishWithoutRecord(err)
	}
	dispatch, err := final(ctx)
	if err != nil || dispatch.IsZero() {
		return finishWithoutRecord(errors.Join(ErrAuthorityChanged, err))
	}
	transport := dispatchPush(ctx)
	postWorkspaceErr := publication.verifyBounded()
	observation, observationErr := e.observer.ExactRef(ctx, binding.FullName(), binding.RepositoryID(), plan.TargetRef(), plan.CommitOID())
	if observationErr != nil {
		observation = githubbinding.RefObservation{Status: githubbinding.RefUnavailable}
	}
	outcome, _ := reconcileOutcome(observation, transport.acknowledged)
	record, recordErr := newRecord(plan, dispatch, transport.acknowledged, observation, outcome)
	localAfter, localErr := snapshotGit(repository.GitDir())
	if localErr == nil && localAfter != localBefore {
		localErr = ErrLocalGitChanged
	}
	cleanupErr := cleanup()
	result := Result{Record: record, CleanupError: cleanupErr, Attempted: true}
	baseErr := errors.Join(recordErr, localErr, postWorkspaceErr, cleanupErr)
	switch outcome {
	case OutcomePublished:
		return result, baseErr
	case OutcomeConflicted:
		return result, errors.Join(ErrPreexistingRef, baseErr)
	case OutcomeNotPublished:
		return result, errors.Join(ErrPublication, baseErr)
	default:
		return result, errors.Join(ErrPublicationUncertain, baseErr)
	}
}

// Reconcile is read-only and is the only operation allowed after an uncertain
// attempt. It never invokes the runner.
func (e *Engine) Reconcile(ctx context.Context, binding *githubbinding.Binding, plan *Plan) (githubbinding.RefObservation, Outcome, error) {
	if e == nil || e.observer == nil || binding == nil || plan == nil {
		return githubbinding.RefObservation{}, OutcomePublicationUncertain, ErrPublicationUncertain
	}
	observation, err := e.observer.ExactRef(ctx, binding.FullName(), binding.RepositoryID(), plan.TargetRef(), plan.CommitOID())
	if err != nil {
		return githubbinding.RefObservation{Status: githubbinding.RefUnavailable}, OutcomePublicationUncertain, ErrPublicationUncertain
	}
	outcome, outcomeErr := reconcileOutcome(observation, false)
	return observation, outcome, outcomeErr
}

func verifyPublicationView(ctx context.Context, publication *workspace, repository *gitbinding.Binding, artifact *gitcommit.Artifact) error {
	env := publicationEnvironment(publication, repository, "")
	commit, err := runGit(ctx, env, publication.gitDir, "cat-file", "-p", artifact.CommitOID())
	if err != nil {
		return fmt.Errorf("%w: resolve exact commit", ErrWorkspace)
	}
	lines := strings.Split(string(commit), "\n")
	if len(lines) < 2 || lines[0] != "tree "+artifact.NewTreeOID() || lines[1] != "parent "+artifact.BaseCommit() {
		return fmt.Errorf("%w: exported commit graph differs", ErrWorkspaceChanged)
	}
	if _, err := runGit(ctx, env, publication.gitDir, "cat-file", "-e", artifact.NewTreeOID()+"^{tree}"); err != nil {
		return fmt.Errorf("%w: resolve exact tree", ErrWorkspace)
	}
	if _, err := runGit(ctx, env, publication.gitDir, "cat-file", "-e", artifact.BaseCommit()+"^{commit}"); err != nil {
		return fmt.Errorf("%w: resolve exact parent", ErrWorkspace)
	}
	return nil
}

type gitPushRunner struct{ remoteURL string }

func (r gitPushRunner) prepare(publication *workspace, binding *gitbinding.Binding, token, repository, targetRef, commitOID string) (func(context.Context) pushResult, error) {
	if binding == nil || targetRef == "" || commitOID == "" {
		return nil, fmt.Errorf("%w: incomplete prepared push", ErrPublication)
	}
	remoteURL := r.remoteURL
	if remoteURL == "" {
		remoteURL = "https://github.com/" + repository + ".git"
	}
	env := publicationEnvironment(publication, binding, token)
	if r.remoteURL == "" {
		env = append(env, "GIT_ALLOW_PROTOCOL=https")
	} else {
		env = append(env, "GIT_ALLOW_PROTOCOL=file")
	}
	args := pushArguments(publication, remoteURL, targetRef, commitOID)
	executable := gitExecutable()
	return func(ctx context.Context) pushResult {
		command := exec.CommandContext(ctx, executable, args...)
		command.Env = append([]string(nil), env...)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		return pushResult{acknowledged: command.Run() == nil}
	}, nil
}

func pushArguments(publication *workspace, remoteURL, targetRef, commitOID string) []string {
	return []string{"--git-dir=" + publication.gitDir, "-c", "credential.helper=", "-c", "core.hooksPath=" + publication.hooks, "-c", "http.followRedirects=false", "-c", "protocol.version=2", "push", "--porcelain", "--no-verify", "--no-follow-tags", "--recurse-submodules=no", "--force-with-lease=" + targetRef + ":", remoteURL, commitOID + ":" + targetRef}
}

func runGit(ctx context.Context, env []string, gitDir string, args ...string) ([]byte, error) {
	all := append([]string{"--git-dir=" + gitDir, "-c", "credential.helper=", "-c", "core.hooksPath=" + filepath.Join(filepath.Dir(gitDir), "hooks-disabled"), "-c", "http.followRedirects=false"}, args...)
	command := exec.CommandContext(ctx, gitExecutable(), all...)
	command.Env = env
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return nil, errors.New("trusted Git subprocess failed")
	}
	return append([]byte(nil), output.Bytes()...), nil
}

func publicationEnvironment(publication *workspace, repository *gitbinding.Binding, token string) []string {
	env := []string{"HOME=" + publication.home, "XDG_CONFIG_HOME=" + publication.home, "TMPDIR=" + publication.root, "TMP=" + publication.root, "TEMP=" + publication.root, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_ASKPASS=" + publication.askpass, "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1", "GIT_PROTOCOL_FROM_USER=0", "GIT_SSH_COMMAND=false", "GIT_OBJECT_DIRECTORY=" + publication.objects}
	if repository != nil {
		env = append(env, "GIT_ALTERNATE_OBJECT_DIRECTORIES="+filepath.Join(repository.GitDir(), "objects"))
	}
	if token != "" {
		env = append(env, "MIRAGE_M53_ASKPASS_TOKEN="+token)
	}
	for _, key := range []string{"SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "LANG", "LC_ALL"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func gitExecutable() string {
	if path, err := exec.LookPath("git"); err == nil {
		return path
	}
	return "git"
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(value []byte) (int, error) {
	original := len(value)
	if b.Len() < 64<<10 {
		remaining := (64 << 10) - b.Len()
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.Buffer.Write(value)
	}
	return original, nil
}
