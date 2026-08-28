// Package gitbinding captures and revalidates the narrow trusted Git
// repository topology supported by M5.1. It performs read-only observation and
// grants no authority to create objects, update refs, or contact remotes.
package gitbinding

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	Version          = "mirage.git-repository-binding/v1"
	maxGitOutput     = 4096
	maxConfigBytes   = 1 << 20
	maxIndexBytes    = 64 << 20
	sha1HexLength    = 40
	maxReferenceSize = 255
)

var (
	ErrInvalidRepository = errors.New("invalid trusted Git repository")
	ErrUnsupportedLayout = errors.New("unsupported Git repository layout")
	ErrDirtyRepository   = errors.New("tracked Git worktree or index differs from HEAD")
	ErrRepositoryChanged = errors.New("trusted Git repository binding changed")
	ErrGitObservation    = errors.New("trusted read-only Git observation failed")
)

// Binding is immutable trusted repository evidence. The os.FileInfo values are
// retained privately so revalidation can prove that the physical repository
// root and .git directory are still the objects captured before execution.
type Binding struct {
	manifestHash       string
	root               string
	gitDir             string
	headCommit         string
	headTree           string
	headRef            string
	objectFormat       string
	configDigest       string
	indexDigest        string
	headFileDigest     string
	refStorageDigest   string
	repositoryIdentity string
	identity           string
	capturedAt         time.Time
	rootInfo           os.FileInfo
	gitInfo            os.FileInfo
}

type observation struct {
	root             string
	gitDir           string
	headCommit       string
	headTree         string
	headRef          string
	objectFormat     string
	configDigest     string
	indexDigest      string
	headFileDigest   string
	refStorageDigest string
	rootInfo         os.FileInfo
	gitInfo          os.FileInfo
}

// Capture binds an ordinary, non-bare, attached worktree. M5.1 deliberately
// rejects gitfiles, linked worktrees, alternate object databases, submodule
// administrative stores, and tracked/index dirtiness.
func Capture(repositoryRoot, manifestHash string, at time.Time) (*Binding, error) {
	if strings.TrimSpace(manifestHash) == "" || at.IsZero() {
		return nil, fmt.Errorf("%w: manifest identity and trusted capture time are required", ErrInvalidRepository)
	}
	first, err := observe(repositoryRoot)
	if err != nil {
		return nil, err
	}
	second, err := observe(first.root)
	if err != nil {
		return nil, err
	}
	if !sameObservation(first, second) || !os.SameFile(first.rootInfo, second.rootInfo) || !os.SameFile(first.gitInfo, second.gitInfo) {
		return nil, fmt.Errorf("%w: repository changed during capture", ErrRepositoryChanged)
	}

	repositoryIdentity, err := hashCanonical(struct {
		Version      string `json:"version"`
		Root         string `json:"root"`
		GitDir       string `json:"git_dir"`
		ObjectFormat string `json:"object_format"`
		ConfigDigest string `json:"config_digest"`
	}{Version, first.root, first.gitDir, first.objectFormat, first.configDigest})
	if err != nil {
		return nil, err
	}
	identity, err := hashCanonical(struct {
		Version            string `json:"version"`
		ManifestHash       string `json:"manifest_hash"`
		RepositoryIdentity string `json:"repository_identity"`
		HeadCommit         string `json:"head_commit"`
		HeadTree           string `json:"head_tree"`
		HeadRef            string `json:"head_ref"`
		IndexDigest        string `json:"index_digest"`
		HeadFileDigest     string `json:"head_file_digest"`
		RefStorageDigest   string `json:"ref_storage_digest"`
		CapturedAt         string `json:"captured_at"`
	}{Version, manifestHash, repositoryIdentity, first.headCommit, first.headTree, first.headRef, first.indexDigest, first.headFileDigest, first.refStorageDigest, at.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return nil, err
	}
	return &Binding{
		manifestHash:       manifestHash,
		root:               first.root,
		gitDir:             first.gitDir,
		headCommit:         first.headCommit,
		headTree:           first.headTree,
		headRef:            first.headRef,
		objectFormat:       first.objectFormat,
		configDigest:       first.configDigest,
		indexDigest:        first.indexDigest,
		headFileDigest:     first.headFileDigest,
		refStorageDigest:   first.refStorageDigest,
		repositoryIdentity: repositoryIdentity,
		identity:           identity,
		capturedAt:         at.UTC(),
		rootInfo:           first.rootInfo,
		gitInfo:            first.gitInfo,
	}, nil
}

func (b *Binding) Identity() string {
	if b == nil {
		return ""
	}
	return b.identity
}
func (b *Binding) ManifestHash() string {
	if b == nil {
		return ""
	}
	return b.manifestHash
}
func (b *Binding) RepositoryIdentity() string {
	if b == nil {
		return ""
	}
	return b.repositoryIdentity
}
func (b *Binding) Root() string {
	if b == nil {
		return ""
	}
	return b.root
}
func (b *Binding) GitDir() string {
	if b == nil {
		return ""
	}
	return b.gitDir
}
func (b *Binding) HeadCommit() string {
	if b == nil {
		return ""
	}
	return b.headCommit
}
func (b *Binding) HeadTree() string {
	if b == nil {
		return ""
	}
	return b.headTree
}
func (b *Binding) HeadRef() string {
	if b == nil {
		return ""
	}
	return b.headRef
}
func (b *Binding) CapturedAt() time.Time {
	if b == nil {
		return time.Time{}
	}
	return b.capturedAt
}

// Revalidate proves that the same physical repository and bound Git state are
// still present. It never refreshes or regenerates the binding.
func (b *Binding) Revalidate(manifestHash string) error {
	if b == nil || b.identity == "" || manifestHash == "" || manifestHash != b.manifestHash || b.rootInfo == nil || b.gitInfo == nil {
		return fmt.Errorf("%w: binding or manifest identity is invalid", ErrRepositoryChanged)
	}
	current, err := observe(b.root)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRepositoryChanged, err)
	}
	if !os.SameFile(b.rootInfo, current.rootInfo) || !os.SameFile(b.gitInfo, current.gitInfo) {
		return fmt.Errorf("%w: physical root or .git identity differs", ErrRepositoryChanged)
	}
	expected := observation{
		root: b.root, gitDir: b.gitDir, headCommit: b.headCommit, headTree: b.headTree,
		headRef: b.headRef, objectFormat: b.objectFormat, configDigest: b.configDigest,
		indexDigest: b.indexDigest, headFileDigest: b.headFileDigest, refStorageDigest: b.refStorageDigest,
	}
	if !sameObservation(expected, current) {
		return fmt.Errorf("%w: HEAD, tree, ref, index, configuration, or repository layout differs", ErrRepositoryChanged)
	}
	return nil
}

func observe(repositoryRoot string) (observation, error) {
	root, rootInfo, gitDir, gitInfo, configDigest, indexDigest, headFileDigest, err := validatePhysicalLayout(repositoryRoot)
	if err != nil {
		return observation{}, err
	}
	if err := requireClean(root); err != nil {
		return observation{}, err
	}
	if err := requireSupportedIndex(root); err != nil {
		return observation{}, err
	}
	top, err := gitOutput(root, "rev-parse", "--show-toplevel")
	if err != nil || !samePath(top, root) {
		return observation{}, fmt.Errorf("%w: worktree root is ambiguous", ErrUnsupportedLayout)
	}
	observedGitDir, err := gitOutput(root, "rev-parse", "--absolute-git-dir")
	if err != nil || !samePath(observedGitDir, gitDir) {
		return observation{}, fmt.Errorf("%w: .git directory is indirect or ambiguous", ErrUnsupportedLayout)
	}
	bare, err := gitOutput(root, "rev-parse", "--is-bare-repository")
	if err != nil || bare != "false" {
		return observation{}, fmt.Errorf("%w: bare repositories are not supported", ErrUnsupportedLayout)
	}
	inside, err := gitOutput(root, "rev-parse", "--is-inside-work-tree")
	if err != nil || inside != "true" {
		return observation{}, fmt.Errorf("%w: path is not an ordinary worktree", ErrUnsupportedLayout)
	}
	objectFormat, err := gitOutput(root, "rev-parse", "--show-object-format=storage")
	if err != nil || objectFormat != "sha1" {
		return observation{}, fmt.Errorf("%w: only SHA-1 object-format repositories are supported in M5.1", ErrUnsupportedLayout)
	}
	head, err := gitOutput(root, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || !validObjectID(head) {
		return observation{}, fmt.Errorf("%w: HEAD commit is unavailable or malformed", ErrGitObservation)
	}
	tree, err := gitOutput(root, "rev-parse", "--verify", "HEAD^{tree}")
	if err != nil || !validObjectID(tree) {
		return observation{}, fmt.Errorf("%w: HEAD tree is unavailable or malformed", ErrGitObservation)
	}
	ref, err := gitOutput(root, "symbolic-ref", "--quiet", "HEAD")
	if err != nil || !validHeadRef(ref) {
		return observation{}, fmt.Errorf("%w: detached or malformed HEAD is unsupported", ErrUnsupportedLayout)
	}
	refStorageDigest, err := observeRefStorage(gitDir, ref)
	if err != nil {
		return observation{}, err
	}
	return observation{
		root: root, gitDir: gitDir, headCommit: head, headTree: tree, headRef: ref,
		objectFormat: objectFormat, configDigest: configDigest, indexDigest: indexDigest,
		headFileDigest: headFileDigest, refStorageDigest: refStorageDigest,
		rootInfo: rootInfo, gitInfo: gitInfo,
	}, nil
}

func validatePhysicalLayout(repositoryRoot string) (string, os.FileInfo, string, os.FileInfo, string, string, string, error) {
	if strings.TrimSpace(repositoryRoot) == "" {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: repository root is empty", ErrInvalidRepository)
	}
	absolute, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: resolve root: %v", ErrInvalidRepository, err)
	}
	absolute = filepath.Clean(absolute)
	initial, err := os.Lstat(absolute)
	if err != nil || initial.Mode()&os.ModeSymlink != 0 || !initial.IsDir() {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: root is not a non-symlink directory", ErrInvalidRepository)
	}
	physical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: resolve physical root: %v", ErrInvalidRepository, err)
	}
	root := filepath.Clean(physical)
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: physical root is invalid", ErrInvalidRepository)
	}
	gitDir := filepath.Join(root, ".git")
	gitInfo, err := os.Lstat(gitDir)
	if err != nil || gitInfo.Mode()&os.ModeSymlink != 0 || !gitInfo.IsDir() {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: .git must be a real directory", ErrUnsupportedLayout)
	}
	for _, unsupported := range []string{"commondir", "gitdir", "worktrees", "modules", "config.worktree"} {
		if _, err := os.Lstat(filepath.Join(gitDir, unsupported)); err == nil {
			return "", nil, "", nil, "", "", "", fmt.Errorf("%w: .git/%s is unsupported", ErrUnsupportedLayout, unsupported)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", nil, "", nil, "", "", "", fmt.Errorf("%w: inspect .git/%s", ErrGitObservation, unsupported)
		}
	}
	if _, err := os.Lstat(filepath.Join(gitDir, "objects", "info", "alternates")); err == nil {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: alternate object databases are unsupported", ErrUnsupportedLayout)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: inspect object alternates", ErrGitObservation)
	}
	if _, err := os.Lstat(filepath.Join(gitDir, "info", "grafts")); err == nil {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: grafted history is unsupported", ErrUnsupportedLayout)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: inspect grafted history", ErrGitObservation)
	}
	configBytes, configDigest, err := readAndHashRegular(filepath.Join(gitDir, "config"), maxConfigBytes)
	if err != nil {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: read repository config: %v", ErrUnsupportedLayout, err)
	}
	if hasForbiddenConfig(configBytes) {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: config include/worktree indirection is unsupported", ErrUnsupportedLayout)
	}
	_, indexDigest, err := readAndHashRegular(filepath.Join(gitDir, "index"), maxIndexBytes)
	if err != nil {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: read repository index: %v", ErrUnsupportedLayout, err)
	}
	_, headFileDigest, err := readAndHashRegular(filepath.Join(gitDir, "HEAD"), maxGitOutput)
	if err != nil {
		return "", nil, "", nil, "", "", "", fmt.Errorf("%w: read repository HEAD: %v", ErrUnsupportedLayout, err)
	}
	return root, rootInfo, gitDir, gitInfo, configDigest, indexDigest, headFileDigest, nil
}

func requireClean(root string) error {
	for _, args := range [][]string{
		{"diff-index", "--cached", "--quiet", "--no-ext-diff", "HEAD", "--"},
		{"diff-files", "--quiet", "--no-ext-diff", "--"},
	} {
		_, err := gitOutput(root, args...)
		if err == nil {
			continue
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return ErrDirtyRepository
		}
		return fmt.Errorf("%w: establish tracked/index cleanliness", ErrGitObservation)
	}
	return nil
}

func requireSupportedIndex(root string) error {
	output, err := gitOutputBytes(root, int(maxIndexBytes), "ls-files", "--stage", "-v", "-z")
	if err != nil {
		return fmt.Errorf("%w: inspect index entries", ErrGitObservation)
	}
	for _, record := range bytes.Split(output, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		tab := bytes.IndexByte(record, '\t')
		if tab < 0 {
			return fmt.Errorf("%w: malformed index entry", ErrUnsupportedLayout)
		}
		fields := strings.Fields(string(record[:tab]))
		if len(fields) != 4 || fields[0] != "H" || (fields[1] != "100644" && fields[1] != "100755") || !validObjectID(fields[2]) || fields[3] != "0" {
			return fmt.Errorf("%w: hidden index flags, non-regular entries, or non-zero stages are unsupported", ErrUnsupportedLayout)
		}
	}
	return nil
}

func gitOutput(root string, args ...string) (string, error) {
	output, err := gitOutputBytes(root, maxGitOutput, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func gitOutputBytes(root string, limit int, args ...string) ([]byte, error) {
	full := append([]string{"--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "credential.helper=", "-C", root}, args...)
	command := exec.Command("git", full...)
	command.Env = scrubbedGitEnvironment()
	stdout := &boundedBuffer{remaining: limit}
	stderr := &boundedBuffer{remaining: maxGitOutput}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return nil, err
	}
	if stdout.truncated || stderr.truncated {
		return nil, fmt.Errorf("%w: bounded Git output exceeded", ErrGitObservation)
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}

func scrubbedGitEnvironment() []string {
	allowed := map[string]bool{"PATH": true, "PATHEXT": true, "SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true}
	environment := make([]string, 0, len(allowed)+5)
	for _, item := range os.Environ() {
		name, _, ok := strings.Cut(item, "=")
		if ok && allowed[strings.ToUpper(name)] {
			environment = append(environment, item)
		}
	}
	nullDevice := "/dev/null"
	if runtime.GOOS == "windows" {
		nullDevice = "NUL"
	}
	return append(environment,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+nullDevice,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_NO_REPLACE_OBJECTS=1",
	)
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if len(p) > b.remaining {
		p = p[:b.remaining]
		b.truncated = true
	}
	if len(p) > 0 {
		_, _ = b.buffer.Write(p)
		b.remaining -= len(p)
	}
	return original, nil
}

func readAndHashRegular(path string, maximum int64) ([]byte, string, error) {
	initial, err := os.Lstat(path)
	if err != nil || !initial.Mode().IsRegular() || initial.Mode()&os.ModeSymlink != 0 || initial.Size() < 0 || initial.Size() > maximum {
		return nil, "", fmt.Errorf("not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(initial, opened) {
		return nil, "", fmt.Errorf("file identity changed while opening")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		return nil, "", fmt.Errorf("bounded read failed")
	}
	final, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, final) || final.Size() != int64(len(contents)) {
		return nil, "", fmt.Errorf("file identity changed while reading")
	}
	digest := sha256.Sum256(contents)
	return contents, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validObjectID(value string) bool {
	if len(value) != sha1HexLength || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validHeadRef(ref string) bool {
	if len(ref) <= len("refs/heads/") || len(ref) > maxReferenceSize || !strings.HasPrefix(ref, "refs/heads/") {
		return false
	}
	name := strings.TrimPrefix(ref, "refs/heads/")
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") || strings.Contains(name, "@{") || strings.Contains(name, "//") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	for _, r := range name {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("~^:?*[\\", r) {
			return false
		}
	}
	return true
}

func sameObservation(left, right observation) bool {
	return samePath(left.root, right.root) && samePath(left.gitDir, right.gitDir) &&
		left.headCommit == right.headCommit && left.headTree == right.headTree &&
		left.headRef == right.headRef && left.objectFormat == right.objectFormat &&
		left.configDigest == right.configDigest && left.indexDigest == right.indexDigest &&
		left.headFileDigest == right.headFileDigest && left.refStorageDigest == right.refStorageDigest
}

func observeRefStorage(gitDir, ref string) (string, error) {
	loose := filepath.Join(gitDir, filepath.FromSlash(ref))
	if _, err := os.Lstat(loose); err == nil {
		_, digest, readErr := readAndHashRegular(loose, maxGitOutput)
		if readErr != nil {
			return "", fmt.Errorf("%w: current loose ref is not a bounded regular file", ErrUnsupportedLayout)
		}
		return "loose:" + digest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: inspect current loose ref", ErrGitObservation)
	}
	_, digest, err := readAndHashRegular(filepath.Join(gitDir, "packed-refs"), maxConfigBytes)
	if err != nil {
		return "", fmt.Errorf("%w: current ref has no supported loose or packed storage", ErrUnsupportedLayout)
	}
	return "packed:" + digest, nil
}

func hasForbiddenConfig(contents []byte) bool {
	section := ""
	for _, raw := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")))
			if strings.HasPrefix(section, "include") {
				return true
			}
			continue
		}
		key, _, _ := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if (section == "core" && strings.EqualFold(key, "worktree")) || (section == "extensions" && strings.EqualFold(key, "worktreeConfig")) {
			return true
		}
	}
	return false
}

func samePath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func hashCanonical(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: canonicalize binding: %v", ErrInvalidRepository, err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
