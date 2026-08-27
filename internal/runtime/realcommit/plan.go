// Package realcommit applies the single existing-file content replacement
// supported by M4.3. It never copies or synchronizes a shadow tree.
package realcommit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/MrGray17/Mirage/internal/limits"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

var (
	ErrInvalidPlan      = errors.New("invalid real commit plan")
	ErrConflict         = errors.New("real commit baseline conflict")
	ErrRevalidation     = errors.New("real commit revalidation failed")
	ErrCleanup          = errors.New("real commit cleanup failed")
	errObservedConflict = errors.New("real commit target changed")
)

type Spec struct {
	ManifestHash         string
	AuthorityHash        string
	RealBaselineIdentity string
	RealWorkspace        string
	Resource             string
	BeforeDigest         string
	AfterDigest          string
	RealMode             uint32
	Contents             []byte
}

type Plan struct {
	manifestHash         string
	authorityHash        string
	realBaselineIdentity string
	realWorkspace        string
	resource             string
	relative             string
	beforeDigest         string
	afterDigest          string
	realMode             uint32
	contents             []byte
	hash                 string
}

func New(spec Spec) (*Plan, error) {
	if strings.TrimSpace(spec.ManifestHash) == "" || strings.TrimSpace(spec.AuthorityHash) == "" || strings.TrimSpace(spec.RealBaselineIdentity) == "" || strings.TrimSpace(spec.RealWorkspace) == "" {
		return nil, fmt.Errorf("%w: authority binding is incomplete", ErrInvalidPlan)
	}
	relative, err := canonicalRelative(spec.Resource)
	if err != nil {
		return nil, err
	}
	if spec.RealMode > 0o777 || spec.BeforeDigest == "" || spec.AfterDigest == "" || int64(len(spec.Contents)) > limits.MaxTreeFileBytes {
		return nil, fmt.Errorf("%w: file identity, mode, or content is invalid", ErrInvalidPlan)
	}
	digest := sha256.Sum256(spec.Contents)
	observedAfter := fmt.Sprintf("sha256:%x", digest)
	if observedAfter != spec.AfterDigest {
		return nil, fmt.Errorf("%w: content does not match after digest", ErrInvalidPlan)
	}
	absolute, err := filepath.Abs(spec.RealWorkspace)
	if err != nil {
		return nil, fmt.Errorf("%w: real workspace: %v", ErrInvalidPlan, err)
	}
	canonical := struct {
		ManifestHash         string `json:"manifest_hash"`
		AuthorityHash        string `json:"authority_hash"`
		RealBaselineIdentity string `json:"real_baseline_identity"`
		RealWorkspace        string `json:"real_workspace"`
		Resource             string `json:"resource"`
		BeforeDigest         string `json:"before_digest"`
		AfterDigest          string `json:"after_digest"`
		RealMode             uint32 `json:"real_mode"`
	}{spec.ManifestHash, spec.AuthorityHash, spec.RealBaselineIdentity, filepath.Clean(absolute), spec.Resource, spec.BeforeDigest, spec.AfterDigest, spec.RealMode}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %v", ErrInvalidPlan, err)
	}
	planDigest := sha256.Sum256(encoded)
	return &Plan{
		manifestHash:         spec.ManifestHash,
		authorityHash:        spec.AuthorityHash,
		realBaselineIdentity: spec.RealBaselineIdentity,
		realWorkspace:        filepath.Clean(absolute),
		resource:             spec.Resource,
		relative:             relative,
		beforeDigest:         spec.BeforeDigest,
		afterDigest:          spec.AfterDigest,
		realMode:             spec.RealMode,
		contents:             append([]byte(nil), spec.Contents...),
		hash:                 fmt.Sprintf("sha256:%x", planDigest),
	}, nil
}

func (p *Plan) Hash() string                 { return p.hash }
func (p *Plan) ManifestHash() string         { return p.manifestHash }
func (p *Plan) AuthorityHash() string        { return p.authorityHash }
func (p *Plan) RealBaselineIdentity() string { return p.realBaselineIdentity }
func (p *Plan) Resource() string             { return p.resource }
func (p *Plan) BeforeDigest() string         { return p.beforeDigest }
func (p *Plan) AfterDigest() string          { return p.afterDigest }
func (p *Plan) RealMode() uint32             { return p.realMode }
func (p *Plan) Contents() []byte             { return append([]byte(nil), p.contents...) }

// Apply performs a final rooted target revalidation, stages only after that
// trusted commit phase begins, revalidates again, requires lifecycle-owned
// authority at the last point before replacement, and atomically replaces the
// one named file while preserving the real baseline permission mode.
func Apply(plan *Plan, beforeReplace func() error) (returnErr error) {
	if plan == nil || plan.hash == "" || beforeReplace == nil {
		return ErrInvalidPlan
	}
	root, err := os.OpenRoot(plan.realWorkspace)
	if err != nil {
		return fmt.Errorf("%w: open real workspace: %v", ErrRevalidation, err)
	}
	replaced := false
	defer func() {
		closeErr := root.Close()
		if !replaced && closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("%w: close real workspace root: %v", ErrCleanup, closeErr))
		}
	}()

	if err := requireExpected(root, plan); err != nil {
		return err
	}
	temporary, err := temporaryRelative(plan.relative)
	if err != nil {
		return fmt.Errorf("prepare trusted staging name: %w", err)
	}
	staged, err := root.OpenFile(temporary, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create trusted staging file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			if err := root.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("%w: remove commit staging file: %v", ErrCleanup, err))
			}
		}
	}()
	defer func() {
		closeErr := staged.Close()
		if !replaced && closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("%w: close commit staging file: %v", ErrCleanup, closeErr))
		}
	}()
	written, err := staged.Write(plan.contents)
	if err != nil {
		return fmt.Errorf("write trusted staging file: %w", err)
	}
	if written != len(plan.contents) {
		return fmt.Errorf("write trusted staging file: %w", io.ErrShortWrite)
	}
	if err := staged.Chmod(os.FileMode(plan.realMode)); err != nil {
		return fmt.Errorf("preserve real file mode: %w", err)
	}
	if err := staged.Sync(); err != nil {
		return fmt.Errorf("sync trusted staging file: %w", err)
	}
	if err := requireStaged(root, temporary, staged, plan); err != nil {
		return fmt.Errorf("revalidate trusted staging file: %w", err)
	}
	if err := requireExpected(root, plan); err != nil {
		return err
	}
	if err := requireStaged(root, temporary, staged, plan); err != nil {
		return fmt.Errorf("revalidate trusted staging file immediately before replacement: %w", err)
	}
	if err := beforeReplace(); err != nil {
		return fmt.Errorf("final commit authority check: %w", err)
	}
	if err := os.Rename(filepath.Join(plan.realWorkspace, temporary), filepath.Join(plan.realWorkspace, plan.relative)); err != nil {
		return fmt.Errorf("replace real resource: %w", err)
	}
	cleanup = false
	replaced = true
	return nil
}

func requireExpected(root *os.Root, plan *Plan) error {
	digest, mode, err := observeRegular(root, plan.relative)
	if err != nil {
		if errors.Is(err, errObservedConflict) {
			return fmt.Errorf("%w: %s: %v", ErrConflict, plan.resource, err)
		}
		return fmt.Errorf("%w: %s: %v", ErrRevalidation, plan.resource, err)
	}
	if digest != plan.beforeDigest || mode != plan.realMode {
		return fmt.Errorf("%w: %s expected digest %s mode %04o, observed digest %s mode %04o", ErrConflict, plan.resource, plan.beforeDigest, plan.realMode, digest, mode)
	}
	return nil
}

func observeRegular(root *os.Root, relative string) (digest string, mode uint32, returnErr error) {
	initial, err := root.Lstat(relative)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", 0, fmt.Errorf("%w: target is absent", errObservedConflict)
		}
		return "", 0, fmt.Errorf("initial observation failed: %w", err)
	}
	if !initial.Mode().IsRegular() || hasUnsupportedSecurityMode(initial.Mode()) || initial.Size() < 0 || initial.Size() > limits.MaxTreeFileBytes {
		return "", 0, fmt.Errorf("%w: target is not a supported regular file", errObservedConflict)
	}
	file, err := root.Open(relative)
	if err != nil {
		return "", 0, err
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	opened, err := file.Stat()
	current, currentErr := root.Lstat(relative)
	if err != nil || currentErr != nil {
		return "", 0, fmt.Errorf("establish opened target identity: %w", errors.Join(err, currentErr))
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || hasUnsupportedSecurityMode(opened.Mode()) || hasUnsupportedSecurityMode(current.Mode()) || !os.SameFile(initial, opened) || !os.SameFile(opened, current) {
		return "", 0, fmt.Errorf("%w: opened file is not the still-named regular object", errObservedConflict)
	}
	contents, err := io.ReadAll(io.LimitReader(file, limits.MaxTreeFileBytes+1))
	if err != nil || int64(len(contents)) > limits.MaxTreeFileBytes {
		return "", 0, fmt.Errorf("bounded read failed: %v", err)
	}
	after, afterErr := file.Stat()
	current, currentErr = root.Lstat(relative)
	if afterErr != nil || currentErr != nil {
		return "", 0, fmt.Errorf("complete target observation: %w", errors.Join(afterErr, currentErr))
	}
	if !os.SameFile(opened, after) || !os.SameFile(opened, current) || hasUnsupportedSecurityMode(after.Mode()) || hasUnsupportedSecurityMode(current.Mode()) || opened.Size() != after.Size() || opened.Mode() != after.Mode() || after.Mode() != current.Mode() || !opened.ModTime().Equal(after.ModTime()) || after.Size() != int64(len(contents)) {
		return "", 0, fmt.Errorf("%w: file changed during revalidation", errObservedConflict)
	}
	contentDigest := sha256.Sum256(contents)
	return fmt.Sprintf("sha256:%x", contentDigest), uint32(opened.Mode().Perm()), nil
}

func requireStaged(root *os.Root, relative string, staged *os.File, plan *Plan) error {
	before, err := staged.Stat()
	named, namedErr := root.Lstat(relative)
	if err != nil || namedErr != nil {
		return errors.Join(err, namedErr)
	}
	if !before.Mode().IsRegular() || !named.Mode().IsRegular() || hasUnsupportedSecurityMode(before.Mode()) || hasUnsupportedSecurityMode(named.Mode()) || !os.SameFile(before, named) || uint32(before.Mode().Perm()) != plan.realMode || before.Size() != int64(len(plan.contents)) {
		return errors.New("staging path is not the plan-bound regular file")
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return err
	}
	contents, err := io.ReadAll(io.LimitReader(staged, limits.MaxTreeFileBytes+1))
	if err != nil || int64(len(contents)) > limits.MaxTreeFileBytes {
		return fmt.Errorf("bounded staging read failed: %w", err)
	}
	after, afterErr := staged.Stat()
	named, namedErr = root.Lstat(relative)
	if afterErr != nil || namedErr != nil {
		return errors.Join(afterErr, namedErr)
	}
	if !os.SameFile(before, after) || !os.SameFile(after, named) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || after.Size() != int64(len(contents)) {
		return errors.New("staging file changed during verification")
	}
	digest := sha256.Sum256(contents)
	if fmt.Sprintf("sha256:%x", digest) != plan.afterDigest {
		return errors.New("staging content does not match the plan")
	}
	return nil
}

func hasUnsupportedSecurityMode(mode os.FileMode) bool {
	return mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
}

func canonicalRelative(resource string) (string, error) {
	if !strings.HasPrefix(resource, "/workspace/") || strings.Contains(resource, "\\") || path.Clean(resource) != resource {
		return "", fmt.Errorf("%w: non-canonical resource %q", ErrInvalidPlan, resource)
	}
	relative := strings.TrimPrefix(resource, "/workspace/")
	if relative == "" || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", fmt.Errorf("%w: unsafe resource %q", ErrInvalidPlan, resource)
	}
	return filepath.FromSlash(relative), nil
}

func temporaryRelative(target string) (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(target), workspace.CommitStagingPrefix+hex.EncodeToString(bytes)+".tmp"), nil
}
