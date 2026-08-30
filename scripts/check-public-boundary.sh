#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Reject private planning references and internal delivery terminology from all
# tracked public text. This script intentionally does not scan itself because
# its built-in test corpus contains forbidden examples.

set -u

pattern='docs/(superpowers|aegisvm-artifacts)|(prd|arch|standards|spec|design)[[:space:]]*§|pre-consolidation[[:space:]-]*neuronedge|ported[[:space:]]+from[[:space:]].*neuronedge|(^|[^[:alnum:]_-])task[[:space:]-]*[0-9]+[a-z]?([^[:alnum:]_]|$)|(^|[^[:alnum:]_-])task_[0-9]+[a-z]?([^[:alnum:]]|$)|risk[[:space:]]+[a-z]?[0-9]+|(^|[^[:alnum:]_])wedge([^[:alnum:]_]|$)|neuronedge\.ai|design[[:space:]-]+partners?|joined[[:space:]]+mindpool|premium[[:space:]-]+tier|/users/[^/]+/(development|desktop|documents|downloads)/|commercial/ne-control-plane'

matches_pattern() {
    printf '%s\n' "$1" | grep -E -i "$pattern" >/dev/null
}

expect_match() {
    if ! matches_pattern "$2"; then
        echo "public-boundary self-test failed: expected match: $1" >&2
        exit 2
    fi
}

expect_no_match() {
    if matches_pattern "$2"; then
        echo "public-boundary self-test failed: unexpected match: $1" >&2
        exit 2
    fi
}

run_self_test() {
    # Positive corpus: case and spelling variants that must fail the guard.
    expect_match 'private document path' 'DOCS/SUPERPOWERS/specs/internal.md'
    expect_match 'private artifact path' 'docs/aegisvm-artifacts/design.md'
    expect_match 'private PRD citation' 'PRD §9.2'
    expect_match 'private architecture citation' 'arch §6.4'
    expect_match 'private standards citation' 'STANDARDS §8'
    expect_match 'private design citation' 'Design §4.2'
    expect_match 'pre-consolidation attribution' 'pre-consolidation NeuronEdge report'
    expect_match 'private source attribution' 'Ported from NeuronEdge redactors/hash.rs'
    expect_match 'internal task label' 'Task 6b coverage tests'
    expect_match 'internal snake-case task identifier' 'task_6c_driver_license_patterns'
    expect_match 'internal risk label' 'risk R3 remains open'
    expect_match 'internal wedge label' 'Wedge-6.8 implementation'
    expect_match 'product-site reference' 'https://neuronedge.ai'
    expect_match 'product-domain email' 'security@neuronedge.ai'
    expect_match 'partner-recruitment language' 'We are looking for design partners'
    expect_match 'acquisition-history language' 'NeuronEdge joined Mindpool'
    expect_match 'commercial tier language' 'the v2 premium tier'
    expect_match 'author-local path' '/Users/example/Development/private-notes.md'
    expect_match 'private control-plane path' 'Commercial/ne-control-plane/docs/PRD.md'

    # Negative corpus: public terminology and normal English must remain valid.
    expect_no_match 'public repository link' 'https://github.com/NVIDIA/OpenShell'
    expect_no_match 'ordinary API path' '/api/v2/users/42'
    expect_no_match 'ordinary blocked-state word' 'the child process is wedged'
    expect_no_match 'upstream dependency name' 'futures-task 0.3.31'
    expect_no_match 'public technical description' 'built-in regex entity groups'
}

run_self_test

# Scan every tracked text file. `git grep` reports 1 for no matches and greater
# than 1 for a scanner error. Preserve scanner errors so the check fails closed
# rather than passing silently.
git grep -n -I -i -E "$pattern" -- . ':(exclude)scripts/check-public-boundary.sh'
content_status=$?
case "$content_status" in
    0)
        echo 'public-boundary check failed: remove private references or internal delivery terminology' >&2
        exit 1
        ;;
    1)
        :
        ;;
    *)
        echo "public-boundary check failed: git grep exited with $content_status" >&2
        exit "$content_status"
        ;;
esac

# File names are public data too. Check tracked paths and active untracked paths
# after content has passed. Omit deleted paths so a pending rename is checked
# without inspecting names that are leaving the working tree.
tracked_paths=$(git ls-files)
paths_status=$?
if [ "$paths_status" -ne 0 ]; then
    echo "public-boundary check failed: git ls-files exited with $paths_status" >&2
    exit "$paths_status"
fi

deleted_paths=$(git ls-files --deleted)
paths_status=$?
if [ "$paths_status" -ne 0 ]; then
    echo "public-boundary check failed: git ls-files --deleted exited with $paths_status" >&2
    exit "$paths_status"
fi

untracked_paths=$(git ls-files --others --exclude-standard)
paths_status=$?
if [ "$paths_status" -ne 0 ]; then
    echo "public-boundary check failed: git ls-files --others exited with $paths_status" >&2
    exit "$paths_status"
fi

active_paths=$(printf '%s\n%s\n' "$tracked_paths" "$untracked_paths" | while IFS= read -r candidate_path; do
    if [ "$candidate_path" = 'scripts/check-public-boundary.sh' ]; then
        continue
    fi
    if ! printf '%s\n' "$deleted_paths" | grep -F -x "$candidate_path" >/dev/null; then
        printf '%s\n' "$candidate_path"
    fi
done)

printf '%s\n' "$active_paths" | grep -E -i "$pattern"
path_status=$?
case "$path_status" in
    0)
        echo 'public-boundary check failed: remove private references or internal delivery terminology from active paths' >&2
        exit 1
        ;;
    1)
        :
        ;;
    *)
        echo "public-boundary check failed: path scanner exited with $path_status" >&2
        exit "$path_status"
        ;;
esac
