#!/usr/bin/env zsh
emulate -R zsh
setopt errexit

0=${(%):-%N}

REPO=coder/envbuilder

run() {
	dirty="$(git status --porcelain | grep -v '^??')" || true
	if [[ -n $dirty ]]; then
		print error: uncommitted changes, aborting...
		print $dirty
		exit 1
	fi

	branch=$(git rev-parse --abbrev-ref HEAD)
	if [[ ! $branch =~ ^release/[0-9]*\.[0-9]*$ ]]; then
		print "error: ${(qqq)branch} is not on a release branch (should be release/X.Y), aborting..."
		exit 1
	fi

	v=$(git tag --list 'v*' --sort=-v:refname | head -n1 | tr -d v)
	vv=(${(@s,.,)v})
	case $1 in
		major) ((vv[1]++)); vv[2]=0; vv[3]=0;;
		minor) ((vv[2]++)); vv[3]=0;;
		patch) ((vv[3]++));;
		*) print 'error: unknown semver method $1, use patch, minor or major'; exit 1;;
	esac
	nv=${(j,.,)vv}

	head_version=$(./scripts/version.sh)
	print "Latest version: v${v}"
	print "HEAD version: ${head_version}"
	print "New version: v${nv}"

	git rev-parse --verify v${nv} &>/dev/null && {
		print "error: tag v${nv} already exists, aborting..."
		exit 1
	}

	head_tag=$(git describe --tags --exact-match HEAD 2>/dev/null) && {
		print "error: HEAD is already tagged as ${head_tag}, aborting..."
		exit 1
	}

	print "Running checks for ${head_version}..."

	print -n " * Checking fmt... "
	output=$(./scripts/check_fmt.sh 2>&1) || {
		print ERROR
		print "error: check fmt failed, aborting..."
		print $output
		exit 1
	}
	print OK

	print -n " * Building... "
	output=$(./scripts/build.sh 2>&1) || {
		print ERROR
		print "error: build failed, aborting..."
		print $output
		exit 1
	}
	print OK

	changelog=(
		${(f)"$(git log --format='* %s %h' v${v}...HEAD)"}
	)
	changelog=(
		"## Changelog"
		""
		$changelog
		""
		"Compare: https://github.com/${REPO}/compare/v${v}...v${nv}"
		""
		"## Container image"
		""
		' * `docker pull ghcr.io/coder/envbuilder:'${nv}'`'
	)

	print
	print "Changelog:"
	print
	indented=($'\t'${^changelog})
	print ${(F)indented}

	print
	print -n "Publish v${nv} (Y/n): "
	read -r -k1
	case $REPLY in
		[Yy$'\n']) print;;
		[Nn]) print; exit 0;;
		*) print $'\n'error: bad response $REPLY; exit 1;;
	esac

	git tag -a "v${nv}" -m "Release v${nv}"
	git push --follow-tags

	typeset -a params=(
		tag=v${nv}
		title=v${nv}
		body="$(jq -rn --arg x "${(F)changelog}" '$x|@uri')"
	)

	echo open https://github.com/${REPO}/releases/new'?'${(j.&.)params}
}

if [[ -z $1 ]]; then
	1=patch
fi

(cd ${0:h}/..; run $1)
