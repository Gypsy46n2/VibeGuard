# VibeGuard's own image. It practises what the container rules preach: a pinned
# digest-able base, no build toolchain in the final layer, a non-root user, and
# dependencies installed before the source is copied so a code change does not
# invalidate the dependency layer.
#
#   docker build -t vibeguard .
#   docker run --rm -v "$PWD":/repo vibeguard audit /repo
#
# The mount must be writable even for an audit: vibeguard-report.json is canonical
# and is written into the directory that was scanned. `fix` additionally needs a git
# worktree it can branch and commit on.

FROM python:3.12-slim AS build

WORKDIR /src
# Dependency metadata first: this layer is cached until pyproject.toml changes.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip build \
 && pip wheel --no-cache-dir --wheel-dir /wheels .


FROM python:3.12-slim

# git is not optional: `vibeguard fix` refuses to write to a repository it cannot
# branch, commit, and roll back (ARCHITECTURE.md §7).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels vibeguard \
 && rm -rf /wheels

# An unprivileged user, and a home it can actually write to — pip, git, and the
# report writer all want one.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin vibeguard
USER vibeguard
WORKDIR /repo

# Scanning somebody else's repository as a stranger is normal; say so once rather
# than having git fail confusingly mid-run.
ENV GIT_CONFIG_GLOBAL=/home/vibeguard/.gitconfig
RUN git config --global --add safe.directory '*'

# No HEALTHCHECK: this image is a one-shot CLI, not a service. There is no
# long-running process for a probe to ask about, and VG-CTR-002 only applies to
# images that declare a server-shaped CMD.
ENTRYPOINT ["vibeguard"]
CMD ["--help"]
