#!/usr/bin/env bash
#
# campaign.sh — drive a `br`-tracked, one-issue-per-run remediation campaign
# unattended. Repo-agnostic: it reads a selected campaign config and defers the
# actual workflow + Definition of Done to that config's prompt file. Each
# iteration launches ONE headless Copilot CLI run that
# takes a single issue to Done, then the driver inspects `br` to decide whether
# to continue. It stops — and surfaces to you — only on cases that need a human:
# no ready work while open work remains, an invalid tracker transition, a
# non-zero exit, or a dirty / already-claimed starting state.
#
# State lives in `br` (beads), so this is resumable: stop any time, re-run, and
# it picks up where it left off.
#
# ---- .campaign.conf (sourced bash; all optional) ----------------------------
#   CAMPAIGN_NAME="myproject"                # label for logs (default: repo dir name)
#   CAMPAIGN_PROJECTS=(.)                    # subdirs each with their own .beads/
#                                            #   (federated monorepos); default (.)
#   CAMPAIGN_LABELS=(audit-2026-06 ...)      # campaign labels, OR-unioned; epics skipped
#   CAMPAIGN_PROMPT_FILE="prompt.md"          # selected workflow + Definition of Done
#   CAMPAIGN_GUARDRAILS="..."                # repo-specific guardrails appended to the prompt
#
# ---- env knobs (override conf/defaults) -------------------------------------
#   MAX_ITERS (30)  RUN_TIMEOUT (1800s)  CAMPAIGN_REPO  CAMPAIGN_CONF
#   COPILOT_MODEL  COPILOT_EFFORT
#   COPILOT_FALLBACK_MODEL  COPILOT_FALLBACK_EFFORT
#
# Usage:  ./campaign.sh            # run until done / blocked / cap
#         ./campaign.sh --dry-run  # resolve config + show ready counts, launch nothing
#
set -uo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

REPO="${CAMPAIGN_REPO:-$(git rev-parse --show-toplevel 2>/dev/null)}"

# ---- defaults (a repo's .campaign.conf may override the CAMPAIGN_* arrays) ---
CAMPAIGN_PROJECTS=(.)
CAMPAIGN_LABELS=(audit-2026-06)
CAMPAIGN_GUARDRAILS=""
CAMPAIGN_NAME=""
CAMPAIGN_PROMPT_FILE="prompt.md"

# ---- helpers ----------------------------------------------------------------
log()  { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }
die()  { printf '\n\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
rule() { printf '\033[2m%s\033[0m\n' "────────────────────────────────────────────────────────"; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

copilot_policy_refused() {
  local prefix='Execution failed: CAPIError: '
  local signature=' This content was flagged for possible cybersecurity risk.'
  local last_line
  last_line="$(awk 'NF { last = $0 } END { print last }' "$1")"

  [[ "$last_line" == "$prefix"[0-9][0-9][0-9]"$signature"* ]]
}

project_issue_items() {
  local proj=$1
  local include_epics=$2
  local json
  shift 2

  json="$(cd "$REPO/$proj" 2>/dev/null && br "$@" --json 2>/dev/null)" ||
    return 1

  if [[ "$include_epics" -eq 1 ]]; then
    jq -r --arg proj "$proj" \
      'if type == "array" then .[]? | [$proj, .id] | @tsv else error("expected array") end' \
      <<< "$json"
  else
    jq -r --arg proj "$proj" \
      'if type == "array" then .[]? | select(.issue_type != "epic") | [$proj, .id] | @tsv else error("expected array") end' \
      <<< "$json"
  fi
}

items_ready() {
  local proj label output item
  local -a items=()

  for proj in "${CAMPAIGN_PROJECTS[@]}"; do
    for label in "${CAMPAIGN_LABELS[@]}"; do
      output="$(project_issue_items "$proj" 0 ready -l "$label" --limit 0)" ||
        return 1
      while IFS= read -r item; do
        [[ -n "$item" ]] && items+=("$item")
      done <<< "$output"
    done
  done

  (( ${#items[@]} == 0 )) || printf '%s\n' "${items[@]}" | sort -u
}

items_with_labeled_status() {
  local status=$1
  local proj label output item
  local -a items=()

  for proj in "${CAMPAIGN_PROJECTS[@]}"; do
    for label in "${CAMPAIGN_LABELS[@]}"; do
      output="$(project_issue_items "$proj" 0 list -l "$label" \
        --status "$status" --limit 0)" || return 1
      while IFS= read -r item; do
        [[ -n "$item" ]] && items+=("$item")
      done <<< "$output"
    done
  done

  (( ${#items[@]} == 0 )) || printf '%s\n' "${items[@]}" | sort -u
}

items_with_status() {
  local status=$1
  local proj output item
  local -a items=()

  for proj in "${CAMPAIGN_PROJECTS[@]}"; do
    output="$(project_issue_items "$proj" 1 list --status "$status" --limit 0)" ||
      return 1
    while IFS= read -r item; do
      [[ -n "$item" ]] && items+=("$item")
    done <<< "$output"
  done

  (( ${#items[@]} == 0 )) || printf '%s\n' "${items[@]}" | sort -u
}

line_count() { awk 'NF { count++ } END { print count + 0 }' <<< "$1"; }

# True if any TRACKED file (outside GUARD_EXCLUDES) has staged/unstaged changes.
# (untracked tooling/logs are ignored — git diff does not see them.)
src_dirty() {
  ! git -C "$REPO" diff        --quiet -- . "${GUARD_EXCLUDES[@]}" 2>/dev/null && return 0
  ! git -C "$REPO" diff --cached --quiet -- . "${GUARD_EXCLUDES[@]}" 2>/dev/null && return 0
  return 1
}

surface() { # $1=headline  $2=optional log file
  rule
  printf '\033[33m⏸  HUMAN NEEDED: %s\033[0m\n' "$1"
  local proj ip
  for proj in "${CAMPAIGN_PROJECTS[@]}"; do
    ip="$( ( cd "$REPO/$proj" 2>/dev/null && br list --status in_progress --limit 0 --json 2>/dev/null ) \
      | jq -r --arg p "$proj" '.[]? | "   in_progress (\($p)): \(.id) — \(.title)"' 2>/dev/null )"
    [[ -n "$ip" ]] && printf '%s\n' "$ip"
  done
  if [[ -n "${2:-}" && -f "${2:-}" ]]; then
    printf '\033[2m   last lines of %s:\033[0m\n' "$2"
    tail -n 25 "$2" | sed 's/^/   │ /'
  fi
  rule
}

# ---- preflight + config -----------------------------------------------------
[[ -n "$REPO" ]] || die "not inside a git repository (set CAMPAIGN_REPO)"
cd "$REPO" || die "cannot cd to $REPO"
need br; need jq; need git; need copilot

CAMPAIGN_CONF_PATH="${CAMPAIGN_CONF:-.campaign.conf}"
[[ "$CAMPAIGN_CONF_PATH" = /* ]] ||
  CAMPAIGN_CONF_PATH="$REPO/$CAMPAIGN_CONF_PATH"
[[ -f "$CAMPAIGN_CONF_PATH" ]] ||
  die "campaign config not found: $CAMPAIGN_CONF_PATH"
# shellcheck source=/dev/null
source "$CAMPAIGN_CONF_PATH" ||
  die "failed to load campaign config: $CAMPAIGN_CONF_PATH"

CAMPAIGN_PROMPT_PATH="$CAMPAIGN_PROMPT_FILE"
[[ "$CAMPAIGN_PROMPT_PATH" = /* ]] ||
  CAMPAIGN_PROMPT_PATH="$REPO/$CAMPAIGN_PROMPT_PATH"
[[ -f "$CAMPAIGN_PROMPT_PATH" ]] ||
  die "campaign prompt not found: $CAMPAIGN_PROMPT_PATH"

[[ -n "$CAMPAIGN_NAME" ]] || CAMPAIGN_NAME="$(basename "$REPO")"

MAX_ITERS="${MAX_ITERS:-30}"
RUN_TIMEOUT="${RUN_TIMEOUT:-1800}"
[[ "$MAX_ITERS" =~ ^[1-9][0-9]*$ ]] ||
  die "MAX_ITERS must be a positive integer (got '$MAX_ITERS')"
[[ "$RUN_TIMEOUT" =~ ^[1-9][0-9]*$ ]] ||
  die "RUN_TIMEOUT must be a positive integer (got '$RUN_TIMEOUT')"

CAMPAIGN_CONF_REL="$CAMPAIGN_CONF_PATH"
CAMPAIGN_PROMPT_REL="$CAMPAIGN_PROMPT_PATH"
[[ "$CAMPAIGN_CONF_REL" == "$REPO/"* ]] &&
  CAMPAIGN_CONF_REL="${CAMPAIGN_CONF_REL#"$REPO/"}"
[[ "$CAMPAIGN_PROMPT_REL" == "$REPO/"* ]] &&
  CAMPAIGN_PROMPT_REL="${CAMPAIGN_PROMPT_REL#"$REPO/"}"

GUARD_EXCLUDES=(
  ':(exclude,glob)**/.beads/**'
  ':(exclude)campaign.sh'
  ":(exclude)$CAMPAIGN_CONF_REL"
  ":(exclude)$CAMPAIGN_PROMPT_REL"
)

CAMPAIGN_STATE_DIR="$REPO/.campaign"
LOG_DIR="$CAMPAIGN_STATE_DIR/logs"
if [[ -L "$CAMPAIGN_STATE_DIR" ||
  ( -e "$CAMPAIGN_STATE_DIR" && ! -d "$CAMPAIGN_STATE_DIR" ) ]]; then
  die "campaign state root is not a repository-local directory: $CAMPAIGN_STATE_DIR"
fi
mkdir -p "$LOG_DIR"
if [[ -L "$CAMPAIGN_STATE_DIR" || -L "$LOG_DIR" || ! -d "$LOG_DIR" ]]; then
  die "campaign log root is not a repository-local directory: $LOG_DIR"
fi
case "$(realpath -m "$LOG_DIR")/" in
  "$(realpath -m "$REPO")/"*) ;;
  *) die "campaign log root escapes the repository: $LOG_DIR" ;;
esac
chmod 700 "$CAMPAIGN_STATE_DIR" "$LOG_DIR"
SESSION_ID="$(date +%Y%m%d-%H%M%S)"   # one id per loop invocation → logs group & sort, no run-N collisions

# Validate configured projects.
for proj in "${CAMPAIGN_PROJECTS[@]}"; do
  [[ -d "$REPO/$proj/.beads" ]] ||
    die "campaign project '$proj' has no .beads/ tracker"
done

DRIVER_PROMPT="You are one automated run of this repository's remediation campaign. Read ${CAMPAIGN_PROMPT_REL} in the repository root and follow it EXACTLY. Pick ONE ready, non-epic issue per its ordering rules, claim it (br update <id> --claim), and take it to Done end-to-end: confirm the finding against the current code, implement the smallest correct fix, add a regression test that fails before and passes after, run that file's full Definition of Done, then commit and br close per its workflow. Then STOP — do not start a second issue. If no issue is ready, or the only correct next action needs a human decision, do NOT force a change: stop and explain what you found. Never weaken security or correctness just to make something pass.${CAMPAIGN_GUARDRAILS:+ ${CAMPAIGN_GUARDRAILS}}"
FALLBACK_PROMPT="Resume this same one-issue campaign run from where it stopped after a provider policy refusal. Continue following the original prompt and ${CAMPAIGN_PROMPT_REL} exactly. If an issue was already selected or claimed, work only that issue. If the refusal happened before selection, select exactly one issue as the original prompt directs. Do not restart completed investigation, release the claim, or choose a second issue. Complete the original run, then STOP."

log "campaign:   $CAMPAIGN_NAME"
log "repo:       $REPO"
log "projects:   ${CAMPAIGN_PROJECTS[*]}"
log "labels:     ${CAMPAIGN_LABELS[*]}"
log "config:     $CAMPAIGN_CONF_REL"
log "prompt:     $CAMPAIGN_PROMPT_REL"
log "max iters:  $MAX_ITERS   run timeout: ${RUN_TIMEOUT}s"
[[ -n "${COPILOT_MODEL:-}"  ]] && log "model:      $COPILOT_MODEL"
[[ -n "${COPILOT_EFFORT:-}" ]] && log "effort:     $COPILOT_EFFORT"
if [[ -n "${COPILOT_FALLBACK_MODEL:-}" ]]; then
  log "fallback:   $COPILOT_FALLBACK_MODEL (policy refusal only)"
  [[ -n "${COPILOT_FALLBACK_EFFORT:-}" ]] &&
    log "fb effort:  $COPILOT_FALLBACK_EFFORT"
fi
rule

# ---- dry run: resolve + report, launch nothing ------------------------------
if [[ "$DRY_RUN" -eq 1 ]]; then
  dry_ready="$(items_ready)" || die "failed to query ready campaign issues"
  dry_open="$(items_with_labeled_status open)" ||
    die "failed to query open campaign issues"
  dry_closed="$(items_with_labeled_status closed)" ||
    die "failed to query closed campaign issues"
  dry_claimed="$(items_with_status in_progress)" ||
    die "failed to query in-progress issues"
  log "[dry-run] ready (non-epic): $(line_count "$dry_ready")   open: $(line_count "$dry_open")   closed: $(line_count "$dry_closed")   in_progress: $(line_count "$dry_claimed")"
  for proj in "${CAMPAIGN_PROJECTS[@]}"; do
    for label in "${CAMPAIGN_LABELS[@]}"; do
      c="$(project_issue_items "$proj" 0 ready -l "$label" --limit 0)" ||
        die "failed to query ready issues in $proj for label $label"
      log "[dry-run]   $proj / $label : $(line_count "$c") ready"
    done
  done
  src_dirty && log "[dry-run] tracked changes present → a real run would stop and ask you to clean/finish first."
  log "[dry-run] driver prompt: ${DRIVER_PROMPT:0:96}..."
  exit 0
fi

# ---- main loop --------------------------------------------------------------
attempted=0
for (( iter=1; iter<=MAX_ITERS; iter++ )); do
  if src_dirty; then
    surface "tracked changes are present before iteration $iter — a previous run crashed or another run is active. Commit/finish or revert it, then re-run."
    git -C "$REPO" status --short -- . "${GUARD_EXCLUDES[@]}" | sed 's/^/   /'
    exit 2
  fi
  starting_claimed="$(items_with_status in_progress)" ||
    die "failed to query in-progress issues"
  if [[ -n "$starting_claimed" ]]; then
    surface "an issue is already claimed (in_progress) before iteration $iter — finish or release it first."
    exit 2
  fi

  initial_ready_items="$(items_ready)" ||
    die "failed to query ready campaign issues"
  ready="$(line_count "$initial_ready_items")"
  if [[ "$ready" -eq 0 ]]; then
    open_items="$(items_with_labeled_status open)" ||
      die "failed to query open campaign issues"
    open="$(line_count "$open_items")"
    if [[ "$open" -gt 0 ]]; then
      surface "no issue is ready, but $open non-epic campaign issue(s) remain open and blocked. Resolve their dependencies or human decisions before resuming."
      exit 2
    fi
    rule
    printf '\033[32m✓ No open, non-epic work for [%s]. Campaign complete.\033[0m\n' "$CAMPAIGN_NAME"
    exit 0
  fi

  before_closed_campaign_items="$(items_with_labeled_status closed)" ||
    die "failed to query closed campaign issues"
  before_closed_all_items="$(items_with_status closed)" ||
    die "failed to query repository closed issues"
  before_closed="$(line_count "$before_closed_campaign_items")"
  # Pin the copilot session UUID ourselves (rather than scrape it — `-s` hides it)
  # so the log carries it (filename + header) and a killed/timed-out/blocked run is
  # directly resumable: `copilot --resume=<id>`. Falls back gracefully if no uuid
  # source exists (then copilot self-generates and we just don't know the id).
  csid="$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
  logf="$LOG_DIR/run-${SESSION_ID}-$(printf '%02d' "$iter")${csid:+-$csid}.log"
  log "iteration $iter/$MAX_ITERS — $ready ready, $before_closed closed so far → $logf"
  [[ -n "$csid" ]] && log "  copilot session: $csid   (resume with: copilot --resume=$csid)"

  cargs=( -C "$REPO" -p "$DRIVER_PROMPT" --allow-all-tools --no-ask-user
          --no-auto-update --no-color --log-level error -s )
  [[ -n "$csid" ]] && cargs+=( --session-id "$csid" )
  [[ -n "${COPILOT_MODEL:-}"  ]] && cargs+=( --model "$COPILOT_MODEL" )
  [[ -n "${COPILOT_EFFORT:-}" ]] && cargs+=( --effort "$COPILOT_EFFORT" )

  attempted=$(( attempted + 1 ))
  # Header first (truncates/creates the file), then append the teed run output.
  { printf '# campaign %s  iter=%s/%s  session=%s  started=%s\n' \
      "$CAMPAIGN_NAME" "$iter" "$MAX_ITERS" "${csid:-<auto>}" "$(date -Is)"
    printf '# resume: copilot --resume=%s\n\n' "${csid:-<id>}"
    printf '# primary: model=%s effort=%s\n' \
      "${COPILOT_MODEL:-<default>}" "${COPILOT_EFFORT:-<default>}"
    if [[ -n "${COPILOT_FALLBACK_MODEL:-}" ]]; then
      printf '# refusal fallback: model=%s effort=%s\n' \
        "$COPILOT_FALLBACK_MODEL" "${COPILOT_FALLBACK_EFFORT:-<default>}"
    fi
    printf '\n'
  } > "$logf"
  run_started="$SECONDS"
  final_attempt="primary"
  timeout "$RUN_TIMEOUT" copilot "${cargs[@]}" 2>&1 | tee -a "$logf"
  rc="${PIPESTATUS[0]}"

  if [[ "$rc" -ne 0 && "$rc" -ne 124 && -n "$csid" &&
    -n "${COPILOT_FALLBACK_MODEL:-}" ]] &&
    copilot_policy_refused "$logf"; then
    elapsed=$(( SECONDS - run_started ))
    remaining_timeout=$(( RUN_TIMEOUT - elapsed ))

    if (( remaining_timeout <= 0 )); then
      rc=124
    else
      final_attempt="fallback"
      log "  provider policy refusal detected — resuming $csid with $COPILOT_FALLBACK_MODEL"
      {
        printf '\n# fallback: session=%s model=%s effort=%s remaining_timeout=%ss started=%s\n\n' \
          "$csid" "$COPILOT_FALLBACK_MODEL" \
          "${COPILOT_FALLBACK_EFFORT:-<default>}" "$remaining_timeout" "$(date -Is)"
      } | tee -a "$logf"

      fallback_args=( -C "$REPO" -p "$FALLBACK_PROMPT" --allow-all-tools --no-ask-user
                      --no-auto-update --no-color --log-level error -s
                      "--resume=$csid" --model "$COPILOT_FALLBACK_MODEL" )
      [[ -n "${COPILOT_FALLBACK_EFFORT:-}" ]] &&
        fallback_args+=( --effort "$COPILOT_FALLBACK_EFFORT" )

      timeout "$remaining_timeout" copilot "${fallback_args[@]}" 2>&1 | tee -a "$logf"
      rc="${PIPESTATUS[0]}"
    fi
  fi

  if [[ "$rc" -eq 124 ]]; then
    surface "run $iter exceeded its ${RUN_TIMEOUT}s budget during the $final_attempt attempt and was killed. Resume it: copilot --resume=${csid:-<id>}" "$logf"; exit 3
  elif [[ "$rc" -ne 0 ]]; then
    surface "$final_attempt copilot attempt exited with code $rc on iteration $iter. Resume it: copilot --resume=${csid:-<id>}" "$logf"; exit 3
  fi

  after_closed_campaign_items="$(items_with_labeled_status closed)" ||
    die "failed to query closed campaign issues after run $iter"
  after_closed_all_items="$(items_with_status closed)" ||
    die "failed to query repository closed issues after run $iter"
  after_claimed_items="$(items_with_status in_progress)" ||
    die "failed to query in-progress issues after run $iter"
  after_closed="$(line_count "$after_closed_campaign_items")"
  closed_added="$(
    comm -13 \
      <(printf '%s\n' "$before_closed_all_items" | sed '/^$/d') \
      <(printf '%s\n' "$after_closed_all_items" | sed '/^$/d')
  )"
  closed_removed="$(
    comm -23 \
      <(printf '%s\n' "$before_closed_all_items" | sed '/^$/d') \
      <(printf '%s\n' "$after_closed_all_items" | sed '/^$/d')
  )"

  if [[ "$(line_count "$closed_added")" -ne 1 ||
    -n "$closed_removed" || -n "$after_claimed_items" ]] ||
    ! grep -Fxq -- "$closed_added" <<< "$initial_ready_items"; then
    surface "run $iter did not close exactly one issue from its initial ready set. Inspect/continue: copilot --resume=${csid:-<id>}" "$logf"
    exit 4
  fi

  log "iteration $iter done — closed $before_closed → $after_closed. Continuing."
  rule
done

rule
printf '\033[32m✓ Reached MAX_ITERS=%s (attempted %s runs). Re-run ./campaign.sh to continue.\033[0m\n' "$MAX_ITERS" "$attempted"
