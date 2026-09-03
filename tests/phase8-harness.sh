#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

evidence_profile="smoke"

emit() {
  local group="$1"
  local status="$2"
  shift 2
  local scenario
  for scenario in "$@"; do
    printf '{"scenario":%s,"status":"%s","profile":"%s","group":"%s"}\n' \
      "$scenario" "$status" "$evidence_profile" "$group"
  done
}

run() {
  local group="$1"
  local scenarios="$2"
  shift 2
  printf 'phase8: %s\n' "$group" >&2
  "$@"
  # shellcheck disable=SC2086
  emit "$group" passed $scenarios
}

source_admission() {
  printf 'phase8: source-admission\n' >&2
  cargo test --bin phx-port \
    admission::tests::source_rate_uses_a_deterministic_fake_clock -- --exact
  cargo test --test ingress_limits_cli \
    unix::source_pre_routing_limit_rejects_before_worker_and_recovers -- --exact
  cargo test --bin phx-port \
    admission::tests::relay_transition_releases_source_capacity_for_more_than_sixteen_relays \
    -- --exact
  emit source-admission passed 6
}

source_churn() {
  printf 'phase8: source-churn\n' >&2
  cargo test --bin phx-port \
    admission::tests::source_table_expires_entries_and_never_exceeds_its_limit -- --exact
  cargo test --bin phx-port \
    admission::tests::full_source_table_rejects_when_every_entry_is_active -- --exact
  emit source-churn passed 7
}

relay_idle() {
  printf 'phase8: relay-idle\n' >&2
  cargo test --bin phx-port \
    ingress_config::tests::public_routes_support_default_override_and_disabled_relay_idle_policy \
    -- --exact
  cargo test --bin phx-port \
    relay::tests::idle_policy_times_out_and_can_be_disabled -- --exact
  emit relay-idle passed 14
}

graceful_drain() {
  printf 'phase8: graceful-drain\n' >&2
  cargo test --test ingress_limits_cli \
    unix::clean_shutdown_emits_one_bounded_drain_event -- --exact
  cargo test --bin phx-port \
    proxy::tests::shutdown_drains_established_relay_until_shared_deadline -- --exact
  emit graceful-drain passed 15
}

resource_smoke() {
  printf 'phase8: resource-recovery\n' >&2
  PHX_PORT_PHASE8_PROFILE=smoke \
    cargo test --test adversarial_public_ingress \
      mixed_load_and_fd_pressure_recover_to_baseline -- --exact
  emit resource-recovery passed 19
  emit q26-load exercised 20
}

qualification_host_gate() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'qualification requires Linux\n' >&2
    return 1
  fi
  if ((EUID == 0)); then
    printf 'qualification must run as an unprivileged service user\n' >&2
    return 1
  fi

  local vcpus affinity_cpus host_vcpus host_memory_kib memory_kib memory_source
  read -r vcpus affinity_cpus host_vcpus < <(qualification_cpu_affinity)
  host_memory_kib="$(awk '$1 == "MemTotal:" { print $2; exit }' /proc/meminfo)"
  read -r memory_kib memory_source < <(
    qualification_effective_memory_kib \
      /proc/self/cgroup /sys/fs/cgroup /proc/meminfo
  )
  qualification_validate_host \
    "$(uname -s)" "$EUID" "$vcpus" "$affinity_cpus" "$host_vcpus" \
    "$memory_kib" "$memory_source" "$host_memory_kib"
}

qualification_validate_host() {
  local kernel="$1"
  local euid="$2"
  local vcpus="$3"
  local affinity_cpus="$4"
  local host_vcpus="$5"
  local memory_kib="$6"
  local memory_source="$7"
  local host_memory_kib="$8"
  if [[ "$kernel" != "Linux" ]]; then
    printf 'qualification requires Linux\n' >&2
    return 1
  fi
  if [[ ! "$euid" =~ ^[0-9]+$ ]] || ((euid == 0)); then
    printf 'qualification must run as an unprivileged service user\n' >&2
    return 1
  fi
  if [[ ! "$vcpus" =~ ^[0-9]+$ || ! "$host_vcpus" =~ ^[0-9]+$ ||
    ! "$affinity_cpus" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
    printf 'qualification could not validate CPU affinity\n' >&2
    return 1
  fi
  if [[ "$vcpus" != "4" ]]; then
    printf 'qualification requires exactly 4 available vCPUs, found %s\n' "$vcpus" >&2
    return 1
  fi
  local -a affinity
  IFS=',' read -r -a affinity <<<"$affinity_cpus"
  if ((${#affinity[@]} != vcpus)) || ((host_vcpus < vcpus)); then
    printf 'qualification CPU affinity evidence is inconsistent\n' >&2
    return 1
  fi
  if [[ ! "$memory_kib" =~ ^[0-9]+$ || ! "$host_memory_kib" =~ ^[0-9]+$ ]] ||
    ((memory_kib < 7549747 || memory_kib > 9227469)); then
    printf 'qualification requires an 8 GiB host (within 10%%), found %s KiB\n' \
      "${memory_kib:-unknown}" >&2
    return 1
  fi
  if [[ "$memory_source" != "host" && "$memory_source" != "cgroup_v2" ]]; then
    printf 'qualification memory evidence has an invalid source\n' >&2
    return 1
  fi
  local environment dedicated_vm_equivalent
  environment="dedicated_host"
  dedicated_vm_equivalent="true"
  if [[ "$vcpus" != "$host_vcpus" || "$memory_source" != "host" ||
    "$memory_kib" != "$host_memory_kib" ]]; then
    environment="cgroup_constrained_larger_host"
    dedicated_vm_equivalent="false"
  fi
  printf '{"metric":"qualification_host","kernel":"linux","vcpus":%s,"affinity_vcpus":%s,"affinity_cpus":[%s],"host_vcpus":%s,"memory_kib":%s,"memory_source":"%s","host_memory_kib":%s,"environment":"%s","dedicated_vm_equivalent":%s,"euid":%s}\n' \
    "$vcpus" "$vcpus" "$affinity_cpus" "$host_vcpus" "$memory_kib" \
    "$memory_source" "$host_memory_kib" "$environment" \
    "$dedicated_vm_equivalent" "$euid"
}

qualification_cpu_affinity() {
  python3 -I - <<'PY'
import os

try:
    affinity = sorted(os.sched_getaffinity(0))
except (AttributeError, OSError) as error:
    raise SystemExit(f"cannot inspect CPU affinity with sched_getaffinity: {error}")

if not affinity:
    raise SystemExit("sched_getaffinity returned an empty CPU set")

host_vcpus = os.cpu_count()
if host_vcpus is None or host_vcpus < len(affinity):
    raise SystemExit("cannot determine the host CPU count")

print(len(affinity), ",".join(str(cpu) for cpu in affinity), host_vcpus)
PY
}

qualification_effective_memory_kib() {
  local proc_cgroup_file="$1"
  local cgroup_root="${2%/}"
  local proc_meminfo_file="$3"
  local host_memory_kib
  host_memory_kib="$(
    awk '$1 == "MemTotal:" { print $2; exit }' "$proc_meminfo_file"
  )"
  if [[ ! "$host_memory_kib" =~ ^[0-9]+$ ]]; then
    printf 'cannot determine physical memory from %s\n' "$proc_meminfo_file" >&2
    return 1
  fi

  local cgroup_path
  cgroup_path="$(
    awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "$proc_cgroup_file"
  )"
  if [[ -z "$cgroup_path" ]]; then
    printf '%s host\n' "$host_memory_kib"
    return
  fi
  if [[ "$cgroup_path" != /* || "$cgroup_path" == *"/../"* || "$cgroup_path" == "/.." ]]; then
    printf 'invalid cgroup v2 path in %s\n' "$proc_cgroup_file" >&2
    return 1
  fi

  local current="${cgroup_root}${cgroup_path}"
  local limit_bytes=""
  local value
  while [[ "$current" == "$cgroup_root" || "$current" == "$cgroup_root/"* ]]; do
    if [[ -e "$current/memory.max" ]]; then
      IFS= read -r value <"$current/memory.max" || {
        printf 'cannot read cgroup memory limit %s\n' "$current/memory.max" >&2
        return 1
      }
      if [[ "$value" != "max" ]]; then
        if [[ ! "$value" =~ ^[0-9]+$ ]]; then
          printf 'invalid cgroup memory limit in %s\n' "$current/memory.max" >&2
          return 1
        fi
        if [[ -z "$limit_bytes" ]] || ((value < limit_bytes)); then
          limit_bytes="$value"
        fi
      fi
    fi
    [[ "$current" == "$cgroup_root" ]] && break
    current="${current%/*}"
  done

  if [[ -z "$limit_bytes" ]]; then
    printf '%s host\n' "$host_memory_kib"
    return
  fi

  local limit_kib=$((limit_bytes / 1024))
  if ((host_memory_kib < limit_kib)); then
    printf '%s host\n' "$host_memory_kib"
  else
    printf '%s cgroup_v2\n' "$limit_kib"
  fi
}

qualification_passing_test_count() {
  awk '/test result: ok\. 1 passed; 0 failed;/ { count++ } END { print count + 0 }' "$1"
}

smoke() {
  run delivery "1 2 3 11 12 18" \
    cargo test --test adversarial_public_ingress \
      relay_handoff_and_phxp_failures_are_end_to_end -- --exact
  run client-hello "4" \
    cargo test --test adversarial_public_ingress \
      malformed_fragmented_slow_and_ipv6_client_hellos_are_bounded -- --exact
  run global-admission "5" \
    cargo test --test ingress_limits_cli \
      unix::connection_admission_rejects_before_worker_and_recovers -- --exact
  source_admission
  source_churn
  run lifecycle "8 9 10 13" \
    cargo test --test adversarial_public_ingress \
      reload_rotation_long_lived_connections_and_log_flood_are_safe -- --exact
  relay_idle
  graceful_drain
  resource_smoke
}

systemd_gate() {
  evidence_profile="systemd"
  run systemd "16 17" \
    cargo test --test adversarial_public_ingress \
      real_systemd_crash_restart_and_sandbox_denial -- --ignored --exact
}

main() {
  cd "$REPOSITORY_ROOT"
  local mode="${1:---smoke}"
  case "$mode" in
    --smoke)
      evidence_profile="smoke"
      smoke
      printf '{"summary":"passed","profile":"smoke","scenarios_passed":17,"scenarios_exercised":18,"q26_qualified":false}\n'
      ;;
    --systemd)
      systemd_gate
      printf '{"summary":"passed","profile":"systemd","scenarios_passed":2}\n'
      ;;
    --all)
      evidence_profile="smoke"
      smoke
      systemd_gate
      printf '{"summary":"passed","profile":"all","scenarios_passed":19,"scenarios_exercised":20,"q26_qualified":false}\n'
      ;;
    --qualification)
      evidence_profile="qualification"
      printf 'phase8: qualification-load\n' >&2
      qualification_host_gate
      local qualification_log
      qualification_log="$(mktemp)"
      if ! PHX_PORT_PHASE8_PROFILE=qualification \
        cargo test --test adversarial_public_ingress \
          mixed_load_and_fd_pressure_recover_to_baseline -- --exact --nocapture \
          2>&1 | tee "$qualification_log"; then
        rm -f "$qualification_log"
        exit 1
      fi
      local qualification_tests
      qualification_tests="$(qualification_passing_test_count "$qualification_log")"
      rm -f "$qualification_log"
      if [[ "$qualification_tests" != "1" ]]; then
        printf 'qualification did not execute exactly one passing Linux gate\n' >&2
        exit 1
      fi
      emit qualification-load passed 19 20
      printf '{"summary":"passed","profile":"qualification","scenarios_passed":2,"q26_qualified":true,"representative_whole_host_workload_soak_completed":false}\n'
      ;;
    *)
      printf 'usage: %s [--smoke|--systemd|--all|--qualification]\n' "$0" >&2
      exit 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
