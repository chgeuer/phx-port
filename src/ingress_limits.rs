use std::time::Duration;

#[cfg(unix)]
use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, rlim_t, setrlimit};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::{Component, Path, PathBuf};

pub const DAEMON_USAGE: &str = "\
Usage: phx-port daemon [--listen ADDRESS]...
       [--active-connections N] [--pre-routing-connections N]
       [--relay-connections N] [--handoff-negotiations N]
       [--accepts-per-second N] [--accept-burst N]
       [--client-hello-timeout-ms N] [--task-budget N]";

const MAX_THREADED_ACTIVE_CONNECTIONS: usize = 256;
const MIN_CLIENT_HELLO_TIMEOUT_MS: u64 = 500;
const MAX_CLIENT_HELLO_TIMEOUT_MS: u64 = 10_000;
const CERTIFICATE_PROBE_WORKERS: usize = 32;
const AUXILIARY_TASKS: usize = 4;
const CONTROL_AND_STATE_FILE_DESCRIPTORS: usize = 8;
const RELAY_ADDITIONAL_FILE_DESCRIPTORS: usize = 3;
const FILE_DESCRIPTOR_RESERVE_PERCENT: u64 = 30;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressLimits {
    pub active_connections: usize,
    pub pre_routing_connections: usize,
    pub relay_connections: usize,
    pub handoff_negotiations: usize,
    pub accepts_per_second: usize,
    pub accept_burst: usize,
    pub client_hello_timeout_ms: u64,
}

impl Default for IngressLimits {
    fn default() -> Self {
        Self {
            active_connections: MAX_THREADED_ACTIVE_CONNECTIONS,
            pre_routing_connections: 128,
            relay_connections: 128,
            handoff_negotiations: 64,
            accepts_per_second: 200,
            accept_burst: 400,
            client_hello_timeout_ms: 2_000,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    pub listen_addresses: Vec<String>,
    pub limits: IngressLimits,
    pub task_budget: Option<usize>,
}

impl DaemonConfig {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut listen_addresses = Vec::new();
        let mut limits = IngressLimits::default();
        let mut task_budget = None;
        let mut index = 0;

        while index < args.len() {
            let option = args[index].as_str();
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{option} requires a value"))?;
            match option {
                "--listen" => listen_addresses.push(value.clone()),
                "--active-connections" => {
                    limits.active_connections = parse_usize(value, "active_connections")?;
                }
                "--pre-routing-connections" => {
                    limits.pre_routing_connections = parse_usize(value, "pre_routing_connections")?;
                }
                "--relay-connections" => {
                    limits.relay_connections = parse_usize(value, "relay_connections")?;
                }
                "--handoff-negotiations" => {
                    limits.handoff_negotiations = parse_usize(value, "handoff_negotiations")?;
                }
                "--accepts-per-second" => {
                    limits.accepts_per_second = parse_usize(value, "accepts_per_second")?;
                }
                "--accept-burst" => {
                    limits.accept_burst = parse_usize(value, "accept_burst")?;
                }
                "--client-hello-timeout-ms" => {
                    limits.client_hello_timeout_ms = parse_u64(value, "client_hello_timeout_ms")?;
                }
                "--task-budget" => {
                    task_budget = Some(parse_usize(value, "task_budget")?);
                }
                _ => return Err(format!("unknown argument for daemon: {option}")),
            }
            index += 2;
        }

        if listen_addresses.is_empty() {
            listen_addresses.extend(["0.0.0.0:443".to_string(), "[::]:443".to_string()]);
        }

        Ok(Self {
            listen_addresses,
            limits,
            task_budget,
        })
    }
}

fn parse_usize(value: &str, field: &str) -> Result<usize, String> {
    value.parse::<usize>().map_err(|_| {
        format!("{field} must be a non-negative integer that fits this platform, got {value:?}")
    })
}

fn parse_u64(value: &str, field: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{field} must be a non-negative integer, got {value:?}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemCapacity {
    pub(crate) file_descriptors: Option<u64>,
    pub(crate) tasks: Option<u64>,
}

impl SystemCapacity {
    fn detect(
        configured_task_budget: Option<usize>,
        minimum_file_descriptor_limit: u64,
    ) -> Result<Self, String> {
        let configured_task_budget = configured_task_budget
            .map(|value| {
                u64::try_from(value)
                    .map_err(|_| "task_budget does not fit the system capacity model".to_string())
            })
            .transpose()?;
        let system_task_budget = detect_system_task_budget()?;
        let tasks = match (configured_task_budget, system_task_budget) {
            (Some(configured), Some(system)) => Some(configured.min(system)),
            (configured, system) => configured.or(system),
        };

        Ok(Self {
            file_descriptors: detect_file_descriptor_limit(minimum_file_descriptor_limit)?,
            tasks,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceDemand {
    file_descriptors: usize,
    tasks: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedIngressLimits {
    limits: IngressLimits,
}

impl ValidatedIngressLimits {
    pub fn active_connections(&self) -> usize {
        self.limits.active_connections
    }

    pub fn pre_routing_connections(&self) -> usize {
        self.limits.pre_routing_connections
    }

    pub fn relay_connections(&self) -> usize {
        self.limits.relay_connections
    }

    pub fn handoff_negotiations(&self) -> usize {
        self.limits.handoff_negotiations
    }

    pub fn accepts_per_second(&self) -> usize {
        self.limits.accepts_per_second
    }

    pub fn accept_burst(&self) -> usize {
        self.limits.accept_burst
    }

    pub fn client_hello_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.client_hello_timeout_ms)
    }
}

impl IngressLimits {
    pub fn validate_for_startup(
        self,
        configured_task_budget: Option<usize>,
        listener_count: usize,
    ) -> Result<ValidatedIngressLimits, String> {
        if configured_task_budget == Some(0) {
            return Err("task_budget must be greater than zero".to_string());
        }
        let demand = self.resource_demand(listener_count)?;
        let required_file_descriptors = u64::try_from(demand.file_descriptors)
            .map_err(|_| "file descriptor demand does not fit u64".to_string())?;
        let minimum_file_descriptor_limit =
            minimum_limit_with_reserve(required_file_descriptors, FILE_DESCRIPTOR_RESERVE_PERCENT)?;
        let system = SystemCapacity::detect(configured_task_budget, minimum_file_descriptor_limit)?;
        self.validate_system_capacity(system, demand)
    }

    #[cfg(test)]
    pub fn validate(
        self,
        system: SystemCapacity,
        listener_count: usize,
    ) -> Result<ValidatedIngressLimits, String> {
        let demand = self.resource_demand(listener_count)?;
        self.validate_system_capacity(system, demand)
    }

    fn resource_demand(&self, listener_count: usize) -> Result<ResourceDemand, String> {
        for (field, value) in [
            ("active_connections", self.active_connections),
            ("pre_routing_connections", self.pre_routing_connections),
            ("relay_connections", self.relay_connections),
            ("handoff_negotiations", self.handoff_negotiations),
            ("accepts_per_second", self.accepts_per_second),
            ("accept_burst", self.accept_burst),
        ] {
            if value == 0 {
                return Err(format!("{field} must be greater than zero"));
            }
        }
        if self.client_hello_timeout_ms == 0 {
            return Err("client_hello_timeout_ms must be greater than zero".to_string());
        }
        if listener_count == 0 {
            return Err("at least one ingress listener is required".to_string());
        }

        validate_sublimit(
            "pre_routing_connections",
            self.pre_routing_connections,
            self.active_connections,
        )?;
        validate_sublimit(
            "relay_connections",
            self.relay_connections,
            self.active_connections,
        )?;
        validate_sublimit(
            "handoff_negotiations",
            self.handoff_negotiations,
            self.active_connections,
        )?;

        if !(MIN_CLIENT_HELLO_TIMEOUT_MS..=MAX_CLIENT_HELLO_TIMEOUT_MS)
            .contains(&self.client_hello_timeout_ms)
        {
            return Err(format!(
                "client_hello_timeout_ms must be between {MIN_CLIENT_HELLO_TIMEOUT_MS} and \
                 {MAX_CLIENT_HELLO_TIMEOUT_MS}, got {}",
                self.client_hello_timeout_ms
            ));
        }

        let relay_file_descriptors = self
            .relay_connections
            .checked_mul(RELAY_ADDITIONAL_FILE_DESCRIPTORS)
            .ok_or_else(|| {
                "file descriptor demand overflowed while validating relay_connections".to_string()
            })?;
        let required_file_descriptors = checked_sum(
            &[
                self.active_connections,
                relay_file_descriptors,
                self.handoff_negotiations,
                CERTIFICATE_PROBE_WORKERS,
                listener_count,
                CONTROL_AND_STATE_FILE_DESCRIPTORS,
            ],
            "file descriptor",
        )?;
        let required_tasks = checked_sum(
            &[
                self.active_connections,
                self.relay_connections,
                CERTIFICATE_PROBE_WORKERS,
                listener_count,
                AUXILIARY_TASKS,
            ],
            "task",
        )?;

        if self.active_connections > MAX_THREADED_ACTIVE_CONNECTIONS {
            return Err(format!(
                "active_connections must not exceed the threaded runtime cap of \
                 {MAX_THREADED_ACTIVE_CONNECTIONS}, got {}",
                self.active_connections
            ));
        }

        Ok(ResourceDemand {
            file_descriptors: required_file_descriptors,
            tasks: required_tasks,
        })
    }

    fn validate_system_capacity(
        self,
        system: SystemCapacity,
        demand: ResourceDemand,
    ) -> Result<ValidatedIngressLimits, String> {
        if let Some(limit) = system.file_descriptors {
            let reserve = percentage_rounded_up(limit, FILE_DESCRIPTOR_RESERVE_PERCENT);
            let available = limit.saturating_sub(reserve);
            let required = u64::try_from(demand.file_descriptors)
                .map_err(|_| "file descriptor demand does not fit u64".to_string())?;
            if required > available {
                return Err(format!(
                    "ingress limits require {required} file descriptors, but RLIMIT_NOFILE={limit} \
                     allows at most {available} after the required \
                     {FILE_DESCRIPTOR_RESERVE_PERCENT}% reserve; raise RLIMIT_NOFILE or lower \
                     active_connections, relay_connections, or handoff_negotiations"
                ));
            }
        }

        if let Some(limit) = system.tasks {
            if limit == 0 {
                return Err("task_budget must be greater than zero".to_string());
            }
            let required = u64::try_from(demand.tasks)
                .map_err(|_| "task demand does not fit u64".to_string())?;
            if required > limit {
                return Err(format!(
                    "ingress limits require up to {required} tasks, but the configured/systemd \
                     task budget is {limit}; raise TasksMax or --task-budget, or lower \
                     active_connections or relay_connections"
                ));
            }
        }

        Ok(ValidatedIngressLimits { limits: self })
    }
}

fn validate_sublimit(field: &str, value: usize, active_connections: usize) -> Result<(), String> {
    if value > active_connections {
        return Err(format!(
            "{field} ({value}) must not exceed active_connections ({active_connections})"
        ));
    }
    Ok(())
}

fn checked_sum(values: &[usize], resource: &str) -> Result<usize, String> {
    values.iter().try_fold(0_usize, |total, value| {
        total
            .checked_add(*value)
            .ok_or_else(|| format!("{resource} demand overflowed while validating ingress limits"))
    })
}

fn percentage_rounded_up(value: u64, percent: u64) -> u64 {
    let whole = (value / 100) * percent;
    let remainder = ((value % 100) * percent).div_ceil(100);
    whole + remainder
}

fn minimum_limit_with_reserve(required: u64, reserve_percent: u64) -> Result<u64, String> {
    let usable_percent = 100_u64
        .checked_sub(reserve_percent)
        .filter(|value| *value > 0)
        .ok_or_else(|| "file descriptor reserve must be below 100%".to_string())?;
    let whole = (required / usable_percent)
        .checked_mul(100)
        .ok_or_else(|| "RLIMIT_NOFILE requirement overflowed".to_string())?;
    let remainder = ((required % usable_percent) * 100).div_ceil(usable_percent);
    whole
        .checked_add(remainder)
        .ok_or_else(|| "RLIMIT_NOFILE requirement overflowed".to_string())
}

#[cfg(unix)]
fn detect_file_descriptor_limit(minimum: u64) -> Result<Option<u64>, String> {
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE)
        .map_err(|error| format!("cannot read RLIMIT_NOFILE: {error}"))?;
    if soft == RLIM_INFINITY {
        return Ok(None);
    }
    if soft >= minimum {
        return Ok(Some(soft));
    }
    if hard != RLIM_INFINITY && hard < minimum {
        return Err(format!(
            "RLIMIT_NOFILE soft limit {soft} cannot be raised to the required {minimum} because \
             the hard limit is {hard}; raise the hard limit or lower active_connections, \
             relay_connections, or handoff_negotiations"
        ));
    }

    let requested = to_rlim_t(minimum)?;
    setrlimit(Resource::RLIMIT_NOFILE, requested, hard).map_err(|error| {
        let hard = if hard == RLIM_INFINITY {
            "unlimited".to_string()
        } else {
            hard.to_string()
        };
        format!(
            "cannot raise RLIMIT_NOFILE soft limit from {soft} to the required {minimum} \
             (hard limit {hard}): {error}; lower ingress limits or raise the operating-system \
             per-process file limit"
        )
    })?;
    let (effective, _) = getrlimit(Resource::RLIMIT_NOFILE)
        .map_err(|error| format!("cannot verify raised RLIMIT_NOFILE: {error}"))?;
    if effective != RLIM_INFINITY && effective < minimum {
        return Err(format!(
            "RLIMIT_NOFILE remained {effective} after requesting {minimum}; lower ingress limits \
             or raise the operating-system per-process file limit"
        ));
    }
    eprintln!(
        "Raised RLIMIT_NOFILE soft limit from {soft} to {effective} for the configured ingress \
         capacity"
    );
    Ok((effective != RLIM_INFINITY).then_some(effective))
}

#[cfg(unix)]
#[allow(clippy::useless_conversion)]
fn to_rlim_t(value: u64) -> Result<rlim_t, String> {
    value
        .try_into()
        .map_err(|_| format!("required RLIMIT_NOFILE {value} does not fit this platform"))
}

#[cfg(not(unix))]
fn detect_file_descriptor_limit(_minimum: u64) -> Result<Option<u64>, String> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn detect_system_task_budget() -> Result<Option<u64>, String> {
    let memberships = match fs::read_to_string("/proc/self/cgroup") {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot read /proc/self/cgroup: {error}")),
    };
    let Some((root, membership)) = task_cgroup(&memberships) else {
        return Ok(None);
    };
    let process_tasks = fs::read_dir("/proc/self/task")
        .map_err(|error| format!("cannot inspect current process tasks: {error}"))?
        .try_fold(0_u64, |count, entry| {
            entry
                .map(|_| count + 1)
                .map_err(|error| format!("cannot inspect current process tasks: {error}"))
        })?;
    let mut directory = join_cgroup_path(&root, membership)?;
    let mut limit = None;

    loop {
        let path = directory.join("pids.max");
        match fs::read_to_string(&path) {
            Ok(value) => {
                let value = value.trim();
                if value != "max" {
                    let maximum = value.parse::<u64>().map_err(|error| {
                        format!("invalid systemd task budget in {}: {error}", path.display())
                    })?;
                    let current_path = directory.join("pids.current");
                    let current = fs::read_to_string(&current_path)
                        .map_err(|error| {
                            format!(
                                "cannot read current systemd task use {}: {error}",
                                current_path.display()
                            )
                        })?
                        .trim()
                        .parse::<u64>()
                        .map_err(|error| {
                            format!(
                                "invalid current systemd task use in {}: {error}",
                                current_path.display()
                            )
                        })?;
                    let available = effective_task_budget(maximum, current, process_tasks)?;
                    limit = Some(limit.map_or(available, |value: u64| value.min(available)));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot read systemd task budget {}: {error}",
                    path.display()
                ));
            }
        }

        if directory == root {
            break;
        }
        if !directory.pop() || !directory.starts_with(&root) {
            return Err("systemd cgroup path escaped its controller root".to_string());
        }
    }

    Ok(limit)
}

#[cfg(target_os = "linux")]
fn effective_task_budget(maximum: u64, current: u64, process_tasks: u64) -> Result<u64, String> {
    let other_tasks = current.checked_sub(process_tasks).ok_or_else(|| {
        format!(
            "systemd reports {current} cgroup tasks, fewer than this process's {process_tasks} tasks"
        )
    })?;
    Ok(maximum.saturating_sub(other_tasks))
}

#[cfg(target_os = "linux")]
fn task_cgroup(memberships: &str) -> Option<(PathBuf, &str)> {
    let mut unified = None;
    let mut legacy = None;
    for line in memberships.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let membership = fields.next()?;
        if hierarchy == "0" && controllers.is_empty() {
            unified = Some((PathBuf::from("/sys/fs/cgroup"), membership));
        }
        if controllers
            .split(',')
            .any(|controller| controller == "pids")
        {
            legacy = Some((PathBuf::from("/sys/fs/cgroup/pids"), membership));
        }
    }
    legacy.or(unified)
}

#[cfg(target_os = "linux")]
fn join_cgroup_path(root: &Path, membership: &str) -> Result<PathBuf, String> {
    let mut path = root.to_path_buf();
    for component in Path::new(membership).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => path.push(part),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(format!("invalid cgroup membership path {membership:?}"));
            }
        }
    }
    Ok(path)
}

#[cfg(not(target_os = "linux"))]
fn detect_system_task_budget() -> Result<Option<u64>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{
        DaemonConfig, IngressLimits, SystemCapacity, minimum_limit_with_reserve,
        percentage_rounded_up,
    };
    #[cfg(target_os = "linux")]
    use super::{effective_task_budget, task_cgroup};

    fn capacity(file_descriptors: u64, tasks: u64) -> SystemCapacity {
        SystemCapacity {
            file_descriptors: Some(file_descriptors),
            tasks: Some(tasks),
        }
    }

    #[test]
    fn threaded_defaults_are_valid_and_capped_at_256() {
        let limits = IngressLimits::default();
        assert_eq!(limits.active_connections, 256);
        assert_eq!(
            limits
                .clone()
                .validate(capacity(2_048, 1_024), 2)
                .unwrap()
                .client_hello_timeout(),
            std::time::Duration::from_secs(2)
        );
    }

    #[test]
    fn every_required_limit_rejects_zero() {
        for field in [
            "active_connections",
            "pre_routing_connections",
            "relay_connections",
            "handoff_negotiations",
            "accepts_per_second",
            "accept_burst",
        ] {
            let mut limits = IngressLimits::default();
            match field {
                "active_connections" => limits.active_connections = 0,
                "pre_routing_connections" => limits.pre_routing_connections = 0,
                "relay_connections" => limits.relay_connections = 0,
                "handoff_negotiations" => limits.handoff_negotiations = 0,
                "accepts_per_second" => limits.accepts_per_second = 0,
                "accept_burst" => limits.accept_burst = 0,
                _ => unreachable!(),
            }
            let error = limits.validate(capacity(2_048, 1_024), 2).unwrap_err();
            assert!(
                error.contains(field),
                "unexpected error for {field}: {error}"
            );
        }

        let limits = IngressLimits {
            client_hello_timeout_ms: 0,
            ..IngressLimits::default()
        };
        assert!(
            limits
                .validate(capacity(2_048, 1_024), 2)
                .unwrap_err()
                .contains("client_hello_timeout_ms")
        );
    }

    #[test]
    fn sublimits_cannot_exceed_the_global_limit() {
        for field in [
            "pre_routing_connections",
            "relay_connections",
            "handoff_negotiations",
        ] {
            let mut limits = IngressLimits::default();
            match field {
                "pre_routing_connections" => limits.pre_routing_connections = 257,
                "relay_connections" => limits.relay_connections = 257,
                "handoff_negotiations" => limits.handoff_negotiations = 257,
                _ => unreachable!(),
            }
            let error = limits.validate(capacity(2_048, 2_048), 2).unwrap_err();
            assert!(
                error.contains(field),
                "unexpected error for {field}: {error}"
            );
        }
    }

    #[test]
    fn client_hello_timeout_stays_inside_the_accepted_range() {
        for timeout in [499, 10_001] {
            let limits = IngressLimits {
                client_hello_timeout_ms: timeout,
                ..IngressLimits::default()
            };
            assert!(
                limits
                    .validate(capacity(2_048, 1_024), 2)
                    .unwrap_err()
                    .contains("between 500 and 10000")
            );
        }
    }

    #[test]
    fn file_descriptor_validation_preserves_thirty_percent_reserve() {
        IngressLimits::default()
            .validate(capacity(1_066, 1_024), 2)
            .unwrap();
        let error = IngressLimits::default()
            .validate(capacity(1_065, 1_024), 2)
            .unwrap_err();
        assert!(error.contains("RLIMIT_NOFILE=1065"), "{error}");
        assert!(error.contains("30% reserve"), "{error}");
        assert_eq!(percentage_rounded_up(1_065, 30), 320);
        assert_eq!(minimum_limit_with_reserve(746, 30).unwrap(), 1_066);
    }

    #[test]
    fn task_demand_must_fit_the_configured_or_systemd_budget() {
        IngressLimits::default()
            .validate(capacity(2_048, 422), 2)
            .unwrap();
        let error = IngressLimits::default()
            .validate(capacity(2_048, 421), 2)
            .unwrap_err();
        assert!(error.contains("require up to 422 tasks"), "{error}");
        assert!(error.contains("task budget is 421"), "{error}");
    }

    #[test]
    fn capacity_arithmetic_overflow_fails_closed() {
        let limits = IngressLimits {
            active_connections: usize::MAX,
            pre_routing_connections: 1,
            relay_connections: usize::MAX,
            handoff_negotiations: 1,
            ..IngressLimits::default()
        };
        assert!(
            limits
                .validate(capacity(u64::MAX, u64::MAX), 2)
                .unwrap_err()
                .contains("overflowed")
        );
    }

    #[test]
    fn daemon_options_populate_typed_limits() {
        let args = [
            "--listen",
            "127.0.0.1:8443",
            "--active-connections",
            "200",
            "--pre-routing-connections",
            "100",
            "--relay-connections",
            "75",
            "--handoff-negotiations",
            "50",
            "--accepts-per-second",
            "150",
            "--accept-burst",
            "300",
            "--client-hello-timeout-ms",
            "1500",
            "--task-budget",
            "600",
        ]
        .map(str::to_string);

        let config = DaemonConfig::parse(&args).unwrap();
        assert_eq!(config.listen_addresses, ["127.0.0.1:8443"]);
        assert_eq!(
            config.limits,
            IngressLimits {
                active_connections: 200,
                pre_routing_connections: 100,
                relay_connections: 75,
                handoff_negotiations: 50,
                accepts_per_second: 150,
                accept_burst: 300,
                client_hello_timeout_ms: 1_500,
            }
        );
        assert_eq!(config.task_budget, Some(600));
    }

    #[test]
    fn oversized_cli_values_are_rejected() {
        let args = [
            "--active-connections".to_string(),
            format!("{}0", usize::MAX),
        ];
        assert!(
            DaemonConfig::parse(&args)
                .unwrap_err()
                .contains("fits this platform")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_unified_and_legacy_task_cgroups() {
        assert_eq!(
            task_cgroup("0::/user.slice/example.service\n"),
            Some((
                std::path::PathBuf::from("/sys/fs/cgroup"),
                "/user.slice/example.service"
            ))
        );
        assert_eq!(
            task_cgroup("4:cpu,cpuacct:/x\n3:memory:/x\n2:pids:/tasks\n"),
            Some((std::path::PathBuf::from("/sys/fs/cgroup/pids"), "/tasks"))
        );
        assert_eq!(
            task_cgroup("0::/unified\n2:pids:/legacy-tasks\n"),
            Some((
                std::path::PathBuf::from("/sys/fs/cgroup/pids"),
                "/legacy-tasks"
            ))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn task_budget_accounts_for_other_cgroup_occupants() {
        assert_eq!(effective_task_budget(512, 200, 1).unwrap(), 313);
        assert_eq!(effective_task_budget(512, 1, 1).unwrap(), 512);
        assert!(effective_task_budget(512, 0, 1).is_err());
    }
}
