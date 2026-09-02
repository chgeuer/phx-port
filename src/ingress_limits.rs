use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

#[cfg(unix)]
use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, rlim_t, setrlimit};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::{Component, Path};

pub const DAEMON_USAGE: &str = "\
Usage: phx-port daemon [--listen ADDRESS]... [--ingress-config PATH] [--run-as USER]
       [--active-connections N] [--pre-routing-connections N]
       [--relay-connections N] [--handoff-negotiations N]
       [--accepts-per-second N] [--accept-burst N]
       [--source-accepts-per-second N] [--source-accept-burst N]
       [--source-pre-routing-connections N] [--source-ipv6-prefix N]
       [--source-table-capacity N] [--source-entry-ttl-seconds N]
       [--source-policy CIDR=RATE,BURST,PRE_ROUTING[,IPV6_PREFIX]]...
       [--client-hello-timeout-ms N] [--task-budget N]";

const MAX_THREADED_ACTIVE_CONNECTIONS: usize = 256;
const MIN_CLIENT_HELLO_TIMEOUT_MS: u64 = 500;
const MAX_CLIENT_HELLO_TIMEOUT_MS: u64 = 10_000;
const CERTIFICATE_PROBE_WORKERS: usize = 32;
const AUXILIARY_TASKS: usize = 4;
const CONTROL_AND_STATE_FILE_DESCRIPTORS: usize = 8;
const RELAY_ADDITIONAL_FILE_DESCRIPTORS: usize = 3;
const FILE_DESCRIPTOR_RESERVE_PERCENT: u64 = 30;
const DEFAULT_SOURCE_TABLE_CAPACITY: usize = 4_096;
const DEFAULT_SOURCE_ENTRY_TTL_SECONDS: u64 = 300;
const MAX_SOURCE_POLICY_OVERRIDES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceCidr {
    network: IpAddr,
    prefix: u8,
}

impl SourceCidr {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        let (address, prefix) = value
            .rsplit_once('/')
            .ok_or_else(|| format!("source policy CIDR must include a prefix, got {value:?}"))?;
        let address = IpAddr::from_str(address)
            .map_err(|error| format!("invalid source policy address {address:?}: {error}"))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| format!("invalid source policy prefix {prefix:?}"))?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(format!(
                "source policy prefix for {address} must be between 0 and {maximum}, got {prefix}"
            ));
        }

        let network = match address {
            IpAddr::V4(address) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
        };
        Ok(Self { network, prefix })
    }

    pub(crate) fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(address) & mask == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(address) & mask == u128::from(network)
            }
            _ => false,
        }
    }

    pub(crate) fn prefix(self) -> u8 {
        self.prefix
    }

    pub(crate) fn is_ipv6(self) -> bool {
        self.network.is_ipv6()
    }
}

impl fmt::Display for SourceCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLimitOverride {
    pub cidr: SourceCidr,
    pub accepts_per_second: usize,
    pub accept_burst: usize,
    pub pre_routing_connections: usize,
    pub ipv6_prefix: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLimits {
    pub accepts_per_second: usize,
    pub accept_burst: usize,
    pub pre_routing_connections: usize,
    pub ipv6_prefix: u8,
    pub table_capacity: usize,
    pub entry_ttl_seconds: u64,
    pub overrides: Vec<SourceLimitOverride>,
}

impl Default for SourceLimits {
    fn default() -> Self {
        Self {
            accepts_per_second: 20,
            accept_burst: 40,
            pre_routing_connections: 16,
            ipv6_prefix: 64,
            table_capacity: DEFAULT_SOURCE_TABLE_CAPACITY,
            entry_ttl_seconds: DEFAULT_SOURCE_ENTRY_TTL_SECONDS,
            overrides: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressLimits {
    pub active_connections: usize,
    pub pre_routing_connections: usize,
    pub relay_connections: usize,
    pub handoff_negotiations: usize,
    pub accepts_per_second: usize,
    pub accept_burst: usize,
    pub client_hello_timeout_ms: u64,
    pub source: SourceLimits,
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
            source: SourceLimits::default(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    pub listen_addresses: Vec<String>,
    pub listeners_explicit: bool,
    pub ingress_config: Option<PathBuf>,
    pub run_as: Option<String>,
    pub limits: IngressLimits,
    pub task_budget: Option<usize>,
}

impl DaemonConfig {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut listen_addresses = Vec::new();
        let mut limits = IngressLimits::default();
        let mut task_budget = None;
        let mut ingress_config = None;
        let mut run_as = None;
        let mut index = 0;

        while index < args.len() {
            let option = args[index].as_str();
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{option} requires a value"))?;
            match option {
                "--listen" => listen_addresses.push(value.clone()),
                "--ingress-config" => {
                    if ingress_config.replace(PathBuf::from(value)).is_some() {
                        return Err("--ingress-config may be specified only once".to_string());
                    }
                }
                "--run-as" => {
                    if value.is_empty() {
                        return Err("--run-as requires a nonempty user name".to_string());
                    }
                    if run_as.replace(value.clone()).is_some() {
                        return Err("--run-as may be specified only once".to_string());
                    }
                }
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
                "--source-accepts-per-second" => {
                    limits.source.accepts_per_second =
                        parse_usize(value, "source_accepts_per_second")?;
                }
                "--source-accept-burst" => {
                    limits.source.accept_burst = parse_usize(value, "source_accept_burst")?;
                }
                "--source-pre-routing-connections" => {
                    limits.source.pre_routing_connections =
                        parse_usize(value, "source_pre_routing_connections")?;
                }
                "--source-ipv6-prefix" => {
                    limits.source.ipv6_prefix = parse_u8(value, "source_ipv6_prefix")?;
                }
                "--source-table-capacity" => {
                    limits.source.table_capacity = parse_usize(value, "source_table_capacity")?;
                }
                "--source-entry-ttl-seconds" => {
                    limits.source.entry_ttl_seconds = parse_u64(value, "source_entry_ttl_seconds")?;
                }
                "--source-policy" => {
                    limits.source.overrides.push(parse_source_policy(value)?);
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

        let listeners_explicit = !listen_addresses.is_empty();
        if run_as.is_some() && !listeners_explicit {
            return Err("--run-as requires at least one explicit --listen address".to_string());
        }
        if !listeners_explicit {
            listen_addresses.extend(["0.0.0.0:443".to_string(), "[::]:443".to_string()]);
        }

        Ok(Self {
            listen_addresses,
            listeners_explicit,
            ingress_config,
            run_as,
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

fn parse_u8(value: &str, field: &str) -> Result<u8, String> {
    value
        .parse::<u8>()
        .map_err(|_| format!("{field} must be an integer from 0 through 255, got {value:?}"))
}

fn parse_source_policy(value: &str) -> Result<SourceLimitOverride, String> {
    let (cidr, policy) = value.split_once('=').ok_or_else(|| {
        format!("--source-policy must use CIDR=RATE,BURST,PRE_ROUTING[,IPV6_PREFIX], got {value:?}")
    })?;
    let fields = policy.split(',').map(str::trim).collect::<Vec<_>>();
    if !(3..=4).contains(&fields.len()) {
        return Err(format!(
            "--source-policy must use CIDR=RATE,BURST,PRE_ROUTING[,IPV6_PREFIX], got {value:?}"
        ));
    }

    let cidr = SourceCidr::parse(cidr.trim())?;
    let ipv6_prefix = fields
        .get(3)
        .map(|value| parse_u8(value, "source policy ipv6_prefix"))
        .transpose()?;
    if ipv6_prefix.is_some() && !cidr.is_ipv6() {
        return Err(format!(
            "source policy {cidr} cannot set an IPv6 bucket prefix"
        ));
    }

    Ok(SourceLimitOverride {
        cidr,
        accepts_per_second: parse_usize(fields[0], "source policy accepts_per_second")?,
        accept_burst: parse_usize(fields[1], "source policy accept_burst")?,
        pre_routing_connections: parse_usize(fields[2], "source policy pre_routing_connections")?,
        ipv6_prefix,
    })
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

    pub(crate) fn source(&self) -> &SourceLimits {
        &self.limits.source
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
            ("source_accepts_per_second", self.source.accepts_per_second),
            ("source_accept_burst", self.source.accept_burst),
            (
                "source_pre_routing_connections",
                self.source.pre_routing_connections,
            ),
            ("source_table_capacity", self.source.table_capacity),
        ] {
            if value == 0 {
                return Err(format!("{field} must be greater than zero"));
            }
        }
        if self.source.entry_ttl_seconds == 0 {
            return Err("source_entry_ttl_seconds must be greater than zero".to_string());
        }
        if self.source.ipv6_prefix > 128 {
            return Err(format!(
                "source_ipv6_prefix must be between 0 and 128, got {}",
                self.source.ipv6_prefix
            ));
        }
        if self.source.overrides.len() > MAX_SOURCE_POLICY_OVERRIDES {
            return Err(format!(
                "source policy override count must not exceed {MAX_SOURCE_POLICY_OVERRIDES}, got {}",
                self.source.overrides.len()
            ));
        }
        let mut source_cidrs = std::collections::BTreeSet::new();
        for policy in &self.source.overrides {
            for (field, value) in [
                (
                    "source policy accepts_per_second",
                    policy.accepts_per_second,
                ),
                ("source policy accept_burst", policy.accept_burst),
                (
                    "source policy pre_routing_connections",
                    policy.pre_routing_connections,
                ),
            ] {
                if value == 0 {
                    return Err(format!("{field} must be greater than zero"));
                }
            }
            if !source_cidrs.insert(policy.cidr) {
                return Err(format!("duplicate source policy CIDR {}", policy.cidr));
            }
            if let Some(prefix) = policy.ipv6_prefix {
                if prefix > 128 {
                    return Err(format!(
                        "IPv6 bucket prefix for source policy {} must be between 0 and 128, got \
                         {prefix}",
                        policy.cidr
                    ));
                }
                if prefix < policy.cidr.prefix() {
                    return Err(format!(
                        "IPv6 bucket prefix {prefix} for source policy {} must be at least its \
                         CIDR prefix {}",
                        policy.cidr,
                        policy.cidr.prefix()
                    ));
                }
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
        DaemonConfig, IngressLimits, SourceCidr, SourceLimitOverride, SourceLimits, SystemCapacity,
        minimum_limit_with_reserve, percentage_rounded_up,
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
        assert_eq!(limits.source.accepts_per_second, 20);
        assert_eq!(limits.source.accept_burst, 40);
        assert_eq!(limits.source.pre_routing_connections, 16);
        assert_eq!(limits.source.ipv6_prefix, 64);
        assert_eq!(limits.source.table_capacity, 4_096);
        assert_eq!(limits.source.entry_ttl_seconds, 300);
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
            "source_accepts_per_second",
            "source_accept_burst",
            "source_pre_routing_connections",
            "source_table_capacity",
        ] {
            let mut limits = IngressLimits::default();
            match field {
                "active_connections" => limits.active_connections = 0,
                "pre_routing_connections" => limits.pre_routing_connections = 0,
                "relay_connections" => limits.relay_connections = 0,
                "handoff_negotiations" => limits.handoff_negotiations = 0,
                "accepts_per_second" => limits.accepts_per_second = 0,
                "accept_burst" => limits.accept_burst = 0,
                "source_accepts_per_second" => limits.source.accepts_per_second = 0,
                "source_accept_burst" => limits.source.accept_burst = 0,
                "source_pre_routing_connections" => {
                    limits.source.pre_routing_connections = 0;
                }
                "source_table_capacity" => limits.source.table_capacity = 0,
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

        let mut limits = IngressLimits::default();
        limits.source.entry_ttl_seconds = 0;
        assert!(
            limits
                .validate(capacity(2_048, 1_024), 2)
                .unwrap_err()
                .contains("source_entry_ttl_seconds")
        );
    }

    #[test]
    fn source_prefix_and_cidr_policies_fail_closed_when_invalid() {
        let args = ["--source-ipv6-prefix", "129"].map(str::to_string);
        let error = DaemonConfig::parse(&args)
            .unwrap()
            .limits
            .validate(capacity(2_048, 1_024), 2)
            .unwrap_err();
        assert!(error.contains("source_ipv6_prefix"), "{error}");

        let args = [
            "--source-policy",
            "10.0.0.1/8=20,40,16",
            "--source-policy",
            "10.0.0.0/8=40,80,32",
        ]
        .map(str::to_string);
        let error = DaemonConfig::parse(&args)
            .unwrap()
            .limits
            .validate(capacity(2_048, 1_024), 2)
            .unwrap_err();
        assert!(error.contains("duplicate source policy CIDR 10.0.0.0/8"));

        let args = ["--source-policy", "2001:db8::/48=20,40,16,32"].map(str::to_string);
        let error = DaemonConfig::parse(&args)
            .unwrap()
            .limits
            .validate(capacity(2_048, 1_024), 2)
            .unwrap_err();
        assert!(
            error.contains("must be at least its CIDR prefix"),
            "{error}"
        );

        let args = ["--source-policy", "192.0.2.0/24=20,40,16,64"].map(str::to_string);
        let error = DaemonConfig::parse(&args).unwrap_err();
        assert!(
            error.contains("cannot set an IPv6 bucket prefix"),
            "{error}"
        );

        let policy = SourceLimitOverride {
            cidr: SourceCidr::parse("192.0.2.0/24").unwrap(),
            accepts_per_second: 20,
            accept_burst: 40,
            pre_routing_connections: 16,
            ipv6_prefix: None,
        };
        let mut limits = IngressLimits::default();
        limits.source.overrides = vec![policy; 257];
        let error = limits.validate(capacity(2_048, 1_024), 2).unwrap_err();
        assert!(error.contains("must not exceed 256"), "{error}");
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
            "--source-accepts-per-second",
            "25",
            "--source-accept-burst",
            "50",
            "--source-pre-routing-connections",
            "20",
            "--source-ipv6-prefix",
            "56",
            "--source-table-capacity",
            "8192",
            "--source-entry-ttl-seconds",
            "600",
            "--source-policy",
            "192.0.2.0/24=100,200,40",
            "--source-policy",
            "2001:db8::/32=50,100,30,48",
            "--client-hello-timeout-ms",
            "1500",
            "--task-budget",
            "600",
        ]
        .map(str::to_string);

        let config = DaemonConfig::parse(&args).unwrap();
        assert_eq!(config.listen_addresses, ["127.0.0.1:8443"]);
        assert!(config.listeners_explicit);
        assert_eq!(config.ingress_config, None);
        assert_eq!(config.run_as, None);
        let expected = IngressLimits {
            active_connections: 200,
            pre_routing_connections: 100,
            relay_connections: 75,
            handoff_negotiations: 50,
            accepts_per_second: 150,
            accept_burst: 300,
            client_hello_timeout_ms: 1_500,
            source: SourceLimits {
                accepts_per_second: 25,
                accept_burst: 50,
                pre_routing_connections: 20,
                ipv6_prefix: 56,
                table_capacity: 8_192,
                entry_ttl_seconds: 600,
                overrides: vec![
                    SourceLimitOverride {
                        cidr: SourceCidr::parse("192.0.2.0/24").unwrap(),
                        accepts_per_second: 100,
                        accept_burst: 200,
                        pre_routing_connections: 40,
                        ipv6_prefix: None,
                    },
                    SourceLimitOverride {
                        cidr: SourceCidr::parse("2001:db8::/32").unwrap(),
                        accepts_per_second: 50,
                        accept_burst: 100,
                        pre_routing_connections: 30,
                        ipv6_prefix: Some(48),
                    },
                ],
            },
        };
        assert_eq!(config.limits, expected);
        assert_eq!(config.task_budget, Some(600));
    }

    #[test]
    fn run_as_requires_explicit_listeners_and_is_parsed_once() {
        let missing = ["--run-as", "daemon-user"].map(str::to_string);
        assert!(
            DaemonConfig::parse(&missing)
                .unwrap_err()
                .contains("requires at least one explicit --listen")
        );

        let args = ["--run-as", "daemon-user", "--listen", "0.0.0.0:443"].map(str::to_string);
        let config = DaemonConfig::parse(&args).unwrap();
        assert_eq!(config.run_as.as_deref(), Some("daemon-user"));
        assert!(config.listeners_explicit);

        let duplicate = [
            "--run-as",
            "daemon-user",
            "--run-as",
            "other-user",
            "--listen",
            "0.0.0.0:443",
        ]
        .map(str::to_string);
        assert!(
            DaemonConfig::parse(&duplicate)
                .unwrap_err()
                .contains("may be specified only once")
        );
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
