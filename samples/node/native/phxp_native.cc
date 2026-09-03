#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <node_api.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

constexpr size_t kHeaderLength = 40;
constexpr size_t kMaxPacketLength = 512;
constexpr size_t kMaxSniLength = 253;
constexpr uint8_t kVersion = 1;
constexpr uint8_t kHello = 1;
constexpr uint8_t kReady = 2;
constexpr uint8_t kHandoff = 3;
constexpr uint8_t kAdopted = 4;
constexpr uint8_t kRejected = 5;
constexpr uint16_t kRejectInvalidDescriptor = 1;
constexpr uint16_t kRejectDuplicateId = 2;
constexpr uint16_t kRejectAdoptionFailed = 3;

#if defined(__linux__)
constexpr size_t kUnixPathMax = 107;
constexpr int kControlSocketType = SOCK_SEQPACKET;
#elif defined(__APPLE__)
constexpr size_t kUnixPathMax = 103;
constexpr int kControlSocketType = SOCK_STREAM;
#else
#error "PHXP Node integration supports only Linux and macOS"
#endif

class SystemError : public std::runtime_error {
 public:
  explicit SystemError(const std::string& message)
      : std::runtime_error(message + ": " + std::strerror(errno)) {}
};

void CheckNapi(napi_env env, napi_status status, const char* operation) {
  if (status == napi_ok) return;
  const napi_extended_error_info* info = nullptr;
  napi_get_last_error_info(env, &info);
  std::string message(operation);
  if (info != nullptr && info->error_message != nullptr) {
    message += ": ";
    message += info->error_message;
  }
  throw std::runtime_error(message);
}

uint16_t ReadU16(const uint8_t* bytes) {
  return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}

uint32_t ReadU32(const uint8_t* bytes) {
  return (static_cast<uint32_t>(bytes[0]) << 24) |
         (static_cast<uint32_t>(bytes[1]) << 16) |
         (static_cast<uint32_t>(bytes[2]) << 8) |
         static_cast<uint32_t>(bytes[3]);
}

uint64_t ReadU64(const uint8_t* bytes) {
  uint64_t result = 0;
  for (size_t index = 0; index < 8; ++index) result = (result << 8) | bytes[index];
  return result;
}

void WriteU16(uint8_t* bytes, uint16_t value) {
  bytes[0] = static_cast<uint8_t>(value >> 8);
  bytes[1] = static_cast<uint8_t>(value);
}

struct ParsedMessage {
  uint8_t type = 0;
  std::array<uint8_t, 16> connection_id{};
  uint32_t peeked_length = 0;
  uint64_t accepted_at_ns = 0;
  uint16_t rejection_code = 0;
  std::string requested_sni;
};

bool ValidUtf8(const uint8_t* bytes, size_t length) {
  size_t index = 0;
  while (index < length) {
    const uint8_t first = bytes[index++];
    if (first <= 0x7f) continue;
    int continuation = 0;
    uint32_t codepoint = 0;
    if ((first & 0xe0) == 0xc0) {
      continuation = 1;
      codepoint = first & 0x1f;
      if (codepoint < 2) return false;
    } else if ((first & 0xf0) == 0xe0) {
      continuation = 2;
      codepoint = first & 0x0f;
    } else if ((first & 0xf8) == 0xf0) {
      continuation = 3;
      codepoint = first & 0x07;
    } else {
      return false;
    }
    if (index + continuation > length) return false;
    for (int count = 0; count < continuation; ++count) {
      const uint8_t next = bytes[index++];
      if ((next & 0xc0) != 0x80) return false;
      codepoint = (codepoint << 6) | (next & 0x3f);
    }
    if ((continuation == 2 && codepoint < 0x800) ||
        (continuation == 3 && codepoint < 0x10000) ||
        codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
      return false;
    }
  }
  return true;
}

size_t FrameLength(const std::vector<uint8_t>& frame) {
  if (frame.size() < kHeaderLength) {
    throw std::runtime_error("PHXP packet is shorter than its fixed header");
  }
  if (std::memcmp(frame.data(), "PHXP", 4) != 0) {
    throw std::runtime_error("PHXP packet has invalid magic");
  }
  if (frame[4] != kVersion) {
    throw std::runtime_error("unsupported PHXP protocol version");
  }
  if (frame[5] < kHello || frame[5] > kRejected) {
    throw std::runtime_error("unknown PHXP message type");
  }
  if (ReadU16(frame.data() + 6) != 0) {
    throw std::runtime_error("PHXP packet uses unsupported flags");
  }
  const size_t length = kHeaderLength + ReadU16(frame.data() + 36);
  if (length > kMaxPacketLength) {
    throw std::runtime_error("PHXP packet exceeds protocol limit");
  }
  return length;
}

ParsedMessage Decode(const std::vector<uint8_t>& frame) {
  if (frame.size() != FrameLength(frame)) {
    throw std::runtime_error("PHXP payload length does not match packet");
  }
  ParsedMessage message;
  message.type = frame[5];
  std::copy(frame.begin() + 8, frame.begin() + 24, message.connection_id.begin());
  message.peeked_length = ReadU32(frame.data() + 24);
  message.accepted_at_ns = ReadU64(frame.data() + 28);
  const uint16_t payload_length = ReadU16(frame.data() + 36);
  message.rejection_code = ReadU16(frame.data() + 38);

  const std::array<uint8_t, 16> zero_id{};
  if (message.type == kHello || message.type == kReady) {
    if (message.connection_id != zero_id || message.peeked_length != 0 ||
        message.accepted_at_ns != 0 || payload_length != 0 ||
        message.rejection_code != 0) {
      throw std::runtime_error("PHXP handshake has unexpected field values");
    }
    return message;
  }
  if (message.type == kHandoff) {
    if (payload_length == 0 || payload_length > kMaxSniLength ||
        message.rejection_code != 0) {
      throw std::runtime_error("PHXP handoff request has invalid field values");
    }
    const uint8_t* payload = frame.data() + kHeaderLength;
    if (!ValidUtf8(payload, payload_length)) {
      throw std::runtime_error("PHXP handoff SNI is not valid UTF-8");
    }
    message.requested_sni.assign(reinterpret_cast<const char*>(payload), payload_length);
    return message;
  }
  if (payload_length != 0 || message.peeked_length != 0 ||
      message.accepted_at_ns != 0) {
    throw std::runtime_error("PHXP response has unexpected field values");
  }
  if (message.type == kAdopted && message.rejection_code != 0) {
    throw std::runtime_error("PHXP response has unexpected field values");
  }
  if (message.type == kRejected && message.rejection_code == 0) {
    throw std::runtime_error("PHXP rejection has invalid field values");
  }
  return message;
}

std::vector<uint8_t> Response(uint8_t type,
                              const std::array<uint8_t, 16>& connection_id = {},
                              uint16_t rejection_code = 0) {
  std::vector<uint8_t> frame(kHeaderLength, 0);
  std::memcpy(frame.data(), "PHXP", 4);
  frame[4] = kVersion;
  frame[5] = type;
  std::copy(connection_id.begin(), connection_id.end(), frame.begin() + 8);
  WriteU16(frame.data() + 38, rejection_code);
  return frame;
}

void CloseFd(int* fd) {
  if (*fd >= 0) {
    const int owned = *fd;
    *fd = -1;
    close(owned);
  }
}

void SetCloseOnExec(int fd) {
  const int flags = fcntl(fd, F_GETFD);
  if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
    throw SystemError("set descriptor close-on-exec");
  }
}

void SetNonblocking(int fd, bool enabled) {
  const int flags = fcntl(fd, F_GETFL);
  if (flags < 0) throw SystemError("inspect descriptor status flags");
  const int updated = enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK;
  if (fcntl(fd, F_SETFL, updated) < 0) throw SystemError("configure descriptor blocking mode");
}

void ConfigureNoSigpipe(int fd) {
#if defined(__APPLE__)
  int enabled = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) < 0) {
    throw SystemError("disable SIGPIPE on PHXP socket");
  }
#else
  (void)fd;
#endif
}

void ConfigureTimeout(int fd, int timeout_ms) {
  timeval timeout{};
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
    throw SystemError("configure PHXP control timeout");
  }
}

uid_t PeerEuid(int fd) {
#if defined(__linux__)
  ucred credentials{};
  socklen_t length = sizeof(credentials);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) < 0) {
    throw SystemError("inspect PHXP peer credentials");
  }
  if (length != sizeof(credentials)) throw std::runtime_error("PHXP peer credentials are malformed");
  return credentials.uid;
#elif defined(__APPLE__)
  uid_t uid = 0;
  gid_t gid = 0;
  if (getpeereid(fd, &uid, &gid) < 0) {
    throw SystemError("inspect PHXP peer credentials");
  }
  return uid;
#endif
}

void AuthenticatePeer(int fd) {
  if (PeerEuid(fd) != geteuid()) {
    throw std::runtime_error("PHXP peer belongs to a different user");
  }
}

struct ReceivedFrame {
  std::vector<uint8_t> bytes;
  std::vector<int> descriptors;
};

void CloseDescriptors(std::vector<int>* descriptors) {
  for (int descriptor : *descriptors) {
    int fd = descriptor;
    CloseFd(&fd);
  }
  descriptors->clear();
}

std::vector<int> ParseDescriptors(msghdr* message) {
  std::vector<int> descriptors;
  try {
    for (cmsghdr* control = CMSG_FIRSTHDR(message); control != nullptr;
         control = CMSG_NXTHDR(message, control)) {
      if (control->cmsg_level != SOL_SOCKET || control->cmsg_type != SCM_RIGHTS ||
          control->cmsg_len < CMSG_LEN(0) ||
          (control->cmsg_len - CMSG_LEN(0)) % sizeof(int) != 0) {
        throw std::runtime_error("PHXP HANDOFF contains malformed ancillary data");
      }
      const size_t count = (control->cmsg_len - CMSG_LEN(0)) / sizeof(int);
      const int* rights = reinterpret_cast<const int*>(CMSG_DATA(control));
      for (size_t index = 0; index < count; ++index) descriptors.push_back(rights[index]);
    }
    for (int descriptor : descriptors) SetCloseOnExec(descriptor);
    return descriptors;
  } catch (...) {
    CloseDescriptors(&descriptors);
    throw;
  }
}

ReceivedFrame ReceiveFrame(int fd, bool allow_descriptors) {
  std::array<uint8_t, kMaxPacketLength + 1> packet{};
  alignas(cmsghdr) std::array<uint8_t, CMSG_SPACE(sizeof(int) * 4)> ancillary{};
  iovec vector{packet.data(), packet.size()};
  msghdr message{};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = ancillary.data();
  message.msg_controllen = ancillary.size();
  int flags = 0;
#if defined(__linux__)
  flags = MSG_CMSG_CLOEXEC;
#endif
  ssize_t received;
  do {
    received = recvmsg(fd, &message, flags);
  } while (received < 0 && errno == EINTR);
  if (received < 0) throw SystemError("receive PHXP frame");
  if (received == 0) throw std::runtime_error("unexpected EOF in PHXP frame");

  ReceivedFrame result;
  result.descriptors = ParseDescriptors(&message);
  try {
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
        static_cast<size_t>(received) > kMaxPacketLength) {
      throw std::runtime_error("PHXP packet or ancillary data was truncated");
    }
    if (!allow_descriptors && !result.descriptors.empty()) {
      throw std::runtime_error("PHXP non-HANDOFF frame contained ancillary data");
    }
    result.bytes.assign(packet.begin(), packet.begin() + received);
#if defined(__APPLE__)
    while (result.bytes.size() < kHeaderLength) {
      const size_t remaining = kHeaderLength - result.bytes.size();
      std::array<uint8_t, kHeaderLength> chunk{};
      ssize_t count;
      do {
        count = recv(fd, chunk.data(), remaining, 0);
      } while (count < 0 && errno == EINTR);
      if (count <= 0) throw std::runtime_error("unexpected EOF in PHXP frame header");
      result.bytes.insert(result.bytes.end(), chunk.begin(), chunk.begin() + count);
    }
    const size_t expected = FrameLength(result.bytes);
    if (result.bytes.size() > expected) {
      throw std::runtime_error("PHXP stream contains bytes beyond the declared frame");
    }
    while (result.bytes.size() < expected) {
      const size_t remaining = expected - result.bytes.size();
      std::array<uint8_t, kMaxPacketLength> chunk{};
      ssize_t count;
      do {
        count = recv(fd, chunk.data(), remaining, 0);
      } while (count < 0 && errno == EINTR);
      if (count <= 0) throw std::runtime_error("unexpected EOF in PHXP frame payload");
      result.bytes.insert(result.bytes.end(), chunk.begin(), chunk.begin() + count);
    }
#endif
    return result;
  } catch (...) {
    CloseDescriptors(&result.descriptors);
    throw;
  }
}

void SendFrame(int fd, const std::vector<uint8_t>& frame) {
#if defined(__linux__)
  ssize_t sent;
  do {
    sent = send(fd, frame.data(), frame.size(), MSG_NOSIGNAL);
  } while (sent < 0 && errno == EINTR);
  if (sent < 0) throw SystemError("send PHXP frame");
  if (static_cast<size_t>(sent) != frame.size()) {
    throw std::runtime_error("PHXP seqpacket response was partially sent");
  }
#elif defined(__APPLE__)
  size_t offset = 0;
  while (offset < frame.size()) {
    ssize_t sent;
    do {
      sent = send(fd, frame.data() + offset, frame.size() - offset, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) throw SystemError("send PHXP frame");
    if (sent == 0) throw std::runtime_error("unexpected EOF while sending PHXP frame");
    offset += static_cast<size_t>(sent);
  }
#endif
}

bool InternetAddress(const sockaddr_storage& address) {
  return address.ss_family == AF_INET || address.ss_family == AF_INET6;
}

void ValidateConnectedTcp(int fd) {
  int socket_type = 0;
  socklen_t option_length = sizeof(socket_type);
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &option_length) < 0) {
    throw SystemError("inspect handed-off descriptor type");
  }
  if (socket_type != SOCK_STREAM) {
    throw std::runtime_error("handed-off descriptor is not a stream socket");
  }
  int tcp_option = 0;
  option_length = sizeof(tcp_option);
  if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &tcp_option, &option_length) < 0) {
    throw std::runtime_error("handed-off stream is not TCP");
  }
  sockaddr_storage peer{};
  sockaddr_storage local{};
  socklen_t peer_length = sizeof(peer);
  socklen_t local_length = sizeof(local);
  if (getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &peer_length) < 0) {
    throw std::runtime_error("handed-off TCP descriptor is not connected");
  }
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_length) < 0) {
    throw SystemError("inspect handed-off TCP local address");
  }
  if (!InternetAddress(peer) || !InternetAddress(local)) {
    throw std::runtime_error("handed-off descriptor lacks Internet socket addresses");
  }
  SetCloseOnExec(fd);
  SetNonblocking(fd, true);
  const int descriptor_flags = fcntl(fd, F_GETFD);
  const int status_flags = fcntl(fd, F_GETFL);
  if (descriptor_flags < 0 || status_flags < 0 ||
      (descriptor_flags & FD_CLOEXEC) == 0 || (status_flags & O_NONBLOCK) == 0) {
    throw std::runtime_error("adopted descriptor policy could not be enforced");
  }
}

std::string IdKey(const std::array<uint8_t, 16>& id) {
  return std::string(reinterpret_cast<const char*>(id.data()), id.size());
}

std::string ParentPath(const std::string& path) {
  const size_t slash = path.find_last_of('/');
  if (slash == std::string::npos) return {};
  if (slash == 0) return "/";
  return path.substr(0, slash);
}

struct EndpointIdentity {
  dev_t device = 0;
  ino_t inode = 0;
};

void EnsurePrivateDirectory(const std::string& path) {
  if (mkdir(path.c_str(), 0700) < 0 && errno != EEXIST) {
    throw SystemError("create PHXP directory " + path);
  }
  struct stat info {};
  if (lstat(path.c_str(), &info) < 0) throw SystemError("inspect PHXP directory " + path);
  if (!S_ISDIR(info.st_mode)) {
    throw std::runtime_error("PHXP directory is not a directory: " + path);
  }
  if (info.st_uid != geteuid()) {
    throw std::runtime_error("PHXP directory belongs to a different user: " + path);
  }
  if ((info.st_mode & 0077) != 0) {
    throw std::runtime_error("PHXP directory grants group or other permissions: " + path);
  }
  if ((info.st_mode & 0700) != 0700) {
    throw std::runtime_error("PHXP directory must grant its owner read, write, and search access: " +
                             path);
  }
}

int CreateControlSocket() {
#if defined(__linux__)
  const int fd = socket(AF_UNIX, kControlSocketType | SOCK_CLOEXEC, 0);
#else
  const int fd = socket(AF_UNIX, kControlSocketType, 0);
#endif
  if (fd < 0) throw SystemError("create PHXP control socket");
  try {
    SetCloseOnExec(fd);
    ConfigureNoSigpipe(fd);
    return fd;
  } catch (...) {
    int owned = fd;
    CloseFd(&owned);
    throw;
  }
}

sockaddr_un UnixAddress(const std::string& path) {
  if (path.empty() || path[0] != '/' || path.size() > kUnixPathMax) {
    throw std::runtime_error("PHXP endpoint must be an absolute path within platform bounds");
  }
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
  return address;
}

bool EndpointIsLive(const std::string& path) {
  int fd = -1;
  try {
    fd = CreateControlSocket();
    SetNonblocking(fd, true);
    const sockaddr_un address = UnixAddress(path);
    const int result =
        connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
    const bool live =
        result == 0 || errno == EINPROGRESS || errno == EALREADY ||
        errno == EAGAIN || errno == EWOULDBLOCK;
    CloseFd(&fd);
    return live;
  } catch (...) {
    CloseFd(&fd);
    return false;
  }
}

void PrepareEndpoint(const std::string& path, bool validate_runtime_root) {
  const std::string parent = ParentPath(path);
  if (parent.empty() || parent == "/") {
    throw std::runtime_error("PHXP endpoint must have an absolute private parent directory");
  }
  if (validate_runtime_root) {
    const std::string runtime = ParentPath(parent);
    if (runtime.empty() || runtime == "/") {
      throw std::runtime_error("PHXP development runtime root is invalid");
    }
    EnsurePrivateDirectory(runtime);
  }
  EnsurePrivateDirectory(parent);

  struct stat original {};
  if (lstat(path.c_str(), &original) < 0) {
    if (errno == ENOENT) return;
    throw SystemError("inspect PHXP endpoint " + path);
  }
  if (!S_ISSOCK(original.st_mode)) {
    throw std::runtime_error("refusing to replace non-socket PHXP path " + path);
  }
  if (original.st_uid != geteuid()) {
    throw std::runtime_error("PHXP endpoint belongs to a different user");
  }
  if (EndpointIsLive(path)) {
    throw std::runtime_error("another PHXP receiver is already listening at " + path);
  }
  struct stat current {};
  if (lstat(path.c_str(), &current) < 0) {
    throw SystemError("reinspect stale PHXP endpoint " + path);
  }
  if (current.st_dev != original.st_dev || current.st_ino != original.st_ino) {
    throw std::runtime_error("PHXP endpoint changed during stale-socket inspection");
  }
  if (unlink(path.c_str()) < 0) throw SystemError("remove stale PHXP endpoint " + path);
}

enum class PendingState {
  kQueued,
  kInCallback,
  kTransferred,
  kAdopted,
  kRejected,
  kExpired
};
class Broker;

struct Pending {
  Pending(Broker* broker_value, uint64_t token_value, int fd_value,
          ParsedMessage message_value)
      : broker(broker_value),
        token(token_value),
        fd(fd_value),
        message(std::move(message_value)) {}

  Broker* broker;
  uint64_t token;
  int fd;
  ParsedMessage message;
  std::mutex mutex;
  std::condition_variable condition;
  PendingState state = PendingState::kQueued;
  uint16_t rejection_code = kRejectAdoptionFailed;
};

class Broker {
 public:
  Broker(std::string path, bool validate_runtime_root, int queue_size, int backlog,
         int timeout_ms, int max_controls, napi_env env, napi_value callback)
      : path_(std::move(path)),
        timeout_ms_(timeout_ms),
        max_controls_(max_controls) {
    PrepareEndpoint(path_, validate_runtime_root);
    listener_fd_ = CreateControlSocket();
    try {
      SetNonblocking(listener_fd_, true);
      const sockaddr_un address = UnixAddress(path_);
      if (bind(listener_fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
        throw SystemError("bind PHXP endpoint " + path_);
      }
      struct stat identity {};
      if (lstat(path_.c_str(), &identity) < 0 || !S_ISSOCK(identity.st_mode)) {
        throw SystemError("inspect bound PHXP endpoint " + path_);
      }
      identity_.device = identity.st_dev;
      identity_.inode = identity.st_ino;
      if (chmod(path_.c_str(), 0600) < 0) {
        throw SystemError("secure PHXP endpoint " + path_);
      }
      struct stat secured {};
      if (lstat(path_.c_str(), &secured) < 0 || !S_ISSOCK(secured.st_mode) ||
          secured.st_uid != geteuid() || (secured.st_mode & 0777) != 0600 ||
          secured.st_dev != identity_.device || secured.st_ino != identity_.inode) {
        throw std::runtime_error("PHXP endpoint identity changed while it was being secured");
      }
      if (listen(listener_fd_, backlog) < 0) throw SystemError("listen on PHXP endpoint");
      if (pipe(wake_) < 0) throw SystemError("create PHXP shutdown pipe");
      SetCloseOnExec(wake_[0]);
      SetCloseOnExec(wake_[1]);
      SetNonblocking(wake_[0], true);
      SetNonblocking(wake_[1], true);

      napi_value resource_name;
      CheckNapi(env, napi_create_string_utf8(env, "PHXP broker delivery", NAPI_AUTO_LENGTH,
                                             &resource_name),
                "create PHXP resource name");
      CheckNapi(env,
                napi_create_threadsafe_function(env, callback, nullptr, resource_name,
                                                static_cast<size_t>(queue_size), 1, nullptr,
                                                nullptr, nullptr, CallJs, &tsfn_),
                "create PHXP thread-safe callback");
      accept_thread_ = std::thread([this] { AcceptLoop(); });
    } catch (...) {
      CleanupEndpoint();
      CloseFd(&listener_fd_);
      CloseFd(&wake_[0]);
      CloseFd(&wake_[1]);
      if (tsfn_ != nullptr) {
        napi_release_threadsafe_function(tsfn_, napi_tsfn_abort);
        tsfn_ = nullptr;
      }
      throw;
    }
  }

  ~Broker() = default;

  const std::string& path() const { return path_; }

  void Adopt(uint64_t token) {
    const auto pending = FindPending(token);
    std::lock_guard lock(pending->mutex);
    if (pending->state != PendingState::kTransferred || pending->fd >= 0) {
      throw std::runtime_error("PHXP delivery is no longer adoptable");
    }
    pending->state = PendingState::kAdopted;
    pending->condition.notify_all();
  }

  void Transferred(uint64_t token) {
    const auto pending = FindPending(token);
    std::lock_guard lock(pending->mutex);
    if (pending->state != PendingState::kInCallback || pending->fd < 0) {
      throw std::runtime_error("PHXP delivery is no longer transferable");
    }
    pending->state = PendingState::kTransferred;
    pending->fd = -1;
  }

  void Reject(uint64_t token, uint16_t reason) {
    if (reason == 0) throw std::runtime_error("PHXP rejection reason must be nonzero");
    const auto pending = FindPending(token);
    {
      std::lock_guard lock(pending->mutex);
      if (pending->state != PendingState::kInCallback &&
          pending->state != PendingState::kTransferred) {
        throw std::runtime_error("PHXP delivery is no longer rejectable");
      }
      const bool native_owned = pending->state == PendingState::kInCallback;
      pending->state = PendingState::kRejected;
      pending->rejection_code = reason;
      if (native_owned) CloseFd(&pending->fd);
    }
    ReleaseId(pending->message.connection_id);
    pending->condition.notify_all();
  }

  void ReleaseId(const std::array<uint8_t, 16>& id) {
    std::lock_guard lock(active_mutex_);
    active_ids_.erase(IdKey(id));
  }

  void SignalStop() {
    if (stopping_.exchange(true)) return;
    const uint8_t byte = 1;
    ssize_t ignored = write(wake_[1], &byte, sizeof(byte));
    (void)ignored;
    {
      std::lock_guard lock(state_mutex_);
      for (int fd : control_fds_) shutdown(fd, SHUT_RDWR);
    }
    std::vector<std::shared_ptr<Pending>> pending;
    {
      std::lock_guard lock(pending_mutex_);
      for (const auto& entry : pending_) pending.push_back(entry.second);
    }
    for (const auto& item : pending) {
      bool release = false;
      {
        std::lock_guard lock(item->mutex);
        if (item->state == PendingState::kQueued) {
          item->state = PendingState::kExpired;
          CloseFd(&item->fd);
          release = true;
        }
      }
      if (release) ReleaseId(item->message.connection_id);
      item->condition.notify_all();
    }
  }

  void JoinAndCleanup(bool abort_callback) {
    SignalStop();
    if (accept_thread_.joinable()) accept_thread_.join();
    {
      std::unique_lock lock(state_mutex_);
      state_condition_.wait(lock, [this] { return active_controls_ == 0; });
    }
    CleanupEndpoint();
    CloseFd(&listener_fd_);
    CloseFd(&wake_[0]);
    CloseFd(&wake_[1]);
    if (tsfn_ != nullptr) {
      napi_release_threadsafe_function(
          tsfn_, abort_callback ? napi_tsfn_abort : napi_tsfn_release);
      tsfn_ = nullptr;
    }
  }

 private:
  static void CallJs(napi_env env, napi_value callback, void*, void* data) {
    std::unique_ptr<std::shared_ptr<Pending>> holder(
        static_cast<std::shared_ptr<Pending>*>(data));
    const std::shared_ptr<Pending> pending = *holder;
    {
      std::lock_guard lock(pending->mutex);
      if (pending->state != PendingState::kQueued || pending->fd < 0) return;
      pending->state = PendingState::kInCallback;
    }

    napi_status call_status = napi_ok;
    try {
      napi_value delivery;
      CheckNapi(env, napi_create_object(env, &delivery), "create PHXP delivery");
      napi_value value;
      CheckNapi(env, napi_create_bigint_uint64(env, pending->token, &value),
                "create PHXP delivery token");
      CheckNapi(env, napi_set_named_property(env, delivery, "token", value),
                "set PHXP delivery token");
      CheckNapi(env, napi_create_int32(env, pending->fd, &value), "create PHXP descriptor");
      CheckNapi(env, napi_set_named_property(env, delivery, "fd", value),
                "set PHXP descriptor");
      void* buffer_data = nullptr;
      CheckNapi(env, napi_create_buffer_copy(env, pending->message.connection_id.size(),
                                             pending->message.connection_id.data(),
                                             &buffer_data, &value),
                "create PHXP connection ID");
      (void)buffer_data;
      CheckNapi(env, napi_set_named_property(env, delivery, "connectionId", value),
                "set PHXP connection ID");
      CheckNapi(env, napi_create_uint32(env, pending->message.peeked_length, &value),
                "create PHXP peeked length");
      CheckNapi(env, napi_set_named_property(env, delivery, "peekedLength", value),
                "set PHXP peeked length");
      CheckNapi(env, napi_create_bigint_uint64(env, pending->message.accepted_at_ns, &value),
                "create PHXP accepted timestamp");
      CheckNapi(env, napi_set_named_property(env, delivery, "acceptedAtNs", value),
                "set PHXP accepted timestamp");
      CheckNapi(env,
                napi_create_string_utf8(env, pending->message.requested_sni.data(),
                                        pending->message.requested_sni.size(), &value),
                "create PHXP SNI");
      CheckNapi(env, napi_set_named_property(env, delivery, "requestedSni", value),
                "set PHXP SNI");
      napi_value global;
      CheckNapi(env, napi_get_global(env, &global), "get JavaScript global");
      call_status = napi_call_function(env, global, callback, 1, &delivery, nullptr);
    } catch (...) {
      call_status = napi_generic_failure;
    }

    bool release = false;
    {
      std::lock_guard lock(pending->mutex);
      if (pending->state == PendingState::kInCallback ||
          pending->state == PendingState::kTransferred) {
        const bool native_owned = pending->state == PendingState::kInCallback;
        pending->state = PendingState::kRejected;
        pending->rejection_code = kRejectAdoptionFailed;
        if (native_owned) CloseFd(&pending->fd);
        release = true;
      }
    }
    if (release) pending->broker->ReleaseId(pending->message.connection_id);
    pending->condition.notify_all();
    if (call_status != napi_ok) {
      napi_value exception;
      if (napi_get_and_clear_last_exception(env, &exception) == napi_ok) {
        napi_fatal_exception(env, exception);
      }
    }
  }

  std::shared_ptr<Pending> FindPending(uint64_t token) {
    std::lock_guard lock(pending_mutex_);
    const auto found = pending_.find(token);
    if (found == pending_.end()) throw std::runtime_error("unknown PHXP delivery token");
    return found->second;
  }

  bool ReserveId(const std::array<uint8_t, 16>& id) {
    std::lock_guard lock(active_mutex_);
    return active_ids_.insert(IdKey(id)).second;
  }

  void AcceptLoop() {
    pollfd descriptors[2] = {
        {listener_fd_, POLLIN, 0},
        {wake_[0], POLLIN, 0},
    };
    while (!stopping_) {
      int ready;
      do {
        ready = poll(descriptors, 2, -1);
      } while (ready < 0 && errno == EINTR);
      if (ready < 0 || (descriptors[1].revents & POLLIN) != 0 || stopping_) return;
      if ((descriptors[0].revents & POLLIN) == 0) continue;
      while (!stopping_) {
#if defined(__linux__)
        int control = accept4(listener_fd_, nullptr, nullptr, SOCK_CLOEXEC);
#else
        int control = accept(listener_fd_, nullptr, nullptr);
#endif
        if (control < 0) {
          if (errno == EINTR) continue;
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          if (stopping_) return;
          break;
        }
        try {
          SetCloseOnExec(control);
          SetNonblocking(control, false);
          ConfigureNoSigpipe(control);
        } catch (...) {
          CloseFd(&control);
          continue;
        }
        {
          std::lock_guard lock(state_mutex_);
          if (stopping_ || active_controls_ >= max_controls_) {
            CloseFd(&control);
            continue;
          }
          ++active_controls_;
          control_fds_.insert(control);
        }
        try {
          std::thread([this, control] { HandleControlGuarded(control); }).detach();
        } catch (...) {
          CloseAndUnregisterControl(control);
        }
      }
    }
  }

  void HandleControlGuarded(int control) {
    try {
      HandleControl(control);
    } catch (...) {
    }
    CloseAndUnregisterControl(control);
  }

  void HandleControl(int control) {
    ConfigureTimeout(control, timeout_ms_);
    AuthenticatePeer(control);
    ReceivedFrame hello = ReceiveFrame(control, false);
    if (!hello.descriptors.empty()) {
      CloseDescriptors(&hello.descriptors);
      return;
    }
    if (Decode(hello.bytes).type != kHello) return;
    SendFrame(control, Response(kReady));

    ReceivedFrame received = ReceiveFrame(control, true);
    ParsedMessage request;
    try {
      request = Decode(received.bytes);
    } catch (...) {
      CloseDescriptors(&received.descriptors);
      return;
    }
    if (request.type != kHandoff) {
      CloseDescriptors(&received.descriptors);
      return;
    }
    if (received.descriptors.size() != 1) {
      CloseDescriptors(&received.descriptors);
      Reject(control, request.connection_id, kRejectInvalidDescriptor);
      return;
    }

    int descriptor = received.descriptors.front();
    received.descriptors.clear();
    try {
      ValidateConnectedTcp(descriptor);
    } catch (...) {
      CloseFd(&descriptor);
      Reject(control, request.connection_id, kRejectInvalidDescriptor);
      return;
    }
    if (!ReserveId(request.connection_id)) {
      CloseFd(&descriptor);
      Reject(control, request.connection_id, kRejectDuplicateId);
      return;
    }

    const uint64_t token = next_token_.fetch_add(1);
    auto pending = std::make_shared<Pending>(this, token, descriptor, request);
    {
      std::lock_guard lock(pending_mutex_);
      pending_.emplace(token, pending);
    }
    auto* callback_data = new std::shared_ptr<Pending>(pending);
    const napi_status queued =
        napi_call_threadsafe_function(tsfn_, callback_data, napi_tsfn_nonblocking);
    if (queued != napi_ok) {
      delete callback_data;
      {
        std::lock_guard lock(pending_mutex_);
        pending_.erase(token);
      }
      CloseFd(&pending->fd);
      ReleaseId(request.connection_id);
      Reject(control, request.connection_id, kRejectAdoptionFailed);
      return;
    }

    PendingState outcome;
    uint16_t reason;
    {
      std::unique_lock lock(pending->mutex);
      const bool decided = pending->condition.wait_for(
          lock, std::chrono::milliseconds(timeout_ms_), [&pending] {
            return pending->state == PendingState::kAdopted ||
                   pending->state == PendingState::kRejected ||
                   pending->state == PendingState::kExpired ||
                   pending->state == PendingState::kInCallback ||
                   pending->state == PendingState::kTransferred;
          });
      if (!decided) {
        pending->state = PendingState::kExpired;
        CloseFd(&pending->fd);
        lock.unlock();
        ReleaseId(request.connection_id);
        lock.lock();
      }
      while (pending->state == PendingState::kInCallback ||
             pending->state == PendingState::kTransferred) {
        pending->condition.wait(lock);
      }
      outcome = pending->state;
      reason = pending->rejection_code;
    }
    {
      std::lock_guard lock(pending_mutex_);
      pending_.erase(token);
    }
    if (outcome == PendingState::kAdopted) {
      try {
        SendFrame(control, Response(kAdopted, request.connection_id));
      } catch (...) {
      }
    } else {
      Reject(control, request.connection_id, reason);
    }
  }

  void Reject(int control, const std::array<uint8_t, 16>& id, uint16_t reason) {
    try {
      SendFrame(control, Response(kRejected, id, reason));
    } catch (...) {
    }
  }

  void CloseAndUnregisterControl(int control) {
    std::lock_guard lock(state_mutex_);
    control_fds_.erase(control);
    CloseFd(&control);
    if (active_controls_ > 0) --active_controls_;
    state_condition_.notify_all();
  }

  void CleanupEndpoint() {
    if (identity_.inode == 0) return;
    struct stat current {};
    if (lstat(path_.c_str(), &current) == 0 && S_ISSOCK(current.st_mode) &&
        current.st_dev == identity_.device && current.st_ino == identity_.inode) {
      unlink(path_.c_str());
    }
    identity_ = {};
  }

  std::string path_;
  int timeout_ms_;
  int max_controls_;
  int listener_fd_ = -1;
  int wake_[2] = {-1, -1};
  EndpointIdentity identity_;
  napi_threadsafe_function tsfn_ = nullptr;
  std::thread accept_thread_;
  std::atomic<bool> stopping_{false};
  std::atomic<uint64_t> next_token_{1};

  std::mutex state_mutex_;
  std::condition_variable state_condition_;
  int active_controls_ = 0;
  std::unordered_set<int> control_fds_;

  std::mutex pending_mutex_;
  std::unordered_map<uint64_t, std::shared_ptr<Pending>> pending_;
  std::mutex active_mutex_;
  std::unordered_set<std::string> active_ids_;
};

struct BrokerHandle {
  std::mutex mutex;
  Broker* broker = nullptr;
  bool closing = false;
};

BrokerHandle* GetHandle(napi_env env, napi_value receiver) {
  napi_value external;
  CheckNapi(env, napi_get_named_property(env, receiver, "_handle", &external),
            "get PHXP native handle");
  void* data = nullptr;
  CheckNapi(env, napi_get_value_external(env, external, &data), "unwrap PHXP native handle");
  return static_cast<BrokerHandle*>(data);
}

Broker* GetBroker(napi_env env, napi_callback_info info, size_t* argc = nullptr,
                  napi_value* argv = nullptr, napi_value* receiver_out = nullptr) {
  size_t count = argc == nullptr ? 0 : *argc;
  napi_value receiver;
  CheckNapi(env, napi_get_cb_info(env, info, &count, argv, &receiver, nullptr),
            "read PHXP method arguments");
  if (argc != nullptr) *argc = count;
  if (receiver_out != nullptr) *receiver_out = receiver;
  BrokerHandle* handle = GetHandle(env, receiver);
  std::lock_guard lock(handle->mutex);
  if (handle->broker == nullptr) throw std::runtime_error("PHXP broker is closed");
  return handle->broker;
}

uint64_t BigintArgument(napi_env env, napi_value value, const char* field) {
  uint64_t result = 0;
  bool lossless = false;
  CheckNapi(env, napi_get_value_bigint_uint64(env, value, &result, &lossless), field);
  if (!lossless) throw std::runtime_error(std::string(field) + " is outside uint64 range");
  return result;
}

uint32_t Uint32Argument(napi_env env, napi_value value, const char* field) {
  uint32_t result = 0;
  CheckNapi(env, napi_get_value_uint32(env, value, &result), field);
  return result;
}

std::array<uint8_t, 16> IdArgument(napi_env env, napi_value value) {
  bool is_buffer = false;
  CheckNapi(env, napi_is_buffer(env, value, &is_buffer), "inspect PHXP connection ID");
  if (!is_buffer) throw std::runtime_error("PHXP connection ID must be a Buffer");
  void* data = nullptr;
  size_t length = 0;
  CheckNapi(env, napi_get_buffer_info(env, value, &data, &length), "read PHXP connection ID");
  if (length != 16) throw std::runtime_error("PHXP connection ID must contain 16 bytes");
  std::array<uint8_t, 16> id{};
  std::memcpy(id.data(), data, id.size());
  return id;
}

napi_value Undefined(napi_env env) {
  napi_value value;
  CheckNapi(env, napi_get_undefined(env, &value), "get undefined");
  return value;
}

void Throw(napi_env env, const std::exception& error) {
  napi_throw_error(env, nullptr, error.what());
}

napi_value AdoptMethod(napi_env env, napi_callback_info info) {
  try {
    size_t argc = 1;
    napi_value argv[1];
    Broker* broker = GetBroker(env, info, &argc, argv);
    if (argc != 1) throw std::runtime_error("PHXP adopt requires a delivery token");
    broker->Adopt(BigintArgument(env, argv[0], "read PHXP delivery token"));
    return Undefined(env);
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

napi_value TransferredMethod(napi_env env, napi_callback_info info) {
  try {
    size_t argc = 1;
    napi_value argv[1];
    Broker* broker = GetBroker(env, info, &argc, argv);
    if (argc != 1) throw std::runtime_error("PHXP transfer requires a delivery token");
    broker->Transferred(BigintArgument(env, argv[0], "read PHXP delivery token"));
    return Undefined(env);
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

napi_value RejectMethod(napi_env env, napi_callback_info info) {
  try {
    size_t argc = 2;
    napi_value argv[2];
    Broker* broker = GetBroker(env, info, &argc, argv);
    if (argc != 2) throw std::runtime_error("PHXP reject requires a token and reason");
    const uint32_t reason = Uint32Argument(env, argv[1], "read PHXP rejection reason");
    if (reason == 0 || reason > UINT16_MAX) {
      throw std::runtime_error("PHXP rejection reason is outside uint16 range");
    }
    broker->Reject(BigintArgument(env, argv[0], "read PHXP delivery token"),
                   static_cast<uint16_t>(reason));
    return Undefined(env);
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

napi_value ReleaseMethod(napi_env env, napi_callback_info info) {
  try {
    size_t argc = 1;
    napi_value argv[1];
    Broker* broker = GetBroker(env, info, &argc, argv);
    if (argc != 1) throw std::runtime_error("PHXP release requires a connection ID");
    broker->ReleaseId(IdArgument(env, argv[0]));
    return Undefined(env);
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

napi_value PathMethod(napi_env env, napi_callback_info info) {
  try {
    Broker* broker = GetBroker(env, info);
    napi_value value;
    CheckNapi(env,
              napi_create_string_utf8(env, broker->path().data(), broker->path().size(), &value),
              "create PHXP endpoint path");
    return value;
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

struct CloseWork {
  napi_env env;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  napi_ref receiver = nullptr;
  BrokerHandle* handle;
  Broker* broker;
  std::string error;
};

void ExecuteClose(napi_env, void* data) {
  auto* work = static_cast<CloseWork*>(data);
  try {
    work->broker->JoinAndCleanup(false);
  } catch (const std::exception& error) {
    work->error = error.what();
  }
}

void CompleteClose(napi_env env, napi_status, void* data) {
  std::unique_ptr<CloseWork> work(static_cast<CloseWork*>(data));
  {
    std::lock_guard lock(work->handle->mutex);
    if (work->handle->broker == work->broker) work->handle->broker = nullptr;
  }
  delete work->broker;
  napi_value result;
  if (work->error.empty()) {
    napi_get_undefined(env, &result);
    napi_resolve_deferred(env, work->deferred, result);
  } else {
    napi_create_string_utf8(env, work->error.data(), work->error.size(), &result);
    napi_value error;
    napi_create_error(env, nullptr, result, &error);
    napi_reject_deferred(env, work->deferred, error);
  }
  napi_delete_reference(env, work->receiver);
  napi_delete_async_work(env, work->work);
}

napi_value CloseMethod(napi_env env, napi_callback_info info) {
  try {
    size_t argc = 0;
    napi_value receiver;
    CheckNapi(env, napi_get_cb_info(env, info, &argc, nullptr, &receiver, nullptr),
              "read PHXP close receiver");
    BrokerHandle* handle = GetHandle(env, receiver);
    Broker* broker;
    {
      std::lock_guard lock(handle->mutex);
      if (handle->broker == nullptr || handle->closing) {
        throw std::runtime_error("PHXP broker is already closing or closed");
      }
      handle->closing = true;
      broker = handle->broker;
    }
    broker->SignalStop();

    auto* work = new CloseWork{env, nullptr, nullptr, nullptr, handle, broker, {}};
    napi_value promise;
    CheckNapi(env, napi_create_promise(env, &work->deferred, &promise),
              "create PHXP close promise");
    CheckNapi(env, napi_create_reference(env, receiver, 1, &work->receiver),
              "retain PHXP broker during close");
    napi_value name;
    CheckNapi(env, napi_create_string_utf8(env, "close PHXP broker", NAPI_AUTO_LENGTH, &name),
              "create PHXP close work name");
    CheckNapi(env,
              napi_create_async_work(env, nullptr, name, ExecuteClose, CompleteClose, work,
                                     &work->work),
              "create PHXP close work");
    CheckNapi(env, napi_queue_async_work(env, work->work), "queue PHXP close work");
    return promise;
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

void FinalizeHandle(napi_env, void* data, void*) {
  auto* handle = static_cast<BrokerHandle*>(data);
  Broker* broker = nullptr;
  {
    std::lock_guard lock(handle->mutex);
    if (!handle->closing) {
      broker = handle->broker;
      handle->broker = nullptr;
    }
  }
  if (broker != nullptr) {
    broker->SignalStop();
    std::thread([broker] {
      broker->JoinAndCleanup(true);
      delete broker;
    }).detach();
  }
  delete handle;
}

std::string StringProperty(napi_env env, napi_value object, const char* name) {
  napi_value value;
  CheckNapi(env, napi_get_named_property(env, object, name, &value), name);
  size_t length = 0;
  CheckNapi(env, napi_get_value_string_utf8(env, value, nullptr, 0, &length), name);
  std::string result(length + 1, '\0');
  CheckNapi(env, napi_get_value_string_utf8(env, value, result.data(), length + 1, &length), name);
  result.resize(length);
  return result;
}

bool BoolProperty(napi_env env, napi_value object, const char* name) {
  napi_value value;
  CheckNapi(env, napi_get_named_property(env, object, name, &value), name);
  bool result = false;
  CheckNapi(env, napi_get_value_bool(env, value, &result), name);
  return result;
}

int IntProperty(napi_env env, napi_value object, const char* name, int minimum, int maximum) {
  napi_value value;
  CheckNapi(env, napi_get_named_property(env, object, name, &value), name);
  int32_t result = 0;
  CheckNapi(env, napi_get_value_int32(env, value, &result), name);
  if (result < minimum || result > maximum) {
    throw std::runtime_error(std::string(name) + " is outside supported bounds");
  }
  return result;
}

void SetMethod(napi_env env, napi_value object, const char* name, napi_callback callback) {
  napi_value function;
  CheckNapi(env, napi_create_function(env, name, NAPI_AUTO_LENGTH, callback, nullptr, &function),
            "create PHXP native method");
  CheckNapi(env, napi_set_named_property(env, object, name, function), "set PHXP native method");
}

napi_value Start(napi_env env, napi_callback_info info) {
  try {
    size_t argc = 3;
    napi_value argv[3];
    CheckNapi(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr),
              "read PHXP start arguments");
    if (argc != 3) throw std::runtime_error("PHXP start requires path, options, and callback");
    size_t path_length = 0;
    CheckNapi(env, napi_get_value_string_utf8(env, argv[0], nullptr, 0, &path_length),
              "read PHXP endpoint path");
    std::string path(path_length + 1, '\0');
    CheckNapi(env,
              napi_get_value_string_utf8(env, argv[0], path.data(), path_length + 1,
                                         &path_length),
              "read PHXP endpoint path");
    path.resize(path_length);
    napi_valuetype callback_type;
    CheckNapi(env, napi_typeof(env, argv[2], &callback_type), "inspect PHXP callback");
    if (callback_type != napi_function) throw std::runtime_error("PHXP callback must be a function");

    auto* broker =
        new Broker(path, BoolProperty(env, argv[1], "validateRuntimeRoot"),
                   IntProperty(env, argv[1], "queueSize", 1, 4096),
                   IntProperty(env, argv[1], "backlog", 1, 4096),
                   IntProperty(env, argv[1], "controlTimeoutMs", 1, 60000),
                   IntProperty(env, argv[1], "maxControlConnections", 1, 1024), env, argv[2]);
    auto* handle = new BrokerHandle{{}, broker, false};
    napi_value result;
    CheckNapi(env, napi_create_object(env, &result), "create PHXP broker object");
    napi_value external;
    CheckNapi(env, napi_create_external(env, handle, FinalizeHandle, nullptr, &external),
              "create PHXP broker handle");
    CheckNapi(env, napi_set_named_property(env, result, "_handle", external),
              "set PHXP broker handle");
    SetMethod(env, result, "adopt", AdoptMethod);
    SetMethod(env, result, "transferred", TransferredMethod);
    SetMethod(env, result, "reject", RejectMethod);
    SetMethod(env, result, "release", ReleaseMethod);
    SetMethod(env, result, "path", PathMethod);
    SetMethod(env, result, "close", CloseMethod);
    return result;
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

struct TestWork {
  napi_env env;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  std::string endpoint;
  std::vector<uint8_t> frame;
  std::string kind;
  int descriptor_count = 1;
  int timeout_ms = 2000;
  std::vector<uint8_t> response;
  int client_fd = -1;
  std::string error;
};

void ConnectUnix(int fd, const std::string& path) {
  const sockaddr_un address = UnixAddress(path);
  if (connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
    throw SystemError("connect to PHXP endpoint");
  }
}

std::pair<int, int> TcpPair() {
  int listener = -1;
  int client = -1;
  int server = -1;
  try {
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) throw SystemError("create test TCP listener");
    SetCloseOnExec(listener);
    int reuse = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
      throw SystemError("configure test TCP listener");
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 ||
        listen(listener, 1) < 0) {
      throw SystemError("bind test TCP listener");
    }
    socklen_t length = sizeof(address);
    if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) < 0) {
      throw SystemError("inspect test TCP listener");
    }
    client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) throw SystemError("create test TCP client");
    SetCloseOnExec(client);
    if (connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
      throw SystemError("connect test TCP client");
    }
    do {
      server = accept(listener, nullptr, nullptr);
    } while (server < 0 && errno == EINTR);
    if (server < 0) throw SystemError("accept test TCP connection");
    SetCloseOnExec(server);
    SetNonblocking(server, true);
    SetNonblocking(client, true);
    CloseFd(&listener);
    return {client, server};
  } catch (...) {
    CloseFd(&listener);
    CloseFd(&client);
    CloseFd(&server);
    throw;
  }
}

ssize_t SendDescriptorFrame(int control, const std::vector<uint8_t>& frame,
                            const std::vector<int>& descriptors) {
  iovec vector{const_cast<uint8_t*>(frame.data()), frame.size()};
  alignas(cmsghdr) std::array<uint8_t, CMSG_SPACE(sizeof(int) * 4)> ancillary{};
  msghdr message{};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  if (!descriptors.empty()) {
    message.msg_control = ancillary.data();
    message.msg_controllen = CMSG_SPACE(sizeof(int) * descriptors.size());
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int) * descriptors.size());
    std::memcpy(CMSG_DATA(header), descriptors.data(), sizeof(int) * descriptors.size());
  }
  ssize_t sent;
  do {
#if defined(__linux__)
    sent = sendmsg(control, &message, MSG_NOSIGNAL);
#else
    sent = sendmsg(control, &message, 0);
#endif
  } while (sent < 0 && errno == EINTR);
  return sent;
}

void ExecuteTestHandoff(napi_env, void* data) {
  auto* work = static_cast<TestWork*>(data);
  int control = -1;
  int transferred = -1;
  int other = -1;
  try {
    control = CreateControlSocket();
    ConfigureTimeout(control, work->timeout_ms);
    ConnectUnix(control, work->endpoint);
    AuthenticatePeer(control);
    SendFrame(control, Response(kHello));
    const ReceivedFrame ready = ReceiveFrame(control, false);
    if (Decode(ready.bytes).type != kReady) throw std::runtime_error("PHXP receiver was not ready");

    std::vector<int> descriptors;
    if (work->kind == "tcp") {
      auto pair = TcpPair();
      work->client_fd = pair.first;
      transferred = pair.second;
      for (int index = 0; index < work->descriptor_count; ++index) {
        descriptors.push_back(transferred);
      }
    } else if (work->kind == "unix") {
      int pair[2];
      if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        throw SystemError("create test Unix socket pair");
      }
      transferred = pair[0];
      other = pair[1];
      SetCloseOnExec(transferred);
      SetCloseOnExec(other);
      for (int index = 0; index < work->descriptor_count; ++index) {
        descriptors.push_back(transferred);
      }
    } else if (work->kind != "none") {
      throw std::runtime_error("unknown test descriptor kind");
    }

    const ssize_t sent = SendDescriptorFrame(control, work->frame, descriptors);
    if (sent < 0) throw SystemError("send test PHXP descriptor");
    if (sent == 0) throw std::runtime_error("test PHXP descriptor send made no progress");
#if defined(__linux__)
    if (static_cast<size_t>(sent) != work->frame.size()) {
      throw std::runtime_error("test PHXP seqpacket send was partial");
    }
#elif defined(__APPLE__)
    size_t offset = static_cast<size_t>(sent);
    while (offset < work->frame.size()) {
      ssize_t count;
      do {
        count = send(control, work->frame.data() + offset, work->frame.size() - offset, 0);
      } while (count < 0 && errno == EINTR);
      if (count <= 0) throw SystemError("complete test PHXP stream frame");
      offset += static_cast<size_t>(count);
    }
#endif
    CloseFd(&transferred);
    CloseFd(&other);
    const ReceivedFrame response = ReceiveFrame(control, false);
    work->response = response.bytes;
    const ParsedMessage parsed = Decode(work->response);
    if (parsed.type != kAdopted) CloseFd(&work->client_fd);
  } catch (const std::exception& error) {
    work->error = error.what();
    CloseFd(&work->client_fd);
  }
  CloseFd(&transferred);
  CloseFd(&other);
  CloseFd(&control);
}

void CompleteTestHandoff(napi_env env, napi_status, void* data) {
  std::unique_ptr<TestWork> work(static_cast<TestWork*>(data));
  napi_value result;
  if (!work->error.empty()) {
    napi_value message;
    napi_create_string_utf8(env, work->error.data(), work->error.size(), &message);
    napi_value error;
    napi_create_error(env, nullptr, message, &error);
    napi_reject_deferred(env, work->deferred, error);
  } else {
    napi_create_object(env, &result);
    napi_value value;
    void* copied = nullptr;
    napi_create_buffer_copy(env, work->response.size(), work->response.data(), &copied, &value);
    (void)copied;
    napi_set_named_property(env, result, "response", value);
    napi_create_int32(env, work->client_fd, &value);
    napi_set_named_property(env, result, "clientFd", value);
    napi_resolve_deferred(env, work->deferred, result);
  }
  napi_delete_async_work(env, work->work);
}

napi_value TestHandoff(napi_env env, napi_callback_info info) {
  try {
    size_t argc = 1;
    napi_value argv[1];
    CheckNapi(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr),
              "read test handoff options");
    if (argc != 1) throw std::runtime_error("test handoff requires options");
    auto* work = new TestWork;
    work->env = env;
    work->endpoint = StringProperty(env, argv[0], "endpoint");
    work->kind = StringProperty(env, argv[0], "descriptorKind");
    work->descriptor_count = IntProperty(env, argv[0], "descriptorCount", 0, 4);
    work->timeout_ms = IntProperty(env, argv[0], "timeoutMs", 1, 60000);
    napi_value frame;
    CheckNapi(env, napi_get_named_property(env, argv[0], "frame", &frame), "get test PHXP frame");
    bool is_buffer = false;
    CheckNapi(env, napi_is_buffer(env, frame, &is_buffer), "inspect test PHXP frame");
    if (!is_buffer) throw std::runtime_error("test PHXP frame must be a Buffer");
    void* bytes = nullptr;
    size_t length = 0;
    CheckNapi(env, napi_get_buffer_info(env, frame, &bytes, &length), "read test PHXP frame");
    work->frame.assign(static_cast<uint8_t*>(bytes), static_cast<uint8_t*>(bytes) + length);

    napi_value promise;
    CheckNapi(env, napi_create_promise(env, &work->deferred, &promise),
              "create test handoff promise");
    napi_value name;
    CheckNapi(env, napi_create_string_utf8(env, "test PHXP handoff", NAPI_AUTO_LENGTH, &name),
              "create test handoff work name");
    CheckNapi(env,
              napi_create_async_work(env, nullptr, name, ExecuteTestHandoff,
                                     CompleteTestHandoff, work, &work->work),
              "create test handoff work");
    CheckNapi(env, napi_queue_async_work(env, work->work), "queue test handoff work");
    return promise;
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

napi_value TestCreateStaleEndpoint(napi_env env, napi_callback_info info) {
  try {
    size_t argc = 1;
    napi_value argv[1];
    CheckNapi(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr),
              "read stale endpoint path");
    if (argc != 1) throw std::runtime_error("stale endpoint creation requires a path");
    size_t length = 0;
    CheckNapi(env, napi_get_value_string_utf8(env, argv[0], nullptr, 0, &length),
              "read stale endpoint path");
    std::string path(length + 1, '\0');
    CheckNapi(env, napi_get_value_string_utf8(env, argv[0], path.data(), length + 1, &length),
              "read stale endpoint path");
    path.resize(length);
    int fd = CreateControlSocket();
    try {
      const sockaddr_un address = UnixAddress(path);
      if (bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
        throw SystemError("bind stale PHXP endpoint");
      }
      CloseFd(&fd);
    } catch (...) {
      CloseFd(&fd);
      throw;
    }
    return Undefined(env);
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

napi_value TestPeerMatches(napi_env env, napi_callback_info info) {
  try {
    size_t argc = 1;
    napi_value argv[1];
    CheckNapi(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr),
              "read expected peer UID");
    if (argc != 1) throw std::runtime_error("peer test requires an expected UID");
    const uint32_t expected = Uint32Argument(env, argv[0], "read expected peer UID");
    int pair[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
      throw SystemError("create peer credential test socket");
    }
    bool matches;
    try {
      matches = PeerEuid(pair[0]) == static_cast<uid_t>(expected);
    } catch (...) {
      CloseFd(&pair[0]);
      CloseFd(&pair[1]);
      throw;
    }
    CloseFd(&pair[0]);
    CloseFd(&pair[1]);
    napi_value result;
    CheckNapi(env, napi_get_boolean(env, matches, &result), "create peer test result");
    return result;
  } catch (const std::exception& error) {
    Throw(env, error);
    return nullptr;
  }
}

napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor properties[] = {
      {"start", nullptr, Start, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"testHandoff", nullptr, TestHandoff, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"testCreateStaleEndpoint", nullptr, TestCreateStaleEndpoint, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"testPeerMatches", nullptr, TestPeerMatches, nullptr, nullptr, nullptr, napi_default,
       nullptr},
  };
  CheckNapi(env,
            napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]),
                                   properties),
            "define PHXP native exports");
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
