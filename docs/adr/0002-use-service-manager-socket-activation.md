# Use service-manager socket activation for public listeners

Production ingress will adopt named listening sockets from systemd on Linux and
launchd on macOS through one internal activated-listener abstraction. The
service manager owns privileged port 443 while `phx-port` runs unprivileged and
can restart without rebinding the public socket. Explicit `--listen` binding
remains available for foreground and development use; production does not rely
on root execution, persistent executable capabilities, or undocumented
platform privilege behavior.

Manual operation remains supported through
`sudo phx-port daemon --run-as USER`. That path binds explicit listeners while
privileged, permanently drops supplementary groups, GID, and UID before
loading configuration or mutable state and before accepting traffic. After the
drop it refuses startup unless the ingress configuration's listener set
exactly matches the explicitly bound listeners. Bare `sudo phx-port` retains
its existing CLI semantics.
