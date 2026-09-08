"""External PHXP sender; only the TCP/TLS peers live in the workload VM."""

from stalled_handoff_sender import main


if __name__ == "__main__":
    main(in_vm_peers=True)
