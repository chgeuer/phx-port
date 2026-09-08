# External PHXP sender; only the stalled TCP peers live in this VM.
# From phx_port_handoff/, always use an external watchdog:
# MIX_ENV=test ELIXIR_ERL_OPTIONS="+S 2:2" timeout --kill-after=10s 180s \
#   mix run ../docs/evidence/invm_peer_starvation.exs <count> <blocking:0|1>

Code.require_file("scheduler_probe.exs", __DIR__)
PhxPortHandoff.Evidence.SchedulerProbe.main(:in_vm_peer, System.argv())
