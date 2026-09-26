
# Operations

Yes, it starts at boot. The unit at  ~/.config/systemd/user/phx-port.service  is enabled, and your account has `Linger=yes`, so it starts without waiting for you to log in and survives logout. 

Control it as your normal user—no  sudo :

```shell
systemctl --user status phx-port.service --no-pager
systemctl --user stop phx-port.service           # Stop now; keep boot enablement
systemctl --user start phx-port.service          # Start now
systemctl --user restart phx-port.service        # Restart

systemctl --user disable --now phx-port.service # Stop and disable autostart
systemctl --user enable --now phx-port.service  # Start and enable autostart
```

just run-production launches another foreground instance of  ~/.cargo/bin/phx-port ; it does not manage this service or use the newer  target/release  binary. Stop the user service first if you want foreground operation.  just install-release  updates the installed Cargo binary, but the service must then be restarted to load it. The  just public-*  recipes manage a separate system-wide deployment, which is not installed on this laptop.



