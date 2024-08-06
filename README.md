# Rootful networking with rootless podman containers

As presented at [devconf.cz 2023][devconf-talk].

This python tool allows attaching network interfaces to initialized, but not
running, rootless podman containers. It uses `netavark`, which is the same tool
podman uses to do this. There are some known limitations:

 - `podman inspect` won't know about the network. From podman's point of view,
   the container doesn'thave networking.
 - `podman run --sdnotify=conmon` won't work; `systemd` receives but rejects
   the notification with a message similar to `user@1000.service: Got
   notification message from PID 7687, but reception only permitted for main
   PID 3201`

If you are using podman >= 4.5, using

```sh
podman run \
    --uidmap="0:$(id -u user):1" \
    --uidmap="1:$(grep -Po '(?<=^user:).*$' /etc/subuid | head -1)" \
    --gidmap="0:$(id -g user):1" \
    --gidmap="1:$(grep -Po '(?<=^user:).*$' /etc/subgid | head -1")
```

also gives you containers without a mapped root UID without external tooling.
You may want to use that, as it's a lot simpler.

## Dependencies

- `python3`
- `python3-podman`
- `container-selinux`
- `dbus-x11` for `dbus-launch`, which is called somewhere in the setup by podman or systemd

## Running

To see this in action manually, open one shell as root and one as the
unprivileged user you want to use to run your container. In the example below,
this user is `test` with a UID of 1000.

### Initial setup (run once)

As root:

```bash
# Create a secret that will be used to make the IP addresses (which are
# calculated from the container name) unpredictable
touch /etc/rootful_network_secret \
    && chmod 600 /etc/rootful_network_secret \
    && dd if=/dev/urandom of=/etc/rootful_network_secret bs=1 count=32

# lingering is required for the unprivileged user
loginctl enable-linger test

# clone and install required scripts
git clone https://github.com/neverpanic/podman-rootful-network
install -m0755 \
    podman-rootful-network/rootful_network.py \
    /usr/local/sbin/rootful_network

# enable the podman socket for root
systemctl enable --now podman.socket

# create the podman network you want to use; rootless_network.py expects to
# have exclusive control over this network, so do not use it for any other
# containers
podman network create [--ipv6] "$networkname"
```

As user:

```bash
# enable the podman socket for the user
systemctl --user enable --now podman.socket
```

### For each container

As user:

```bash
# create the runtime directory that will contain state information
runtimedir="/run/user/$(id -u)/container/$containername"
mkdir -p "$runtimedir"
# create the container, but do not start it
# the --cidfile will be used by rootful_network.py
podman create \
    --cidfile="$runtimedir/ctr-id" \
    --network=none \
    --name "$containername" \
    "$image:$tag"

# initialize the container namespaces, but do not start it
podman container init rootless
```

As root:

```bash
runtimedir="/run/user/1000/container/$containername"

rootful_network \
    "$runtimedir" \
    setup \
    "$name_used_to_generate_ip" \
    /etc/rootful_network_secret \
    "$unprivileged_user" \
    --network "$networkname" \
    [--publish [[ip:][hostPort]:]containerPort[/protocol]] \
    [--network-alias "$alias"]
```

As user:

```bash
podman start "$containername"
```

### Stopping containers

As user:

```bash
podman stop "$containername"
```

As root:

```bash
runtimedir="/run/user/1000/container/$containername"

rootful_network \
    "$runtimedir" \
    teardown
```

As user:

```bash
podman rm "$containername"
```

If you start containers with `--rm` `rootful_network.py` won't be able to
determine the container ID during teardown and cleanup will fail.

The example systemd service file `rootless-example.service` shows these
commands in a systemd service that can start and stop a container after the
initial setup steps.

## Credits

Without the help of the following people and their posts and presentations,
this would not have been possible:

 - https://web.archive.org/web/20220303110335/https://podman.io/community/meeting/notes/2021-10-05/Podman-Rootless-Networking.pdf
 - https://lists.podman.io/archives/list/podman@lists.podman.io/thread/W6MCYO6RY5YFRTSUDAOEZA7SC2EFXRZE/

## License

This code is licensed under the BSD-2-Clause license. The SPDX identifier is
`BSD-2-Clause`.

[devconf-talk]: https://devconfcz2023.sched.com/event/9b11eda5c5be46020cb1614e96ef25f0
