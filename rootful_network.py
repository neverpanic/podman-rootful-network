#!/usr/bin/env python3

# Copyright (c) 2023 Clemens Lang <neverpanic@gmail.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Helper program to assign a rootful netavark network to a rootless container

This should be called from a systemd service file registered to the system
systemd instance (i.e. PID 1) where the service file sets a non-root User
option. For this to work correctly, the systemd service should

1. Use Type=simple. Unfortunately Type=notify will not work because systemd
   will not accept the notification from a non-root user, and both conmon
   (--sdnotify=conmon) and the container (--sdnotify=container) will not run
   as root.
2. Set RuntimeDirectory=container/%n. This is required because otherwise
   ${RUNTIME_DIRECTORY} will not be available, but we will be using it to
   store the container ID.
3. Create the container and initialize it, but *not* start it. Do this using
   ExecStartPre=/usr/bin/podman create \
     --cidfile=${RUNTIME_DIRECTORY}/ctr-id \
     --replace \
     --network=none \
     --name=name-of-your-choice \
     ARGS
   ExecStartPre=/usr/bin/podman container init name-of-your-choice
4. Invoke this script as root by using ExecStartPre=+. As arguments, pass
     - "${RUNTIME_DIRECTORY}" (i.e., the path of the runtime directory)
     - "setup"
     - %n (systemd will expand this to the service name)
     - "${CREDENTIALS_DIRECTORY}/mac-secret" (a secret used to mac the service
       name to compute IP addresses)
     - "${USER}" (i.e., the user under which the container should be run)
     - the name of the podman network to attach to this container
     - the ports you want to expose (see --help for the format)
5. Start the container using
   ExecStart=/usr/bin/podman start --attach name-of-your-choice
6. Add a cleanup step to tear down the network configuration using
   ExecStopPost=+rootful_network.py \
     "${RUNTIME_DIRECTORY}" \
     "teardown"
"""


# cat podman1.json | \
#   jq \
#     --argjson networkinfo "$(podman network inspect podman1)" \
#     '. + {"network_info": {($networkinfo[0]["name"]): $networkinfo[0]}}' | \
#     /usr/libexec/podman/netavark setup /proc/7227/ns/net

# {
#   "container_id": "10b77528fbcd9983eeb521251c3d18fd5084a82d453b64f29b878e89bb7700ca",
#   "container_name": "fedora",
#   "port_mappings": [
#     {
#       "host_ip": "",
#       "container_port": 8080,
#       "host_port": 80,
#       "range": 1,
#       "protocol": "tcp"
#     }
#   ],
#   "networks": {
#     "podman1": {
#       "static_ips": [
#         "10.89.0.2",
#         "fdf6:cb79:f2dd:eb7::2"
#       ],
#       "aliases": [
#         "fedora-alias"
#        ],
#       "interface_name": "podman0"
#     }
#   },
#   "network_info": {
#   }
# }


import argparse
import hmac
import ipaddress
import json
import logging
import pwd
import re
import sqlite3
import subprocess

from pathlib import Path

import podman  # pylint: disable=import-error

CONTAINER_ID_FILENAME = "ctr-id"
NETAVARK_CONF_FILENAME = "netavark"
NETNS_FILENAME = "netns"

MAX_IP_ITERATIONS = 100
IP_ITERATION_STEP = 7  # this should be a prime number

DB_PATH = "/var/lib/containers/rootful_network.sqlite3"

NETAVARK_BIN = "/usr/libexec/podman/netavark"
NETAVARK_TIMEOUT = 60

# See https://docs.podman.io/en/latest/markdown/podman-run.1.html, except we do
# not randomly assign host ports when none are specified
PUBLISH_REGEX = re.compile(
    r"^(?:"
    r"(?:(?P<ip>(?:\[[a-fA-F0-9:]+\]|[0-9.]+)):)?"
    r"(?P<hostPort>\d+(?:-\d+)?):"
    r")?"
    r"(?P<containerPort>\d+(?:-\d+)?)"
    r"(?:\/(?P<protocol>.*))?$"
)


def parse_arguments():
    """
    Parse command line arguments and return them.
    """
    parser = argparse.ArgumentParser(
        prog="rootful_network",
        description="Attach a podman netavark network to a rootless podman container",
    )

    parser.add_argument(
        "runtime_dir",
        help=(
            "Path to the runtime directory that contains the container ID as generated by"
            " podman create --cidfile in a file named ctr-id"
        ),
        type=Path,
    )

    subparsers = parser.add_subparsers(help="Mode of operation")

    setup_parser = subparsers.add_parser(
        "setup", help="Connect a network to a container"
    )
    setup_parser.set_defaults(func=setup)
    setup_parser.add_argument(
        "systemd_service",
        help=(
            "Full name of the systemd service; use %%n in a systemd service"
            " file to generate this."
        ),
    )
    setup_parser.add_argument(
        "mac_file",
        help=(
            "Path to a file that contains a secret for HMAC with SHA3-512 to"
            " compute IP addresses from the given systemd service name."
        ),
        type=Path,
    )
    setup_parser.add_argument(
        "user",
        help=(
            "Username of the user that will be used to start the container,"
            " usually available in the $USER environemnt variable in the"
            " systemd service file."
        ),
    )
    setup_parser.add_argument(
        "podman_network", help="Name of the podman network to attach to the container"
    )
    setup_parser.add_argument(
        "--network-alias",
        dest="network_alias",
        action="append",
        help=("Add a DNS alias for the container."),
    )
    setup_parser.add_argument(
        "--dns",
        action="append",
        help=(
            "Set custom DNS servers. This option will override the"
            " aardvark-dns that is added by default, so specifying this"
            " setting will break container discovery by name."
        ),
    )
    setup_parser.add_argument(
        "--publish",
        action="append",
        help=(
            "Port exposure configuration for the container, syntax is"
            " [[ip:][hostPort]:]containerPort[/protocol]"
        ),
    )

    teardown_parser = subparsers.add_parser(
        "teardown", help="Disconnect a network from a container"
    )
    teardown_parser.set_defaults(func=teardown)

    return parser.parse_args()


def cleanup_name(systemd_service):
    """
    Extract the likely container name from the systemd service file name
    """
    return systemd_service.removeprefix("container-").removesuffix(".service")


def database_connect():
    """
    Connect to the database and return a connection object. Creates the
    database tables if they do not exist yet.
    """
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("pragma journal_mode=wal")
    with con:
        con.execute(
            """CREATE TABLE IF NOT EXISTS ip (
            network TEXT,
            ip TEXT,
            container_id TEXT,
            PRIMARY KEY (network, ip)
        )"""
        )

    return con


def allocate_ips(con, network, subnets, mac, container_id):
    """
    Select a pseudorandom IP based on the given MAC in each of the given
    subnets of the given network. Ensures the IP is not already in use by
    querying the database and inserting the selected new IPs into the database.

    When the IPs are no longer used, or a failure occurred, release the IPs by
    calling deallocate_ips.
    """
    static_ips = []
    for subnet in subnets:
        net = ipaddress.ip_network(subnet["subnet"])
        suffixlen = net.max_prefixlen - net.prefixlen
        mask = (1 << suffixlen) - 1

        counter = 0
        while True:
            candidate_ip = ipaddress.ip_address(
                (int(net.network_address) & ~mask)
                | ((int.from_bytes(mac, "big") + counter * IP_ITERATION_STEP) & mask)
            )
            if candidate_ip in (net.network_address, net.broadcast_address):
                counter += 1
                continue

            # check sqlite3 database for this entry, and if it doesn't exist,
            # add it; this needs to happen in a transaction
            try:
                with con:
                    con.execute(
                        "INSERT INTO ip(network, ip, container_id) VALUES (?, ?, ?)",
                        (network, str(candidate_ip), container_id),
                    )
                break
            except sqlite3.IntegrityError:
                pass

            counter += 1
            if counter >= MAX_IP_ITERATIONS:
                raise RuntimeError(
                    f"IP {candidate_ip} is already in use, and is the 100th IP"
                    " we tested. Use a larger subnet."
                )

        # Here, the IP must have been found, otherwise the code above would
        # never have left the loop
        static_ips.append(str(candidate_ip))
    return static_ips


def deallocate_ips(con, container_id):
    """
    Mark all IPs used by the given container ID as free.
    """
    with con:
        con.execute("DELETE FROM ip WHERE container_id = ?", (container_id,))


def query_ips(con, network, container_id):
    """
    Return a list of all IPs currently associated with the given container ID.
    """
    with con:
        res = con.execute(
            "SELECT ip FROM ip WHERE network = ? AND container_id = ?",
            (network, container_id),
        )
        return [row["ip"] for row in res.fetchall()]


def portmappings(publish_arg):
    """
    Check the given --publish arguments for semantic sanity and convert them
    into the "port_mappings" list of dicts expected by netavark. The result
    looks something like

    [
      {
        "host_ip": "ff00::abcd:1",
        "container_port": 8080,
        "host_port": 80,
        "range": 20,
        "protocol": "tcp,udp"
      },
      {
        "host_ip": "",
        "container_port": 5353,
        "host_port": 53,
        "range": 1,
        "protocol": "udp"
      }
    ]
    """
    mappings = []

    if publish_arg is None:
        return mappings

    for publish in publish_arg:
        if match := PUBLISH_REGEX.match(publish):
            container_port = [
                int(x, 10) for x in match.group("containerPort").split("-")
            ]
            host_port = [int(x, 10) for x in match.group("hostPort").split("-")]
            protocol = match.group("protocol") or "tcp"
            host_ip = match.group("ip") or ""

            if len(container_port) != len(host_port):
                raise RuntimeError(
                    f"Mapping '{publish} contains a port range in either the"
                    " container or host port, but not both. Please specify the"
                    " port range for both host and container side.'"
                )

            if len(container_port) > 1:
                range_len_container = container_port[-1] - container_port[0]
                range_len_host = host_port[-1] - host_port[0]

                if range_len_container < 0 or range_len_host < 0:
                    raise RuntimeError(
                        f"Mapping '{publish}' contains a port range that"
                        " starts with the high port and ends with the low"
                        " port. Please specify the port range in ascending"
                        " order."
                    )

                if range_len_container != range_len_host:
                    raise RuntimeError(
                        f"Mapping '{publish}' maps {range_len_container}"
                        f" container ports to {range_len_host} host ports."
                        " Both port ranges must be of equal length"
                    )

                range_len = range_len_container
            else:
                range_len = 1

            if host_ip:
                try:
                    host_ip = str(ipaddress.ip_address(host_ip.strip("[]")))
                except ValueError as vale:
                    raise RuntimeError(
                        f"Mapping '{publish}' contains an invalid host IP"
                    ) from vale
                if host_ip in ("::", "0.0.0.0"):
                    host_ip = ""

            mappings.append(
                {
                    "host_ip": host_ip,
                    "container_port": container_port[0],
                    "host_port": host_port[0],
                    "range": range_len,
                    "protocol": protocol,
                }
            )
        else:
            raise RuntimeError(
                f"Could not parse port mapping '{publish}'. Syntax is"
                " [[ip:][hostPort]:]containerPort[/protocol], see"
                " https://docs.podman.io/en/latest/markdown/podman-run.1.html"
            )

    return mappings


def run_netavark(mode, config, netns):
    """
    Invoke netavark in the given mode on netns with the given configuration
    encoded as json on standard input. On success, decode the JSON printed by
    netavark and return it, otherwise raise an error.
    """
    try:
        result = subprocess.run(
            [NETAVARK_BIN, mode, str(netns)],
            input=json.dumps(config, indent=2),
            encoding="utf-8",
            capture_output=True,
            timeout=NETAVARK_TIMEOUT,
            check=True,
        )
        if result.stdout:
            return json.loads(result.stdout)
        return {}
    except subprocess.CalledProcessError as cpe:
        try:
            error = json.loads(cpe.stdout)
            raise RuntimeError(
                f"netavark failed with error:\n{json.dumps(error, indent=2)}\n"
            ) from cpe
        except json.decoder.JSONDecodeError:
            raise RuntimeError(
                f"netavark failed with exit code {cpe.returncode}\n"
                f"stdout: {cpe.stdout}\n\n"
                f"stderr: {cpe.stderr}\n\n\n"
            ) from cpe


def update_resolv_conf(netavark_settings, pid, args):
    """
    Enter the container's mount namespace and update its resolv.conf with the
    values returned by netavark.
    """
    search_domains = []
    dns_server_ips = []
    for settings in netavark_settings.values():
        search_domains.extend(settings.get("dns_search_domains", []))
        dns_server_ips.extend(settings.get("dns_server_ips", []))

    # If manually specified, ignore netavark's defaults
    if args.dns:
        dns_server_ips = args.dns

    resolv_conf_lines = ["# Generated by rootful_network.py"]
    resolv_conf_lines.extend(
        [f"nameserver {dns_server_ip}" for dns_server_ip in dns_server_ips]
    )
    if search_domains:
        resolv_conf_lines.append(f"search {' '.join(search_domains)}")

    print("Filling /etc/resolv.conf:")
    for line in resolv_conf_lines:
        print(f">> {line}")

    subprocess.run(
        [
            "sudo",
            "-u",
            f"{args.user}",
            "--",
            "nsenter",
            f"--user=/proc/{pid}/ns/user",
            f"--mount=/proc/{pid}/ns/mnt",
            "tee",
            "/etc/resolv.conf",
        ],
        input="\n".join(resolv_conf_lines + []),
        encoding="utf-8",
        check=True,
    )

    if args.network_alias:
        # Add a localhost entry for all DNS aliases
        host_line = f"127.0.0.1  {' '.join(args.network_alias)}"
        print("Appending to /etc/hosts:")
        print(f">> {host_line}")

        subprocess.run(
            [
                "sudo",
                "-u",
                f"{args.user}",
                "--",
                "nsenter",
                f"--user=/proc/{pid}/ns/user",
                f"--mount=/proc/{pid}/ns/mnt",
                "tee",
                "-a",
                "/etc/hosts",
            ],
            input=f"{host_line}\n",
            encoding="utf-8",
            check=True,
        )


def setup(args, con):
    """
    Generate the required configuration and run netavark setup to attach the
    network to the container.
    """
    container_id = (args.runtime_dir / CONTAINER_ID_FILENAME).read_text().strip()
    netns = args.runtime_dir / NETNS_FILENAME
    mac = hmac.digest(
        args.mac_file.read_bytes(),
        cleanup_name(args.systemd_service).encode("utf-8"),
        "SHA3-512",
    )
    target_uid = pwd.getpwnam(args.user).pw_uid

    with podman.PodmanClient(base_url="unix:///run/podman/podman.sock") as root_podman:
        network = root_podman.networks.get(args.podman_network)

    with podman.PodmanClient(
        base_url=f"unix:///run/user/{target_uid:d}/podman/podman.sock"
    ) as user_podman:
        container = user_podman.containers.get(container_id)
        if container.attrs["State"]["Pid"] == 0:
            raise RuntimeError(
                f"Container {container_id} has not been started using podman container init."
            )

    try:
        netns.touch(exist_ok=False)
    except FileExistsError as fee:
        raise RuntimeError(
            f"Network namespace file '{netns!s}' already exists, run teardown first."
        ) from fee

    try:
        subprocess.run(
            [
                "mount",
                "--bind",
                f"/proc/{container.attrs['State']['Pid']}/ns/net",
                str(netns),
            ],
            check=True,
        )
    except subprocess.CalledProcessError as cpe:
        raise RuntimeError(
            f"Failed to bind-mount network namespace to {netns!s}"
        ) from cpe

    config = {
        "container_id": container.id,
        "container_name": container.name,
        "port_mappings": portmappings(args.publish),
        "networks": {
            network.name: {
                "static_ips": [],  # to be set later
                "aliases": args.network_alias,
                "interface_name": "eth0",
            }
        },
        "network_info": {network.name: network.attrs},
    }

    # Do not release the allocated IPs when netavark failed; it might have done
    # a partial setup. The only safe way to leave this state is to invoke
    # teardown.
    config["networks"][network.name]["static_ips"] = allocate_ips(
        con, network.id, network.attrs["subnets"], mac, container.id
    )

    print("netavark configuration successfully generated:")
    print(json.dumps(config, indent=2))

    (args.runtime_dir / NETAVARK_CONF_FILENAME).write_text(json.dumps(config, indent=2))

    # Run /usr/libexec/podman/netavark setup netns
    netavark_settings = run_netavark("setup", config, netns)

    print("netvark invocation successful, netavark response:")
    print(json.dumps(netavark_settings, indent=2))

    update_resolv_conf(netavark_settings, container.attrs["State"]["Pid"], args)


def teardown(args, con):
    """
    Run netavark teardown with the configuration in netavark_config on the
    network namespace netns and remove the IPs associated with container_id
    from the database.
    """
    config = {}
    try:
        with (args.runtime_dir / NETAVARK_CONF_FILENAME).open() as inf:
            config = json.load(inf)
    except FileNotFoundError as fnfe:
        logging.error(
            "netavark configuration '%s' does not exist in '%s'; attempting to"
            " clean up potential unclean shutdown",
            NETAVARK_CONF_FILENAME,
            args.runtime_dir,
        )
        logging.exception(fnfe)

    logging.info("netavark teardown configuration:\n%s", json.dumps(config, indent=2))

    try:
        # Run /usr/libexec/podman/netavark teardown netns
        if config:
            run_netavark("teardown", config, args.runtime_dir / NETNS_FILENAME)
            logging.info("netavark teardown successful")
        else:
            logging.warning(
                "skipping netavark teardown because no configuration was available"
            )

        # Clean up netns bind-mount if present
        netns = args.runtime_dir / NETNS_FILENAME
        if netns.exists():
            # Attempt unmount
            logging.info("Unmounting network namespace bind mount %s", netns)
            try:
                subprocess.run(["umount", str(netns)], check=True)
            except subprocess.CalledProcessError as cpe:
                logging.error(
                    "Failed to unmount network namespace bind mount %s; maybe"
                    " it wasn't a bind-mount?",
                    netns,
                )
                logging.exception(cpe)

            netns.unlink()
    finally:
        container_id = None
        try:
            container_id = (
                (args.runtime_dir / CONTAINER_ID_FILENAME).read_text().strip()
            )
        except FileNotFoundError as fnfe:
            logging.error(
                "Could not read container ID from %s/%s, could not clean up IP"
                " addresses. Check that there are no leaked IPs.",
                args.runtime_dir,
                CONTAINER_ID_FILENAME,
            )
            logging.exception(fnfe)

        if container_id is not None:
            logging.info(
                "Marking IP addresses used by container %s as free", container_id
            )
            deallocate_ips(con, container_id)


def main():
    """
    Command line entry point
    """
    args = parse_arguments()

    with database_connect() as con:
        args.func(args, con)


if __name__ == "__main__":
    main()
