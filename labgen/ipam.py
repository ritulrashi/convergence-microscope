"""Address allocation and the resolved lab plan.

Allocation is a pure function of intent order, so the same intent always gives
the same addresses. The plan is written as plan.json next to the configs and
is what labctl verifies against.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field

from labgen.model import DEFAULT_TIMERS, Intent, Mode, Role, Timers


class PoolExhausted(ValueError):
    pass


@dataclass(frozen=True)
class Iface:
    name: str  # eth1, eth2, ...
    address: str  # 10.1.0.0/31
    peer: str  # peer node name (router or host)
    peer_address: str  # 10.1.0.1 (no prefix length)
    cost: int
    kind: str  # "fabric" or "host"


@dataclass
class RouterPlan:
    name: str
    role: str
    asn: int
    router_id: str
    loopback: str  # 10.0.0.1/32
    isis_net: str
    timers: dict
    ifaces: list[Iface] = field(default_factory=list)
    host_subnets: list[str] = field(default_factory=list)


@dataclass
class HostPlan:
    name: str
    router: str
    site: int
    address: str  # 10.10.1.10/24
    gateway: str  # 10.10.1.1
    iface: str = "eth1"


@dataclass
class LinkPlan:
    a: str
    a_iface: str
    b: str
    b_iface: str
    subnet: str
    cost: int


@dataclass
class Plan:
    name: str
    topology: str
    mode: str
    bfd: bool
    routers: list[RouterPlan]
    hosts: list[HostPlan]
    links: list[LinkPlan]

    def router(self, name: str) -> RouterPlan:
        for r in self.routers:
            if r.name == name:
                return r
        raise KeyError(name)

    def to_dict(self) -> dict:
        return asdict(self)


def _timers_dict(t: Timers) -> dict:
    return t.model_dump()


def _isis_net(loopback: ipaddress.IPv4Address) -> str:
    # 49.0001.<loopback as 12 digits>.00, e.g. 10.0.0.1 -> 0100.0000.0001
    digits = "".join(f"{int(o):03d}" for o in str(loopback).split("."))
    return f"49.0001.{digits[0:4]}.{digits[4:8]}.{digits[8:12]}.00"


def build_plan(intent: Intent, mode: Mode | None = None, bfd: bool | None = None) -> Plan:
    intent = intent.with_overrides(mode, bfd)
    pools = intent.pools
    asns = intent.router_asns()

    lo_hosts = list(pools.loopback.hosts()) if pools.loopback.prefixlen < 31 else []
    if len(intent.nodes) > len(lo_hosts):
        raise PoolExhausted(
            f"loopback pool {pools.loopback} has {len(lo_hosts)} addresses, "
            f"{len(intent.nodes)} routers need one each"
        )
    link_subnets = pools.link.subnets(new_prefix=31) if pools.link.prefixlen <= 31 else iter(())
    n_link = 2 ** (31 - pools.link.prefixlen) if pools.link.prefixlen <= 31 else 0
    if len(intent.links) > n_link:
        raise PoolExhausted(
            f"link pool {pools.link} has {n_link} /31s, {len(intent.links)} links need one each"
        )
    host_sites = list(pools.host.subnets(new_prefix=24))
    for h in intent.hosts:
        if h.site >= len(host_sites):
            raise PoolExhausted(f"host pool {pools.host} has no /24 for site {h.site}")

    base_timers = DEFAULT_TIMERS.merged(intent.routing.timers)
    routers: dict[str, RouterPlan] = {}
    for n, lo in zip(intent.nodes, lo_hosts, strict=False):
        rid = str(n.router_id) if n.router_id is not None else str(lo)
        routers[n.name] = RouterPlan(
            name=n.name,
            role=n.role.value,
            asn=asns[n.name],
            router_id=rid,
            loopback=f"{lo}/32",
            isis_net=_isis_net(lo),
            timers=_timers_dict(base_timers.merged(n.timers)),
        )
    if_count = {name: 0 for name in routers}

    def next_if(node: str) -> str:
        if_count[node] += 1
        return f"eth{if_count[node]}"

    links: list[LinkPlan] = []
    for lk, sub in zip(intent.links, link_subnets, strict=False):
        a_ip, b_ip = sub[0], sub[1]
        a_if, b_if = next_if(lk.a), next_if(lk.b)
        routers[lk.a].ifaces.append(Iface(a_if, f"{a_ip}/31", lk.b, str(b_ip), lk.cost, "fabric"))
        routers[lk.b].ifaces.append(Iface(b_if, f"{b_ip}/31", lk.a, str(a_ip), lk.cost, "fabric"))
        links.append(LinkPlan(lk.a, a_if, lk.b, b_if, str(sub), lk.cost))

    hosts: list[HostPlan] = []
    for h in intent.hosts:
        net = host_sites[h.site]
        gw, addr = net[1], net[10]
        r_if = next_if(h.attach)
        routers[h.attach].ifaces.append(Iface(r_if, f"{gw}/24", h.name, str(addr), 10, "host"))
        routers[h.attach].host_subnets.append(str(net))
        hosts.append(HostPlan(h.name, h.attach, h.site, f"{addr}/24", str(gw)))
        links.append(LinkPlan(h.attach, r_if, h.name, "eth1", str(net), 10))

    return Plan(
        name=intent.name,
        topology=intent.topology.value,
        mode=intent.routing.mode.value,
        bfd=intent.routing.bfd,
        routers=list(routers.values()),
        hosts=hosts,
        links=links,
    )


def is_spine(r: RouterPlan) -> bool:
    return r.role == Role.spine.value
