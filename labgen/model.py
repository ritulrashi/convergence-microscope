"""Intent schema. One YAML file describes a topology, its routing and its pools.

Validation here is structural plus every cross-field rule in SPEC 4.3: duplicate
ASNs or router IDs, overlapping or exhausted pools, links to unknown nodes, and
T1 leaves with fewer than two uplinks. Pool exhaustion is checked by the IPAM
step (labgen.ipam) because it depends on allocation.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Mode(StrEnum):
    ebgp = "ebgp"
    ospf = "ospf"
    isis = "isis"


class TopologyKind(StrEnum):
    leafspine = "leafspine"
    mesh = "mesh"


class Role(StrEnum):
    spine = "spine"
    leaf = "leaf"
    router = "router"


class Timers(Strict):
    """Protocol timers. Every field is optional so per-router overrides can
    set only what differs; `resolved()` merges onto the defaults."""

    bgp_keepalive_s: int | None = Field(default=None, ge=1)
    bgp_hold_s: int | None = Field(default=None, ge=3)
    bgp_connect_retry_s: int | None = Field(default=None, ge=1)
    ospf_hello_s: int | None = Field(default=None, ge=1)
    ospf_dead_s: int | None = Field(default=None, ge=2)
    # OSPF: timers throttle spf <delay> <initial-hold> <max-hold>
    spf_delay_ms: int | None = Field(default=None, ge=0, le=600000)
    spf_hold_ms: int | None = Field(default=None, ge=0, le=600000)
    spf_max_hold_ms: int | None = Field(default=None, ge=0, le=600000)
    isis_hello_s: int | None = Field(default=None, ge=1)
    isis_hello_multiplier: int | None = Field(default=None, ge=2)
    # IS-IS: spf-delay-ietf init-delay short-delay long-delay holddown time-to-learn
    isis_spf_init_ms: int | None = Field(default=None, ge=0, le=60000)
    isis_spf_short_ms: int | None = Field(default=None, ge=0, le=60000)
    isis_spf_long_ms: int | None = Field(default=None, ge=0, le=60000)
    isis_spf_holddown_ms: int | None = Field(default=None, ge=0, le=60000)
    isis_spf_time_to_learn_ms: int | None = Field(default=None, ge=0, le=60000)
    bfd_tx_ms: int | None = Field(default=None, ge=10)
    bfd_rx_ms: int | None = Field(default=None, ge=10)
    bfd_multiplier: int | None = Field(default=None, ge=2)

    def merged(self, over: Timers | None) -> Timers:
        if over is None:
            return self
        data = self.model_dump()
        data.update({k: v for k, v in over.model_dump().items() if v is not None})
        return Timers(**data)


DEFAULT_TIMERS = Timers(
    bgp_keepalive_s=1,
    bgp_hold_s=3,
    bgp_connect_retry_s=2,
    ospf_hello_s=1,
    ospf_dead_s=3,
    spf_delay_ms=50,
    spf_hold_ms=200,
    spf_max_hold_ms=5000,
    isis_hello_s=1,
    isis_hello_multiplier=3,
    isis_spf_init_ms=50,
    isis_spf_short_ms=200,
    isis_spf_long_ms=5000,
    isis_spf_holddown_ms=10000,
    isis_spf_time_to_learn_ms=500,
    bfd_tx_ms=100,
    bfd_rx_ms=100,
    bfd_multiplier=3,
)


class AsnScheme(Strict):
    """RFC 7938 style: spines share `spine`; every other router gets
    `base + index` in intent order, unless the node sets `asn` itself."""

    spine: int | None = Field(default=None, ge=1, le=4294967294)
    base: int = Field(default=65101, ge=1, le=4294967294)


class Routing(Strict):
    mode: Mode
    bfd: bool = False
    timers: Timers = Timers()
    asn: AsnScheme = AsnScheme()


class Pools(Strict):
    loopback: ipaddress.IPv4Network = ipaddress.IPv4Network("10.0.0.0/24")
    link: ipaddress.IPv4Network = ipaddress.IPv4Network("10.1.0.0/16")
    host: ipaddress.IPv4Network = ipaddress.IPv4Network("10.10.0.0/16")

    @model_validator(mode="after")
    def _no_overlap(self) -> Pools:
        items = [("loopback", self.loopback), ("link", self.link), ("host", self.host)]
        for i, (na, a) in enumerate(items):
            for nb, b in items[i + 1 :]:
                if a.overlaps(b):
                    raise ValueError(f"pools overlap: {na} {a} and {nb} {b}")
        if self.host.prefixlen > 16:
            raise ValueError(f"host pool {self.host} must be /16 or larger (sites are /24s)")
        return self


class Node(Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9]{0,14}$")
    role: Role
    asn: int | None = Field(default=None, ge=1, le=4294967294)
    router_id: ipaddress.IPv4Address | None = None
    timers: Timers | None = None


class Host(Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9]{0,14}$")
    attach: str
    site: int = Field(ge=0, le=255)


class Link(Strict):
    a: str
    b: str
    cost: int = Field(default=10, ge=1, le=65535)


class Intent(Strict):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,30}$")
    topology: TopologyKind
    routing: Routing
    pools: Pools = Pools()
    nodes: list[Node]
    hosts: list[Host] = []
    links: list[Link]

    @model_validator(mode="after")
    def _cross_checks(self) -> Intent:
        errors: list[str] = []
        names = [n.name for n in self.nodes] + [h.name for h in self.hosts]
        for name, n in Counter(names).items():
            if n > 1:
                errors.append(f"duplicate node name {name!r}")
        routers = {n.name: n for n in self.nodes}

        for i, link in enumerate(self.links):
            for end in (link.a, link.b):
                if end not in routers:
                    errors.append(f"link {i} ({link.a}-{link.b}) references unknown node {end!r}")
            if link.a == link.b:
                errors.append(f"link {i} connects {link.a!r} to itself")
        pairs = Counter(frozenset((lk.a, lk.b)) for lk in self.links)
        for pair, n in pairs.items():
            if n > 1:
                errors.append(f"duplicate link between {' and '.join(sorted(pair))}")

        for h in self.hosts:
            if h.attach not in routers:
                errors.append(f"host {h.name!r} attaches to unknown node {h.attach!r}")
        for site, n in Counter(h.site for h in self.hosts).items():
            if n > 1:
                errors.append(f"duplicate host site {site}")

        if self.topology is TopologyKind.leafspine:
            spines = {n.name for n in self.nodes if n.role is Role.spine}
            for n in self.nodes:
                if n.role is Role.router:
                    errors.append(f"node {n.name!r}: role 'router' is not valid in leafspine")
                if n.role is not Role.leaf:
                    continue
                up = sum(1 for lk in self.links if n.name in (lk.a, lk.b)
                         and ({lk.a, lk.b} - {n.name}) <= spines)
                if up < 2:
                    errors.append(f"leaf {n.name!r} has {up} uplink(s); at least 2 are required")
            if self.routing.mode is Mode.ebgp and self.routing.asn.spine is None:
                errors.append("leafspine ebgp needs routing.asn.spine")
        else:
            for n in self.nodes:
                if n.role is not Role.router:
                    errors.append(f"node {n.name!r}: mesh nodes must have role 'router'")

        rids = [str(n.router_id) for n in self.nodes if n.router_id is not None]
        for rid, n in Counter(rids).items():
            if n > 1:
                errors.append(f"duplicate router ID {rid}")

        if self.routing.mode is Mode.ebgp:
            asns = self.router_asns()
            nonspine = [asns[n.name] for n in self.nodes if n.role is not Role.spine]
            spine_asns = {asns[n.name] for n in self.nodes if n.role is Role.spine}
            for asn, n in Counter(nonspine).items():
                if n > 1:
                    errors.append(f"duplicate ASN {asn}")
                if asn in spine_asns:
                    errors.append(f"ASN {asn} is used by both a spine and a non-spine router")

        if errors:
            raise ValueError("; ".join(errors))
        return self

    def router_asns(self) -> dict[str, int]:
        out: dict[str, int] = {}
        idx = 0
        for n in self.nodes:
            if n.asn is not None:
                out[n.name] = n.asn
            elif n.role is Role.spine and self.routing.asn.spine is not None:
                out[n.name] = self.routing.asn.spine
            else:
                out[n.name] = self.routing.asn.base + idx
            if n.role is not Role.spine:
                idx += 1
        return out

    def with_overrides(self, mode: Mode | None = None, bfd: bool | None = None) -> Intent:
        if (mode is None or mode is self.routing.mode) and (bfd is None or bfd == self.routing.bfd):
            return self
        data = self.model_dump(mode="json")
        if mode is not None:
            data["routing"]["mode"] = mode.value
        if bfd is not None:
            data["routing"]["bfd"] = bfd
        return Intent.model_validate(data)


def load_intent(path: str | Path) -> Intent:
    return Intent.model_validate(yaml.safe_load(Path(path).read_text()))
