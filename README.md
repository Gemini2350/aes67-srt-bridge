# AES67 SRT Bridge

Docker container that carries AES67 / ST 2110-30 streams over SRT
([srt-live-transmit](https://github.com/Haivision/srt/blob/master/docs/apps/srt-live-transmit.md)) and
represents both ends as NMOS resources (IS-04 + IS-05), with a web GUI.

```
 site A                                                         site B
 AES67 sender ──mcast──► [TX channel]  ══ SRT ══►  [RX channel] ──mcast──► AES67 receivers
                          virtual NMOS receiver      virtual NMOS sender
                          (IS-05 patchable)          (rewritten source SDP, own multicast)
```

* **TX channel** = virtual NMOS **receiver**. When a controller connects it (IS-05 `activate` with an SDP),
  the bridge joins the multicast (SSM if the SDP has `a=source-filter`) and sends it to the SRT peer.
* **RX channel** = virtual NMOS **sender** (with source and flow). It receives SRT and sends the stream to a
  configurable multicast group. Its transport file is the **original SDP** with new `c=`, `m=` port,
  `a=source-filter`, `o=` (optionally a new `a=ts-refclk`).
* **srt-live-transmit reads and writes the multicast directly** (`udp://@group:port?adapter=..&source=..` on
  TX, `udp://group:port?adapter=..&ttl=..` on RX). The bridge does not sit in the media path; it only listens
  passively in the same groups for counters and BCP-008.
* The source SDP travels over a **second, small SRT link on SRT port + 1** (same passphrase), once per
  second. The RX side needs no HTTP path to the TX side. A manual SDP can override it.
* **FEC** (SRT packet filter) is optional per channel.
* Registry: unicast DNS-SD (`_nmos-register._tcp`, legacy `_nmos-registration._tcp`), mDNS, or manual URL.
* Several TX and RX channels per container, one SRT connection (port) per channel.
* **IS-12 + BCP-008-01/-02**: one NcReceiverMonitor per TX channel, one NcSenderMonitor per RX channel, with
  live status from the multicast input, the SRT link and the output (see below).
* **IS-13**: label, description and tags of node, device, sources, flows, senders and receivers are writable
  and persisted.

## Install

On the Docker host (Linux, Docker with compose plugin):

```bash
mkdir -p ~/aes67-srt-bridge && cd ~/aes67-srt-bridge
curl -fsSLO https://raw.githubusercontent.com/Gemini2350/aes67-srt-bridge/main/docker-compose.yml
docker compose up -d
```

Update: `docker compose pull && docker compose up -d`. The image (`ghcr.io/gemini2350/aes67-srt-bridge`,
amd64 + arm64) is built by GitHub Actions on every push to `main`. To build locally instead:
`git clone` and `docker compose up -d --build` with `build: .` enabled in `docker-compose.yml`.

Open `http://<host>:8095/`. `network_mode: host` is required (multicast, IGMP, NMOS endpoints).
Configuration lives in `./data/config.json`; the node/resource ids are derived from a seed stored there,
so they stay stable across restarts and image updates. On `docker stop` the node unregisters itself.

## RTP timestamps

Default: **pass-through**. The packets go through srt-live-transmit unchanged, timestamps included
(`tools/rtp_compare.py` checks this byte by byte). This is correct when both sites are locked to the same
PTP time (e.g. both GMs on GNSS). Receivers at site B then see packets that are
`SRT latency + transit` old (about 125 ms with 120 ms latency in the lab). Their **link offset / playout
delay must be larger than that**, otherwise they drop the packets.

Option per RX channel: **restamp to local PTP time**. This is the only mode with a relay in the path
(srt-live-transmit → `127.0.0.1` → relay → multicast). Timestamps are shifted by a constant so they are "now"
on the RX host (`a=mediaclk:direct=0` in the published SDP). Receivers can then use normal small link
offsets. This requires the RX host clock to be disciplined to PTP (ptp4l + phc2sys). The clock source is
`CLOCK_TAI` if the kernel TAI offset is set, otherwise `CLOCK_REALTIME + 37 s` (configurable). If the
deviation exceeds the resync tolerance (default 20 ms), the offset is recomputed and logged.

## Flush host DNS cache

Settings → "Flush host DNS cache" calls `FlushCaches` on the host's **systemd-resolved** via D-Bus, the same as
`resolvectl flush-caches`. It also clears the bridge's own DNS-SD caches (passively learned mDNS records, failed
registries) and restarts registry discovery (heartbeat first, so no re-registration if the registry stays the same).
Requirements are in `docker-compose.yml`:

* `/run/dbus:/run/dbus:ro`: the host's system bus.
* `security_opt: apparmor:unconfined`: on AppArmor hosts (Ubuntu), Docker's default profile blocks D-Bus from
  containers. Remove both lines if you do not need the button. It then reports what is missing.

Hosts without systemd-resolved (e.g. nscd or dnsmasq as cache) are reported as such. Those caches cannot be
reached from the container.

## Status monitoring (IS-12, BCP-008)

IS-12 endpoint: `ws://<host>:8095/x-nmos/ncp/v1.0`, advertised as `urn:x-nmos:control:ncp/v1.0` in the IS-04 device.
The MS-05-02 device model has a root block, a DeviceManager, a ClassManager and one status monitor per channel.
The ClassManager serves the full class and datatype descriptors published by AMWA (`app/models/`, Apache-2.0).
For each status domain, the bridge reports what it can actually measure:

| TX channel → NcReceiverMonitor | |
|---|---|
| linkStatus | operstate of the media interface |
| connectionStatus | reception only: Unhealthy when no multicast packets arrive or RTP sequence gaps occur on the multicast input. The SRT link (state, retransmissions, drops) is not part of it; the GUI shows it per channel |
| streamStatus | Unhealthy: not RTP. PartiallyHealthy: payload type or payload size does not match the SDP |
| externalSynchronizationStatus | NotUsed, `synchronizationSourceId` = `internal` (the bridge forwards packets and does not lock to PTP) |
| GetLostPacketCounters | RTP sequence gaps on the multicast input |

| RX channel → NcSenderMonitor | |
|---|---|
| linkStatus | operstate of the media interface |
| transmissionStatus | Unhealthy: send errors on the multicast output |
| essenceStatus | Unhealthy: no SDP, SRT not connected or no packets. PartiallyHealthy: SRT loss or retransmissions (inherited from the SRT "receiver") |
| externalSynchronizationStatus | NotUsed / `internal` |
| GetTransmissionErrorCounters | send errors |

These BCP-008 rules are implemented:
* `statusReportingDelay` is fixed at the BCP-008 default of 3 s. It is published as a runtime constraint
  (minimum = maximum = 3), and Set accepts only 3. `autoResetCountersAndMessages` is always true; Set accepts
  only `true`. BCP-008 requires only these values to be settable.
* On activation, domains with an Inactive state go to Healthy immediately. Non-healthy states are held back for
  3 s.
* After that, a worse state is reported immediately. A better state is reported only after it has persisted for
  `statusReportingDelay`.
* Deactivation sets connection/transmission, stream/essence and overall to Inactive immediately.
* Transition counters count only changes to a less healthy state.
* `autoResetCountersAndMessages` resets counters and messages on every activation.
* A recovered domain keeps its previous cause as `Previously: …`.

The GUI shows the same statuses per channel and can reset the counters. An explicit IS-12 `userLabel` is persisted.

## Annotation (IS-13)

`http://<host>:8095/x-nmos/annotation/v1.0/`, advertised as the `urn:x-nmos:service:annotation/v1.0` service
of the node. PATCH `label`, `description` and `tags` (`null` restores the default). The new version is
re-registered immediately. Annotations survive restarts and image updates. A monitor's `userLabel` follows
the annotated label unless it was set explicitly via IS-12. Renaming a channel in the GUI clears its label annotation.

## NMOS details

* Node API v1.2/v1.3, registration v1.3, heartbeat 5 s, re-registration on 404.
* Registry failover by DNS-SD priority. A passive mDNS browser keeps alternatives known. On failover the node
  sends a heartbeat first and re-registers only on 404. A stale node (200 on first registration) is deleted and
  registered again.
* Deprecated IS-04 `PUT /receivers/{id}/target` is supported (202, connects via the sender's manifest).
* IS-05 v1.0 + v1.1: single and bulk, `activate_immediate`, `activate_scheduled_absolute/relative`,
  receiver `transport_file`, sender `transportfile` (404 until a source SDP is known).
* CORS is enabled, so browser-based controllers can patch directly.
* Node clock: `ptp` with the configured grandmaster id, otherwise `internal`.
* Registry senders for the GUI's connect dialog are queried with `query.downgrade=v1.0` and paging.
* Only the first media section of an SDP is used (no ST 2022-7 second leg).

## SRT

Each channel can be caller or listener (TX default caller, RX default listener). Per channel you set:
latency, AES passphrase (10–79 characters, 16/24/32 byte keys), stream id and FEC.

Per channel there are two SRT links:

| | port | content |
|---|---|---|
| media | SRT port (e.g. 9000) | the AES67 stream, unchanged |
| SDP | SRT port + 1 (e.g. 9001), configurable | the source SDP, once per second |

**Firewall:** open both UDP ports towards the listener. Both sites must run the same bridge version, because
earlier versions sent the SDP inside the media stream.

Changing the IS-05 output of an RX channel (on/off, new group) restarts its srt-live-transmit. The SRT caller
reconnects within about a second. While the output is off, the stream goes to an unused local port, so the
SRT link stays up.

**FEC** uses SRT's built-in packet filter, e.g. `fec,cols:10,rows:5`. Set the same value on both sides.
* `cols` is the row length. A row of `cols` packets gets one parity packet, which repairs a single loss in that row.
* With `rows` > 1 there is also one parity packet per column. A burst of up to `cols` consecutive packets
  can then be rebuilt as well.
* Extra traffic is about 1/cols + 1/rows (10×5 ≈ 30 %, at 1000 pkt/s AES67 that is ~0.8 Mbit/s).
* Lost packets that FEC cannot rebuild are still retransmitted (ARQ).
* The FEC matrix must fit into the latency: cols × rows × packet time (10×5 at 1 ms = 50 ms) < latency.

Lab result at 1 % random loss: with FEC 10×5, 296 of 335 lost packets were rebuilt without waiting for an RTT
and 2 were retransmitted. Without FEC, all 461 needed a retransmission. On a link with 20–40 ms RTT, this is
what decides whether a packet arrives in time.

srt-live-transmit runs supervised and restarts after 2 s if it exits. The GUI shows RTT, rate,
lost/retransmitted/dropped/belated packets and FEC rebuilt/failed from its statistics.
Passphrases are masked in all logs.

The SDP link and the "output off" sink use local ports `127.0.0.1:41000+id` / `41500+id` (`LOCAL_BASE_PORT`).
Change that if two bridge containers share one host network (as in the lab test).

## Conformance

Tested with the [AMWA NMOS Testing Tool](https://github.com/AMWA-TV/nmos-testing). There were 0 failures in
every suite: IS-04-01 (48 pass), IS-05-01, IS-12-01 (120 pass, invasive + exhaustive MS-05 testing),
BCP-008-01-01 (98 pass) and BCP-008-02-01 (96 pass).
The remaining "Manual" items need forced error conditions and were checked by hand: link loss, multicast loss and
SRT loss, with notifications in the order domain status → message → overall.
"Could Not Test" items cover optional features the bridge does not use: constraints, vendor classes, BCP-004
receiver caps and BCP-002 tags. The testing tool has no IS-13 suite yet, so IS-13 was tested manually.

## Test tools

* `tools/aes67_gen.py <group> <port> [if_ip] [channels]`: L24/48 kHz/1 ms test sender, timestamps = TAI.
* `tools/aes67_check.py <group> <port> [if_ip] [seconds]`: packet rate, sequence gaps, timestamp age.
* `tools/rtp_compare.py <in_group> <in_port> <out_group> <out_port> [if_ip] [seconds]`: compares the stream before
  and after the bridge byte by byte. In pass-through mode, all matched packets are identical (header, timestamp, payload).
* `tools/is12_probe.py ws://host:8095/x-nmos/ncp/v1.0 [seconds]`: walks the IS-12 device model, checks
  descriptors and Set/Get errors, then prints notifications for the given time.

Lab result (TX and RX container on one host, 120 ms latency, AES-128):
1000 pkt/s, 0 gaps, 0 SRT loss. Pass-through timestamp age ≈ 127 ms. With restamp the median is ≈ 5 ms.
