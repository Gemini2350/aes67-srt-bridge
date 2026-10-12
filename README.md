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
* The source SDP travels **inside the SRT stream** (one non-RTP datagram per second). The RX side needs no
  HTTP path to the TX side; a manual SDP can override it.
* Registry: unicast DNS-SD (`_nmos-register._tcp`, legacy `_nmos-registration._tcp`), mDNS, or manual URL.
* Several TX and RX channels per container, one SRT connection (port) per channel.

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

Default: **pass-through**. RTP timestamps are not touched. This is correct when both sites are locked to the same
PTP time (e.g. both GMs on GNSS). Receivers at site B then see packets that are
`SRT latency + transit` old (about 125 ms with 120 ms latency in the lab). Their **link offset / playout
delay must be larger than that**, otherwise they drop the packets.

Option per RX channel: **restamp to local PTP time**. Timestamps are shifted by a constant so they are "now"
on the RX host (`a=mediaclk:direct=0` in the published SDP). Receivers can then use normal small link
offsets. This requires the RX host clock to be disciplined to PTP (ptp4l + phc2sys). The clock source is
`CLOCK_TAI` if the kernel TAI offset is set, otherwise `CLOCK_REALTIME + 37 s` (configurable). If the
deviation exceeds the resync tolerance (default 20 ms), the offset is recomputed and logged.

## NMOS details

* Node API v1.2/v1.3, registration v1.3, heartbeat 5 s, re-registration on 404, rediscovery after 3 failures.
* IS-05 v1.0 + v1.1: single and bulk, `activate_immediate`, `activate_scheduled_absolute/relative`,
  receiver `transport_file`, sender `transportfile` (404 until a source SDP is known).
* CORS is enabled, so browser-based controllers can patch directly.
* Node clock: `ptp` with the configured grandmaster id, otherwise `internal`.
* Registry senders for the GUI's connect dialog are queried with `query.downgrade=v1.0` and paging.
* Only the first media section of an SDP is used (no ST 2022-7 second leg).

## SRT

Each channel can be caller or listener (TX default caller, RX default listener), with latency,
AES passphrase (10–79 characters, 16/24/32 byte keys) and stream id. srt-live-transmit runs supervised and restarts
after 2 s if it exits. The GUI shows RTT, rate, lost/retransmitted/dropped packets from its JSON statistics.
Passphrases are masked in all logs.

Internal hops use `127.0.0.1:41000+channel id` (`LOCAL_BASE_PORT`). Change that if two
bridge containers share one host network (as in the lab test).

## Test tools

* `tools/aes67_gen.py <group> <port> [if_ip] [channels]`: L24/48 kHz/1 ms test sender, timestamps = TAI.
* `tools/aes67_check.py <group> <port> [if_ip] [seconds]`: packet rate, sequence gaps, timestamp age.

Lab result (TX and RX container on one host, 120 ms latency, AES-128):
1000 pkt/s, 0 gaps, 0 SRT loss. Pass-through timestamp age ≈ 127 ms. With restamp the median is ≈ 5 ms.
