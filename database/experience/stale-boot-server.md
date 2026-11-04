---
topic: stale-boot-server
kind: experience
date: 2026-11-04
symptom_class: no-netboot
---

## Symptom

The machine sat in firmware indefinitely. Power on, LED on, no console progress,
no network. Nothing anywhere reported an error. Resetting repeatedly changed
nothing.

## Why it is misleading

Every visible signal pointed at the hypervisor or the machine: a box that powers
on and never boots looks like broken firmware or a hardware fault. The actual
fault was on the *host* and had nothing to do with either.

## Cause

A stale `python3 -m http.server 6767` from a day earlier, started before the
repository layout changed, still held the port while serving a directory that no
longer existed. It answered **404** for both boot images, so the firmware had
nothing to fetch.

The harness made it worse: `start_serve` treated "the port is open" as success,
and reported `serve: True`, so the one component that could have explained the
failure claimed to be working.

## How to tell them apart

Fetch a boot image and check the status code, not the port:

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:6767/PulverizedDXE.efi
```

`200` with a plausible size means the server is usable. A listening port proves
nothing: any process can hold it.

## Fix

`start_serve` verifies a `200` with a non-zero `Content-Length` for a real image
before reporting success, and treats a foreign process that serves the right
files as usable rather than fighting it for the port.

## Residual risk

Any process can still take port 6767. If `serve` reports a failure to bind, the
message now says the port is occupied but not serving images, which points at the
foreign process instead of at the machine.
