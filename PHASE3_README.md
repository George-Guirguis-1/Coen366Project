# CENRS Phase 3 — integration and demonstration

## Setup
Replace the three Python files together. All clients and the server must use the updated files. No external Python packages are needed. Keep existing `data/server_state.json`, `attachments/`, `downloads/`, and logs if desired. Create `attachments/` before publishing a file. Use Python 3.10+ (tested here with the container's Python version; Windows 3.14 remains to be verified).

Start the server: `python server.py`. Start three clients in separate terminals:

```
python client.py --server 127.0.0.1 --udp-port 5001 --tcp-port 6001
python client.py --server 127.0.0.1 --udp-port 5002 --tcp-port 6002
python client.py --server 127.0.0.1 --udp-port 5003 --tcp-port 6003
```
Register Alice and Bob as SUBSCRIBER and CampusSecurity as PUBLISHER. Subscribe Alice and Bob to HALL FIRE. Place a real file named `Hall Map.pdf` in `attachments/`. Publisher command:

```
publish FIRE HALL CRITICAL "Fire Alarm" "Evacuate Building" "Hall Map.pdf"
```
Use the actual returned incident ID in the following commands (INC105 is an example):

```
attach INC105 "Hall Map.pdf"
download INC105 "Hall Map.pdf"
sync
alerts
```
Files are saved under `downloads/<subscriber>/<incident>/<filename>`. On Windows use `Get-FileHash` to compare original and downloaded files. Restart the publisher with the same ports and register under the same name to verify the old file still downloads. Restart the server and run `sync` to recover persisted incidents. Close an incident and synchronize to check it disappears. For a clean crash-recovery test, use a separate server `--state` file and terminate the server process externally before restarting with the same arguments.

## Design decisions
- Existing UDP command/response formats are preserved. CLI quoting and percent-encoding allow spaces, Unicode and delimiters in titles, descriptions and filenames; existing underscore-separated examples remain readable. Existing metadata with literal percent escapes may be interpreted differently. All peers should upgrade together.
- TCP headers are newline-terminated UTF-8, followed by exactly File_Size binary bytes for attachments, or one JSON line per active record for synchronization. Incomplete or oversized headers are rejected. `ACTIVE_ALERTS_DENIED` is an extension for invalid requests.
- SHA-256 verifies exact received bytes. Files are limited to 64 MiB, read into a bounded snapshot per publisher worker, transmitted in chunks, and downloaded to a temporary file before atomic replacement. Failed transfers are manually retried. Socket inactivity timeout is 10 seconds. A failed retry does not delete an older verified download.
- Publisher threads check persisted metadata using an extra TCP `CHECK_ATTACHMENT RQ# Publisher Subscriber Incident_ID File_Name` request to the central server, which returns `CHECK_OK RQ#` or `CHECK_DENIED RQ# Reason`. This avoids separate publisher state and lets attachments survive publisher restarts if the original files remain. The central server never stores or forwards file contents. This extension requires server reachability when starting a transfer. A transfer authorized while active may finish after closure.
- Server uses its existing JSON state and lock. TCP handlers take snapshots under the lock and send outside it. Pending ACK records become UNCONFIRMED on restart; timers are not restored. Clients re-register at the same endpoint and run `sync` after reconnecting. Prior recipient names are tracked for ALL_CLEAR; historical noncritical recipients before this upgrade cannot be reconstructed if no other record exists.
- Client notification versions are monotonic, duplicate critical notifications are re-ACKed, and complete sync snapshots are applied under a lock without replacing newer observed UDP versions. Since the base protocol has no global snapshot watermark, a completely unseen delayed UDP notification may still require another sync to reconcile. TCP sync does not generate UDP ACKs.
- This is a trusted classroom LAN simulation, not a production emergency system. No authentication/TLS; registered names are claims, not verified identities. Publisher and subscriber directories are assumed controlled by the local user. Publisher reachability is not guaranteed by registration. Original Phase 1/2 request cache remains in memory; exact-once publication across crashes is not guaranteed. The existing protocol has no heartbeat or offline registration expiry.

## Automated tests
`python test_phase3.py` runs local loopback integration checks using temporary directories and state, not your live project data. It exercises publication/ACK, discovery, two overlapping publisher connections, spaced filenames, publisher re-registration, missing files, sync/filtering, stale versions, ALL_CLEAR to a previous recipient, checksum mismatch, interrupted data, persisted state reload, incomplete TCP header, and unreachable endpoint. It is not an exhaustive network fault or cross-machine test. The included test opens a second server object against persisted data to check recovery; it does not kill an OS process. Run manual crash/restart and Windows tests before final submission.
