![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>False Order</font>

29<sup>th</sup> June 2026

Prepared By: `kangwijen`

Challenge Author(s): `kangwijen`

Difficulty: <font color='green'>Easy</font>

<br><br>

# Synopsis

False Order is an Easy Cloud Forensics challenge that demonstrates CloudTrail-driven incident reconstruction through S3 object version history correlation and IAM AssumeRole session-name spoofing detection to separate a forged record from its sealed original and identify the credential chain behind the tamper.

## Description

Caldrin Vowmark reaches an Ashguard checkpoint with a sealed order that tells Stormbound's soldiers to leave the east gate and report to Crownspire. The officer in charge believes the order came from Garran Voss, and he will move his soldiers as soon as the seal is checked. If they leave, Vaultrune can take the gate before help arrives. Caldrin knows Garran's orders carry small marks that copyists miss. He has to inspect the order, show the officer that it is false, and stop the unit from leaving before Vaultrune's soldiers reach the gate.

## Skills Required

- AWS CLI basics
- CloudTrail lookup-events
- S3 object listing and version history
- Reading identity and source IP fields in audit records

## Skills Learned

- Separating multi-hour external recon from legitimate internal gatehouse traffic
- Spotting session-name framing in `sts:AssumeRole` chains
- Distinguishing `IAMUser` activity from `AssumedRole` destructive sessions
- Pairing CloudTrail API history with S3 version history on the tampered object

# Enumeration

## Environment setup

Players receive a live challenge instance. Open the briefing URL from the instance card to retrieve starting credentials, then export the environment block shown there:

```bash
$ export AWS_ENDPOINT_URL=http://<CHALLENGE_IP>:<AWS_PORT>
$ export AWS_DEFAULT_REGION=us-east-1
$ export AWS_ACCESS_KEY_ID=<from briefing>
$ export AWS_SECRET_ACCESS_KEY=<from briefing>
$ unset AWS_SESSION_TOKEN
```

Confirm the investigator identity before touching anything else. This is the only credential the challenge hands out, so it is worth knowing exactly what it can reach:

```bash
$ aws sts get-caller-identity

{
    "UserId": "AIDAK2LAAENFPIYR9H25",
    "Account": "638291047582",
    "Arn": "arn:aws:iam::638291047582:user/gate-investigator"
}
```

## Finding the tampered object

The briefing named two evidence sources, the versioned bucket and the audit trail. The bucket is the more direct one, so we''ll be checking that one first:

```bash
$ aws s3 ls s3://ashguard-order-custody/custody/

2026-07-14 14:10:13        139 autumn-order.json
2026-07-14 14:10:15        436 east-gate-order.json
2026-07-14 14:10:13        139 spring-order.json
2026-07-14 14:10:13        139 summer-order.json
2026-07-14 14:10:13        137 void-order.json
2026-07-14 14:10:13        145 winter-order-draft.json
```

Five of the six objects sit in between 137-145 byte band and share the same `LastModified` timestamp, which reads like a single batch write at provisioning time. `east-gate-order.json` breaks both patterns: it is roughly three times larger and its `LastModified` is two seconds later than everything else. A file that was touched after the rest of the bucket settled, and that grew substantially in the process, is the obvious place to look next.

Object listing only shows current state, so the next question is whether this object has any history. Versioning is enabled on the bucket, so a version listing should reveal any prior writes:

```bash
$ aws s3api list-object-versions --bucket ashguard-order-custody --prefix custody/east-gate-order.json

{
    "Versions": [
        {
            "ETag": "\"1be261e8b6c7a5d1976fcbec93d62caa\"",
            "Size": 436,
            "StorageClass": "STANDARD",
            "Key": "custody/east-gate-order.json",
            "VersionId": "45f7d6d2-3ad6-4270-83df-23b619046daa",
            "IsLatest": true,
            "LastModified": "2026-07-14T07:10:15+00:00"
        },
        {
            "ETag": "\"382c450d91c4242455cb2f84d7012300\"",
            "Size": 429,
            "StorageClass": "STANDARD",
            "Key": "custody/east-gate-order.json",
            "VersionId": "25cd557c-da8c-4d88-b17c-17a917036dde",
            "IsLatest": false,
            "LastModified": "2026-07-14T07:10:13+00:00"
        }
    ],
    "DeleteMarkers": [
        {
            "Key": "custody/east-gate-order.json",
            "VersionId": "0d75f878-9137-45a8-ab16-435f057472d7",
            "IsLatest": false,
            "LastModified": "2026-07-14T07:10:15+00:00"
        }
    ]
}
```

> **Note:** `VersionId` values and exact timestamps are unique per instance. The pattern is constant: one `IsLatest: true` version, one older non-latest version, and a delete marker sitting between them.

This is the shape of a delete-and-replace, not an in-place edit. An in-place `PutObject` on a versioned key just stacks a new version on top of the old one and never produces a delete marker. Seeing a delete marker between two real versions means someone issued `DeleteObject` on the key (which is what creates a delete marker on a versioned bucket) and then wrote a new object afterward. That two-step shape, plus the older version being smaller and two seconds earlier, points at version `25cd557c-da8c-4d88-b17c-17a917036dde` as the original and the current `IsLatest` version as whatever replaced it. Download and diff both bodies to confirm:

```bash
$ aws s3api get-object --bucket ashguard-order-custody --key custody/east-gate-order.json \
    /tmp/ledger-latest.json > /dev/null && cat /tmp/ledger-latest.json

{
  "settlement_id": "EAST-GATE-C4R2",
  "season": "winter",
  "gate": "coalition-gate",
  "issuer": "Coalition Gate Authority",
  "issued_date": "2026-01-09",
  "total_units": 920,
  "custody_status": "RELEASED",
  "order_status": "RELEASED",
  "witness_line": "Gate release authorized per emergency writ WR-4412; witness attestation waived.",
  "ledger_hash": "sha256:4f8c2a91e0b7d3c6a5f1e9d8c7b6a5049382716f5e4d3c2b1a0f9e8d7c6b5a5"
}

$ aws s3api get-object --bucket ashguard-order-custody --key custody/east-gate-order.json \
    --version-id 25cd557c-da8c-4d88-b17c-17a917036dde /tmp/ledger-original.json > /dev/null \
    && cat /tmp/ledger-original.json

{
  "settlement_id": "EAST-GATE-C4R2",
  "season": "winter",
  "gate": "coalition-gate",
  "issuer": "Coalition Gate Authority",
  "issued_date": "2026-01-09",
  "total_units": 1840,
  "custody_status": "SEALED",
  "order_status": "PENDING_APPROVAL",
  "witness_line": "The gatehouse clerk attested the sealed order before dawn watch.",
  "ledger_hash": "sha256:4f8c2a91e0b7d3c6a5f1e9d8c7b6a5049382716f5e4d3c2b1a0f9e8d7c6b5a4"
}
```

`settlement_id`, `season`, `gate`, `issuer`, and `issued_date` are identical between the two versions, which rules out an unrelated document landing under the same key by coincidence. Everything else changed: `total_units` was halved (1840 to 920), `custody_status` flipped from `SEALED` to `RELEASED`, `order_status` flipped from `PENDING_APPROVAL` to that same `RELEASED` value, the `witness_line` attestation text was swapped for a claim that the witness requirement was waived, and `ledger_hash` no longer matches. The hash only differs in its final hex digit (`...b5a4` versus `...b5a5`), consistent with whoever built the replacement recomputing a hash over their forged body rather than reusing the original. The hash is internally consistent with the forged content, it just does not match what the original body's hash should be. Object storage confirms *what* changed. CloudTrail is needed for *who* changed it, from where, and how they got the access to do it.

## Pulling the CloudTrail history

The trail is `coalition-gate-audit-trail` and the investigator identity has `cloudtrail:LookupEvents` on it. Pull the entire history and save it locally, then check the raw count before filtering anything, so the scope of the problem is known up front:

```bash
$ aws cloudtrail lookup-events --output json > events.json

$ jq '.Events | length' events.json
600
```

Six hundred events is too many to read line by line, so the first useful move is a source-IP breakdown, to see what populations exist in the data at all:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | .sourceIPAddress] |
  group_by(.) | map({ip: .[0], count: length})' events.json

[
  { "ip": "10.41.53.22",  "count": 548 },
  { "ip": "127.0.0.1",    "count": 26 },
  { "ip": "172.17.0.1",   "count": 5 },
  { "ip": "198.18.44.91", "count": 21 }
]
```

Four distinct source addresses. `127.0.0.1` and `172.17.0.1` are loopback and container-local addresses. That leaves two real populations: `10.41.53.22` with 548 events, and `198.18.44.91` with 21. The 548-event population is large enough and steady enough to read as routine, day-to-day access from a fixed internal address. The 21-event population is small, from an address that does not belong to any internal range this environment uses, and worth treating as the outside party until proven otherwise.

Filtering down to just those two addresses and sorting by `eventTime` lays out the full timeline of who did what, in what order:

```bash
$ jq -r '.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress != "127.0.0.1" and .sourceIPAddress != "172.17.0.1") |
  [.eventTime, .eventName, .sourceIPAddress,
   (.userIdentity.userName // (.userIdentity.sessionContext.sessionIssuer.userName // "?")),
   (.errorCode // "")] | join("  ")' events.json | sort
```

```
2026-07-10T07:01:31.284Z  ListObjectsV2       10.41.53.22   coalition-gate-clerk
2026-07-10T07:02:04.912Z  GetObject           10.41.53.22   coalition-gate-clerk
...  (548 coalition-gate-clerk events total, spanning multiple days up to the line below)
2026-07-14T04:09:47.501Z  HeadObject          10.41.53.22   coalition-gate-clerk
2026-07-14T04:09:58.223Z  ListObjectsV2       10.41.53.22   coalition-gate-clerk   <- last event from this address

2026-07-14T04:11:12.582Z  GetCallerIdentity   198.18.44.91  seal-copyist-contractor
2026-07-14T04:24:25.330Z  ListBuckets         198.18.44.91  seal-copyist-contractor
2026-07-14T04:36:38.243Z  ListObjectsV2       198.18.44.91  seal-copyist-contractor
2026-07-14T04:51:14.727Z  GetObject           198.18.44.91  seal-copyist-contractor   AccessDenied
2026-07-14T05:12:39.851Z  ListObjectsV2       198.18.44.91  seal-copyist-contractor
2026-07-14T05:29:12.109Z  ListObjectsV2       198.18.44.91  seal-copyist-contractor
2026-07-14T05:46:46.827Z  AssumeRole          198.18.44.91  seal-copyist-contractor   AccessDenied
2026-07-14T06:05:12.696Z  ListBuckets         198.18.44.91  seal-copyist-contractor
2026-07-14T06:23:21.577Z  ListObjectsV2       198.18.44.91  seal-copyist-contractor
2026-07-14T06:33:28.930Z  ListObjectsV2       198.18.44.91  seal-copyist-contractor
2026-07-14T06:52:00.811Z  ListObjectsV2       198.18.44.91  seal-copyist-contractor   <- recon activity ends here

2026-07-14T12:58:52.335Z  GetCallerIdentity   198.18.44.91  seal-copyist-contractor
2026-07-14T12:58:52.336Z  ListAllMyBuckets    198.18.44.91  seal-copyist-contractor
2026-07-14T12:58:52.337Z  ListObjectsV2       198.18.44.91  seal-copyist-contractor
2026-07-14T12:58:52.338Z  GetObject           198.18.44.91  seal-copyist-contractor   AccessDenied
2026-07-14T12:58:52.339Z  AssumeRole          198.18.44.91  seal-copyist-contractor   AccessDenied
2026-07-14T12:58:52.340Z  AssumeRole          198.18.44.91  seal-copyist-contractor
2026-07-14T12:58:52.341Z  GetCallerIdentity   198.18.44.91  ashguard-order-scanner
2026-07-14T12:58:52.342Z  ListBucketVersions  198.18.44.91  ashguard-order-scanner
2026-07-14T12:58:52.343Z  DeleteObject        198.18.44.91  ashguard-order-scanner
2026-07-14T12:58:52.344Z  PutObject           198.18.44.91  ashguard-order-scanner
```

> **Note:** Absolute timestamps and version IDs shown here are from this run and will not match another instance. Provisioning happens at a different wall-clock time on every launch, and the gap between the recon window and the burst below also depends on how long that specific instance took to provision. What stays fixed across every instance are the source IPs, usernames, role names, bucket and object names, and event ordering.

A few things fall out of reading this table top to bottom. The last event from `10.41.53.22` is a `ListObjectsV2` call, and there are zero events from that address afterward. Whatever routine use that address represents simply stops, and a different address starts appearing shortly after.

`198.18.44.91` opens with an identity check, then spends several calls on nothing but listing buckets and objects, no reads and no writes. A `GetObject` eventually shows up and comes back `AccessDenied`, meaning this identity's own permissions do not include direct read access to the object it is reaching for. An `AssumeRole` attempt appears too, and it also comes back `AccessDenied`, meaning whatever role this identity is trying to pivot into, it is not authorized to assume that one either. Read denied and pivot denied, back to back, sitting in the middle of otherwise successful listing calls.

Then there is a clean break in the pattern: a few events pass with wide, uneven gaps between them (minutes at a time), and then a few more events land back to back. That second cluster repeats the same opening moves, identity check, bucket list, object list, the same `GetObject` denied again, the same `AssumeRole` denied again, but this time it does not stop there. A second `AssumeRole` call appears, and this one succeeds. Immediately after, the identity performing calls switches from `seal-copyist-contractor` to `ashguard-order-scanner`, and that new identity checks its own caller identity, lists the object's version history, then issues `DeleteObject` followed by `PutObject` against the exact key already identified above.

That is the whole story CloudTrail tells on its own, without needing to know anything about who these names represent: one long-lived credential probes the environment, gets turned away twice, comes back later, gets turned away the same two ways again, then finds a role it is actually authorized to assume, and the destructive calls run under that assumed identity rather than the original one. 

# Solution

## Reconstructing the attack chain

The mixed timeline above is enough to see the shape of what happened. Isolating just the attacker IP and looking at elapsed time relative to its first call makes the two-phase structure explicit, and surfaces one more detail that has not come up yet: what the successful `AssumeRole` call actually requested.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.sourceIPAddress == "198.18.44.91")] |
  sort_by(.eventTime)[] |
  [.eventTime, .eventName,
   (.userIdentity.userName // (.userIdentity.sessionContext.sessionIssuer.userName // "?")),
   (.errorCode // "ok")] | join("  ")' events.json
```

```
T+0h00m  GetCallerIdentity   seal-copyist-contractor  ok
T+0h13m  ListBuckets         seal-copyist-contractor  ok
T+0h25m  ListObjectsV2       seal-copyist-contractor  ok
T+0h40m  GetObject           seal-copyist-contractor  AccessDenied
T+1h01m  ListObjectsV2       seal-copyist-contractor  ok
T+1h18m  ListObjectsV2       seal-copyist-contractor  ok
T+1h35m  AssumeRole          seal-copyist-contractor  AccessDenied
T+1h54m  ListBuckets         seal-copyist-contractor  ok
T+2h12m  ListObjectsV2       seal-copyist-contractor  ok
T+2h22m  ListObjectsV2       seal-copyist-contractor  ok
T+2h41m  ListObjectsV2       seal-copyist-contractor  ok
T+8h47m  GetCallerIdentity   seal-copyist-contractor  ok
T+8h47m  ListAllMyBuckets    seal-copyist-contractor  ok
T+8h47m  ListObjectsV2       seal-copyist-contractor  ok
T+8h47m  GetObject           seal-copyist-contractor  AccessDenied
T+8h47m  AssumeRole          seal-copyist-contractor  AccessDenied
T+8h47m  AssumeRole          seal-copyist-contractor  ok
T+8h47m  GetCallerIdentity   ashguard-order-scanner   ok
T+8h47m  ListBucketVersions  ashguard-order-scanner   ok
T+8h47m  DeleteObject        ashguard-order-scanner   ok
T+8h47m  PutObject           ashguard-order-scanner   ok
```

> **Offsets are instance-specific.** `T+0h00m` is this instance's first attacker event, and every other row shows elapsed time since then. Only the sequence, event names, identities, and the twelve graded field values are guaranteed to repeat. How much real time separates the recon window from the burst depends on how long provisioning took to run on this particular instance.

Two `AssumeRole` calls sit right next to each other in the burst, one denied and one successful, both fired within the same millisecond as the rest of the burst. Reading `requestParameters` on the successful one shows both the role it targeted and the session name it asked for:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventName == "AssumeRole" and (.errorCode // "") == "")] |
  sort_by(.eventTime) | first | {roleArn: .requestParameters.roleArn, roleSessionName: .requestParameters.roleSessionName}' events.json

{
  "roleArn": "arn:aws:iam::638291047582:role/ashguard-order-scanner",
  "roleSessionName": "coalition-gate-clerk"
}
```

`roleSessionName` is not a random string. It is exactly the IAM username of the internal address's identity, the one whose `ListObjectsV2` call was the last thing logged from `10.41.53.22` before any of this started. A role session name is attacker-controlled and shows up verbatim in every subsequent event's `userIdentity.arn` for that session (`assumed-role/ashguard-order-scanner/coalition-gate-clerk`), which means anyone skimming per-resource logs for that role would see a session that looks, at a glance, like it belongs to the regular clerk account rather than to whoever actually holds the `seal-copyist-contractor` access key. Combined with the earlier observation that the destructive calls run under `ashguard-order-scanner`, not under the long-lived contractor identity directly, the picture is now complete: a long-lived IAM credential that only has direct S3 read denied, pivoting into a role it is authorized for, then labeling that session to point suspicion at a completely different account.

## Answering the questions

### [1/12] What was the last CloudTrail API action performed from the internal gatehouse IP immediately before the attacker session began?

The internal address's own activity was already isolated earlier while building the combined timeline. Re-running that filter on its own and taking the last row by `eventTime` gives the exact action logged right before the address goes quiet:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.sourceIPAddress == "10.41.53.22")] |
  sort_by(.eventTime) | last | .eventName' events.json

ListObjectsV2
```

- Answer: `ListObjectsV2`

### [2/12] What was the first CloudTrail API action called from the attacker IP?

Same idea, opposite end: filter to the attacker address and take the first row instead of the last. Whatever this identity did to open its session is the answer:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.sourceIPAddress == "198.18.44.91")] |
  sort_by(.eventTime) | first | .eventName' events.json

GetCallerIdentity
```

An identity check as the opening move makes sense for a credential nobody has used from this address before. It confirms who the key belongs to before doing anything else with it.

- Answer: `GetCallerIdentity`

### [3/12] Which S3 API action did the attacker attempt that was explicitly denied before assuming a role?

The read-up above already spotted a `GetObject` sitting between two successful listing calls, with an `errorCode` attached. Filtering specifically for attacker events on `s3.amazonaws.com` with an `errorCode` set, then taking the earliest match, isolates that exact call:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventSource == "s3.amazonaws.com" and .errorCode != null)] |
  sort_by(.eventTime) | first | .eventName' events.json

GetObject
```

- Answer: `GetObject`

### [4/12] What is the full S3 path of the object that was tampered with? (format s3://bucket/key)

This one was answered before CloudTrail even entered the picture. `east-gate-order.json` stood out from the rest of the custody prefix by size and by having version history where its neighbors had none, and `list-object-versions` confirmed both the delete marker and the two real versions live under the same key:

```bash
$ aws s3 ls s3://ashguard-order-custody/custody/

2026-07-14 14:10:13        139 autumn-order.json
2026-07-14 14:10:15        436 east-gate-order.json
2026-07-14 14:10:13        139 spring-order.json
2026-07-14 14:10:13        139 summer-order.json
2026-07-14 14:10:13        137 void-order.json
2026-07-14 14:10:13        145 winter-order-draft.json

$ aws s3api list-object-versions --bucket ashguard-order-custody --prefix custody/east-gate-order.json \
  | jq '.DeleteMarkers[0].Key, .Versions[0].Key'

"custody/east-gate-order.json"
"custody/east-gate-order.json"
```

- Answer: `s3://ashguard-order-custody/custody/east-gate-order.json`

### [5/12] Which IAM role was assumed for the destructive session? (ARN format)

Only one attacker `AssumeRole` call in the whole dump comes back without an `errorCode`. Filtering to attacker `AssumeRole` events with no error and reading `requestParameters.roleArn` off it names the exact role whose temporary credentials went on to touch the object:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventName == "AssumeRole" and (.errorCode // "") == "")] |
  sort_by(.eventTime) | first | .requestParameters.roleArn' events.json

arn:aws:iam::638291047582:role/ashguard-order-scanner
```

- Answer: `arn:aws:iam::638291047582:role/ashguard-order-scanner`

### [6/12] What was the full STS principal ARN on the DeleteObject call?

`DeleteObject` from the attacker address only occurs once. Reading `userIdentity.arn` off that record is stronger than checking `userIdentity.type` alone: it names the role that was assumed and the session label attached to it, which is how the forged clerk framing shows up in the audit trail.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventName == "DeleteObject")] |
  first | .userIdentity.arn' events.json

arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk
```

The ARN format is `arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION`. Together they prove the delete ran under temporary role credentials labeled to resemble the internal clerk, not under a normal IAM user.

- Answer: `arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk`

### [7/12] From which IP address were the AssumeRole and destructive S3 calls performed?

Reading `sourceIPAddress` off the same successful `AssumeRole` record used for Q5 gives the address the whole destructive chain runs from, since every event in that burst (the role assumption itself, and everything logged under the resulting session) carries the same source address:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventName == "AssumeRole" and (.errorCode // "") == "")] |
  sort_by(.eventTime) | first | .sourceIPAddress' events.json

198.18.44.91
```

- Answer: `198.18.44.91`

### [8/12] Which IAM username owns the long-lived credentials used to call AssumeRole?

`AssumeRole` itself has to be called by something with actual, non-temporary IAM credentials, so the identity calling it (as opposed to the identity it produces) is recorded in `userIdentity.userName` on that same event:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventName == "AssumeRole" and (.errorCode // "") == "")] |
  sort_by(.eventTime) | first | .userIdentity.userName' events.json

seal-copyist-contractor
```

This is the access key doing all the recon, the denied reads, and the role pivot. It is a different name from the internal address's clerk identity, and different again from the role session name that shows up once the pivot succeeds.

- Answer: `seal-copyist-contractor`

### [9/12] Which IAM role name did the attacker fail to assume before the successful AssumeRole? (role name only, not ARN)

Two `AssumeRole` calls from the attacker carry an `errorCode`, one during the earlier recon window and one repeated inside the burst right before the successful call. Taking the earliest of the two and reading its `roleArn` shows what role was targeted and denied:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventName == "AssumeRole" and .errorCode != null)] |
  sort_by(.eventTime) | first | .requestParameters.roleArn' events.json | awk -F/ '{print $NF}'

ashguard-order-auditor
```

Notably, this is a different role from the one the successful call targets. The attacker's credential is not authorized to assume this one at all, denied both times it tries, but it is authorized to assume the scanner role.

- Answer: `ashguard-order-auditor`

### [10/12] What roleSessionName was used on the successful AssumeRole into the scanner role?

`RoleSessionName` is a caller-supplied parameter on `AssumeRole`, not something IAM assigns, so whatever value shows up here was chosen deliberately by whoever made the call:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventName == "AssumeRole" and (.errorCode // "") == "")] |
  sort_by(.eventTime) | first | .requestParameters.roleSessionName' events.json

coalition-gate-clerk
```

That string is the exact IAM username seen operating from the internal address throughout the earlier 500+ event window, the one whose access stopped right before the attacker's first event. Choosing that specific string as the session name means every log entry for the resulting assumed-role session shows an identity ARN that reads as if it belongs to the internal clerk account, even though the STS principal ARN graded in Q6 already proves the delete ran under `ashguard-order-scanner` with that forged session label.

- Answer: `coalition-gate-clerk`

### [11/12] What errorCode did CloudTrail record on the denied GetObject probe before role assumption?

Reading `errorCode` off the same `GetObject` record identified in Q3 gives the specific IAM response the attacker's credential received on that direct read attempt:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventName == "GetObject" and .errorCode != null)] |
  sort_by(.eventTime) | first | .errorCode' events.json

AccessDenied
```

- Answer: `AccessDenied`

### [12/12] Which S3 API action name marks the forged ledger upload after DeleteObject?

The last question closes the loop opened by the S3 version history at the start of this investigation. Filtering to successful (no `errorCode`) attacker calls on `s3.amazonaws.com` and taking the last one by `eventTime` gives the final S3 action in the whole chain, the one that actually wrote the forged body back to the key `DeleteObject` had just cleared:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "198.18.44.91" and .eventSource == "s3.amazonaws.com" and (.errorCode // "") == "")] |
  sort_by(.eventTime) | last | .eventName' events.json

PutObject
```

That single event ties everything together: the object identified in Q4, deleted by the assumed-role session identified in Q5 and Q6, from the address identified in Q7, using the session name spoofed in Q10, ends with this `PutObject` writing the version that `aws s3api get-object` returned at the very start of the investigation.

- Answer: `PutObject`
