![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Wrong Stamp</font>

25<sup>th</sup> June 2026

Prepared By: `kangwijen`

Challenge Author(s): `kangwijen`

Difficulty: <font color='green'>Very Easy</font>

<br><br>

# Synopsis

Wrong Stamp is a Very Easy Cloud Forensics challenge that demonstrates CloudTrail log analysis through distinguishing routine credential reuse from attacker activity by source IP and isolating the StopLogging event that disabled the trail to reconstruct how a compromised IAM credential was used to silence audit logging.

## Description

Elric Ashspar finds a seizure stamp in a dead clerk's bag near Stonepass. Vaultrune uses copies of that stamp to take supplies from Sythra's border guards, leaving a road Stormbound needs open without them. The stamp looks old, but Elric spots fresh tool marks on it. He must find the flaw, prove the stamp is fake, and give the guards a quick way to reject future copies.

## Skills Required

- AWS CLI basics
- CloudTrail lookup-events
- Reading identity and source IP fields in audit records

## Skills Learned

- Isolating the event that disabled the audit trail
- Filtering high-volume routine shift history to isolate a single real timeline
- Spotting foreign source IP traffic among routine internal activity
- Reconstructing attacker probe and denied escalation before trail logging stopped

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

The briefing hands out a single identity with no context on what happened before the investigator logged in. Confirm what that identity is before touching any logs:

```bash
$ aws sts get-caller-identity

{
    "UserId": "AIDAFS72ZCOMFDXV2QIS",
    "Account": "491827305948",
    "Arn": "arn:aws:iam::491827305948:user/stonepass-investigator"
}
```

The `UserId` value is randomized per instance, everything else in this challenge (account ID, IAM usernames, IP addresses, trail and bucket names) is fixed and identical across instances.

CloudTrail is the only data source exposed to the investigator role, so the entire investigation runs through `lookup-events`. Pull the full event history first and look at the raw count before filtering anything, so the scope of the problem is known up front:

```bash
$ aws cloudtrail lookup-events --output json > events.json

$ jq '.Events | length' events.json

267
```

A few hundred events is too many to read line by line. Start with a source-IP breakdown so the populations in the dump are visible before any chronological filter:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | .sourceIPAddress] |
  group_by(.) | map({ip: .[0], count: length})' events.json

[
  { "ip": "10.30.41.118", "count": 253 },
  { "ip": "127.0.0.1",    "count": 8 },
  { "ip": "192.0.2.55",   "count": 6 }
]
```

Three distinct source addresses. `127.0.0.1` is loopback traffic from provision and health checks landing in the same trail, not a client of interest. That leaves two real populations: `10.30.41.118` with hundreds of events spanning earlier shifts, and `192.0.2.55` with only six events. The large population is steady enough to read as routine activity from a fixed internal address. The six-event population is small, from an address outside that range, and worth isolating next.

> **Note:** Timestamps and absolute event counts are unique to this instance. Earlier shift history volume varies between instances, but the shape (event names in the live attack chain, ordering, source IPs, user agents, and error codes) is identical on every instance.

The internal block is long enough that printing every row is not useful. Take the last few events from `10.30.41.118` sorted by `eventTime` to find where that population ends:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.sourceIPAddress == "10.30.41.118")] |
  sort_by(.eventTime) | .[-5:][] |
  [.eventTime, .eventName, (.userAgent | split(" ")[0])] | join("  ")' events.json
```

```
2026-07-15T17:54:54.879Z  ListUsers           Boto3/1.34.0
2026-07-15T17:55:01.911Z  GetCallerIdentity   Boto3/1.34.0
2026-07-15T17:55:03.017Z  ListUsers           Boto3/1.34.0
2026-07-15T17:55:04.023Z  GetUser             Boto3/1.34.0
2026-07-15T17:55:05.231Z  ListAccessKeys      Boto3/1.34.0
```

The end of the internal block is routine monitoring: IAM and identity checks, nothing destructive, nothing denied, and every call signed with `Boto3/1.34.0`. Isolate the other source IP next and read those six calls in order:

## Reconstructing the attack chain

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.sourceIPAddress == "192.0.2.55")] |
  sort_by(.eventTime)[] |
  [.eventTime, .eventName, (.errorCode // "ok"), (.userAgent | split(" ")[0])] | join("  ")' events.json

2026-07-15T17:55:26.196Z  GetTrailStatus  ok                     Boto3/1.29.7
2026-07-15T17:55:28.444Z  DeleteTrail     AccessDeniedException  Boto3/1.29.7
2026-07-15T17:55:30.339Z  ListBucket      ok                     Boto3/1.29.7
2026-07-15T17:55:32.346Z  ListObjectsV2   ok                     Boto3/1.29.7
2026-07-15T17:55:34.154Z  GetObject       NoSuchKey              Boto3/1.29.7
2026-07-15T17:55:35.711Z  StopLogging     ok                     Boto3/1.29.7
```

Two things stand out against the internal block already isolated above:

1. There is a hard break at `192.0.2.55`. The internal population ends on `ListAccessKeys`, then six events appear from a different address with no return to `10.30.41.118`.
2. The user agent changes at the exact same break point. `10.30.41.118` only ever uses `Boto3/1.34.0`. `192.0.2.55` only ever uses `Boto3/1.29.7`, an older SDK build. Two different source addresses and two different client builds lining up on the same boundary is a strong signal that these are two different machines, not one client roaming across networks.

Reading the six-call chain in order tells a coherent story about what the credential was used for once it left its normal source:

- `GetTrailStatus` first. A read-only check of whether the trail is even active.
- `DeleteTrail` next, and it fails with `AccessDeniedException`. The credential is allowed to call CloudTrail management APIs but the IAM policy attached to it explicitly blocks the destructive delete operation.
- Two S3 calls against the trail's log bucket (`ListBucket`, `ListObjectsV2`), then a `GetObject` that returns `NoSuchKey`. Listing the bucket before trying a specific key is how someone checks what evidence already exists before deciding whether it is worth erasing anything. The object lookup fails, so no historical log content was actually read.
- `StopLogging` last, and it succeeds. Denied a full delete, the credential falls back to the softer action the policy does allow: turning off future logging rather than destroying past logging. From this point forward nothing more from this credential shows up in the trail, because the trail itself has stopped recording.

The order matters here as much as the individual calls. The denied `DeleteTrail` sits between the initial probe and the S3 enumeration, which is what shows the policy boundary actively redirected behavior toward `StopLogging` rather than that being the first action attempted.

Pulling `userIdentity.userName` for both blocks (shown in the Solution section below) confirms the same IAM username signs every event on both sides of the break. Same credential, two different network origins and two different client builds. That is consistent with a long-lived access key being used from its normal operating location and then reused from somewhere else entirely, rather than a second account being involved.

# Solution

The attack chain is reconstructed. What remains is pulling the specific field values the eight questions ask for out of the two event clusters already isolated above.

### [1/8] What was the last CloudTrail API action performed by the compromised user from the internal IP immediately before the attacker session began?

The internal block ends where the source address changes. Filter to `10.30.41.118`, sort by `eventTime`, and take the last entry, that is the final call made before the credential started being used from somewhere else.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.sourceIPAddress == "10.30.41.118")] |
  sort_by(.eventTime) | last | .eventName' events.json

ListAccessKeys
```

* Answer: `ListAccessKeys`

### [2/8] What was the first CloudTrail API action called from the attacker IP?

Mirror the same query for `192.0.2.55` and take the first entry instead of the last. This is the opening move once the credential shows up on the new address.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.sourceIPAddress == "192.0.2.55")] |
  sort_by(.eventTime) | first | .eventName' events.json

GetTrailStatus
```

* Answer: `GetTrailStatus`

### [3/8] Which API action did the attacker attempt that was explicitly denied before the trail was stopped?

Filter the same `192.0.2.55` events to only the ones carrying a non-null `errorCode`, sort by time, and take the earliest. Out of six calls only one failed, and it failed early, right after the initial status check.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "192.0.2.55" and .errorCode != null)] |
  sort_by(.eventTime) | first | [.eventName, .errorCode] | join("  ")' events.json

DeleteTrail  AccessDeniedException
```

* Answer: `DeleteTrail`

### [4/8] Which S3 bucket did the attacker enumerate before stopping the trail?

After the denied delete, two of the remaining `192.0.2.55` calls have `eventSource: s3.amazonaws.com`. Filter to those, sort by time, and read `requestParameters.bucketName` off the earliest one. That is the bucket being checked before the trail goes dark.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress == "192.0.2.55" and .eventSource == "s3.amazonaws.com")] |
  sort_by(.eventTime) | first | .requestParameters.bucketName' events.json

stonepass-audit-trail-logs
```

* Answer: `stonepass-audit-trail-logs`

### [5/8] What is the name of the CloudTrail trail that was stopped?

The last event in the attacker chain is `StopLogging`. Filter `events.json` down to that record and read `requestParameters.name`, a request parameter rather than a response field, since `StopLogging` takes the trail name as input:

```bash
$ jq -r '.Events[] | (.CloudTrailEvent | fromjson) |
  select(.eventName == "StopLogging" and .sourceIPAddress == "192.0.2.55") |
  .requestParameters.name' events.json

stonepass-audit-trail
```

* Answer: `stonepass-audit-trail`

### [6/8] Which IAM username's credentials were used to execute the trail disable?

Same filter, reading `userIdentity.userName` instead. It is the same username seen throughout the internal `10.30.41.118` block, confirming this is not a second account, it is one IAM user's long-lived access key being used from two different places.

```bash
$ jq -r '.Events[] | (.CloudTrailEvent | fromjson) |
  select(.eventName == "StopLogging" and .sourceIPAddress == "192.0.2.55") |
  .userIdentity.userName' events.json

stonepass-warden
```

* Answer: `stonepass-warden`

### [7/8] From which IP address was the trail disabled?

The filter already pins `sourceIPAddress` to `192.0.2.55`, the address that never appears anywhere in the internal block and the clearest single indicator that the credential was reused from outside its normal operating context.

```bash
$ jq -r '.Events[] | (.CloudTrailEvent | fromjson) |
  select(.eventName == "StopLogging" and .sourceIPAddress == "192.0.2.55") |
  .sourceIPAddress' events.json

192.0.2.55
```

* Answer: `192.0.2.55`

### [8/8] Which API action was used to disable the audit trail?

`eventName` on the same record. This is the action the IAM policy actually permitted once the harder `DeleteTrail` call was rejected, disabling future logging rather than removing the trail's configuration outright.

```bash
$ jq -r '.Events[] | (.CloudTrailEvent | fromjson) |
  select(.eventName == "StopLogging" and .sourceIPAddress == "192.0.2.55") |
  .eventName' events.json

StopLogging
```

* Answer: `StopLogging`
