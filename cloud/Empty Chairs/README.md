![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Empty Chairs</font>

30<sup>th</sup> June 2026

Prepared By: `kangwijen`

Challenge Author(s): `kangwijen`

Difficulty: <font color='orange'>Medium</font>

<br><br>

# Synopsis

Empty Chairs is a Medium Cloud Forensics challenge that demonstrates multi-service CloudTrail reconstruction across Secrets Manager, STS, SQS, KMS, SNS, and DynamoDB through failed-role-assumption tracing and S3 server-access-log correlation to isolate one attacker session, from initial secret probing to a queue-purging evidence-destruction call, inside thousands of unrelated audit events.

## Description

Elowen Ashglass reaches one of Sythra's road watch posts after its morning signal fails. The fire pit is warm, spears lean by the door, and the scouts are gone. Red ash under the doorways and paired tracks on the road show that the Quiet Helpers took them alive. Without that post, Stormbound loses sight of the road ahead. Elowen must follow the tracks, find the missing scouts, and learn where the Helpers are taking them before frost covers the trail.

## Skills Required

- AWS CLI basics
- CloudTrail `lookup-events`
- S3 server access log listing and parsing
- Reading identity, IP, and request fields in audit records

## Skills Learned

- Separating multi-staff internal shift traffic from roaming contractor recon and the live diversion chain
- Anchoring on a single destructive terminal event to isolate the attacker IP from unrelated traffic
- Tracing a multi-service post-pivot chain across eight AWS APIs in a single session
- Cross-referencing CloudTrail object reads with S3 server access log operation names

# Enumeration

## Environment setup

The instance card exposes an AWS-compatible endpoint and a set of investigator credentials. Export them and confirm identity before touching CloudTrail:

```bash
$ export AWS_ENDPOINT_URL=http://<CHALLENGE_IP>:<AWS_PORT>
$ export AWS_DEFAULT_REGION=us-east-1
$ export AWS_ACCESS_KEY_ID=<from briefing>
$ export AWS_SECRET_ACCESS_KEY=<from briefing>
$ unset AWS_SESSION_TOKEN
```

```bash
$ aws sts get-caller-identity

{
    "UserId": "AIDAY5NN1XSCXSPUSIG9",
    "Account": "719384620571",
    "Arn": "arn:aws:iam::719384620571:user/eastreach-investigator"
}
```

The account only grants this identity read access to CloudTrail, one S3 log bucket, and nothing else. That scoping rules out live inspection of the resources themselves: everything from here on has to come from audit records.

## Finding a starting point in three thousand events

A cold pull of every recorded event is the obvious first move:

```bash
$ aws cloudtrail lookup-events --output json > events.json
$ jq '.Events | length' events.json

3381
```

Over three thousand records with no filter applied is not something a human can read line by line. A condensed view sorted by time makes the shape of the traffic visible without drowning in it:

```bash
$ jq -r '.Events[] | (.CloudTrailEvent | fromjson) | select(.sourceIPAddress != "127.0.0.1") |
  [.eventTime, .eventName, (.sourceIPAddress // "?"),
   (.userIdentity.userName // (.userIdentity.sessionContext.sessionIssuer.userName // "?")),
   (.errorCode // "")] | join("  ")' events.json | sort | head -8

2026-06-30T13:33:28.912Z  ListObjectsV2        10.23.87.52    eastreach-dispatch-lead
2026-06-30T13:33:28.998Z  GetSecretValue       10.23.88.14    eastreach-supply-clerk   AccessDeniedException
2026-06-30T13:33:29.104Z  ListSecrets          198.51.100.22  eastreach-contractor
2026-06-30T13:33:29.211Z  GetQueueAttributes   10.23.87.41    eastreach-dispatcher
2026-06-30T13:33:29.340Z  GetSecretValue       198.51.100.22  eastreach-contractor     AccessDeniedException
2026-06-30T13:33:29.402Z  ListSecrets          10.23.88.14    eastreach-supply-clerk
2026-06-30T13:33:29.501Z  GetCallerIdentity    203.0.113.41   eastreach-contractor
2026-06-30T13:33:29.512Z  ListRoles            10.23.87.55    eastreach-dispatch-lead
2026-06-30T13:33:29.512Z  ListRoles            203.0.113.41   eastreach-contractor    AccessDenied

```

Two patterns stand out immediately. First, a cluster of `10.23.x` source IPs generates the bulk of the volume, all under a handful of usernames: this reads like normal internal shift traffic. Second, `eastreach-contractor` also shows up from IPs outside that range, and its calls there are almost all denied. That single username spanning both an internal-looking pattern and an external, mostly-failing pattern is why scrolling through the raw dump will not get anywhere: distinguishing the same name behaving differently across networks requires filtering, not reading.

Counting by source IP confirms the split instead of guessing at it:

```bash
$ jq -r '.Events[] | (.CloudTrailEvent | fromjson) | .sourceIPAddress' events.json | sort | uniq -c | sort -rn

    548 10.23.87.41
    487 10.23.87.52
    257 10.23.87.55
    241 10.23.88.14
    205 10.23.87.43
    201 10.23.87.48
    184 10.23.86.9
    160 10.23.86.12
    141 10.23.88.20
    109 10.23.87.59
     83 10.23.86.15
     41 10.23.88.22
    273 203.0.113.41
    147 198.51.100.22
     50 203.0.113.17
     19 203.0.113.88
```

Twelve `10.23.x` addresses account for the majority of the log, and four more sit outside that range. Grouping every event by `userIdentity.userName` instead of by raw IP, excluding the investigator's own loopback (`127.0.0.1`) and container-network (`172.17.0.1`) addresses, shows what the full population actually breaks down into:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) |
  select(.sourceIPAddress != "127.0.0.1" and .sourceIPAddress != "172.17.0.1")] |
  group_by(.userIdentity.userName) |
  map({user: .[0].userIdentity.userName, ips: (map(.sourceIPAddress) | unique), count: length})' events.json

[
  {
    "user": null,
    "ips": ["203.0.113.88", "s3.amazonaws.com"],
    "count": 13
  },
  {
    "user": "eastreach-contractor",
    "ips": ["198.51.100.22", "203.0.113.17", "203.0.113.41", "203.0.113.88"],
    "count": 478
  },
  {
    "user": "eastreach-dispatch-lead",
    "ips": ["10.23.87.52", "10.23.87.55", "10.23.87.59"],
    "count": 881
  },
  {
    "user": "eastreach-dispatcher",
    "ips": ["10.23.87.41", "10.23.87.43", "10.23.87.48"],
    "count": 864
  },
  {
    "user": "eastreach-relay-watch",
    "ips": ["10.23.86.9", "10.23.86.12", "10.23.86.15"],
    "count": 441
  },
  {
    "user": "eastreach-supply-clerk",
    "ips": ["10.23.88.14", "10.23.88.20", "10.23.88.22"],
    "count": 471
  }
]
```

Six groups come back. Four are internal staff accounts, `eastreach-dispatcher`, `eastreach-dispatch-lead`, `eastreach-supply-clerk`, `eastreach-relay-watch`, each rotating across its own small, fixed pool of three `10.23.x` IPs, which is exactly what a multi-person shift roster running secret lookups, queue attribute checks, and manifest reads over several days would look like. That volume matches routine staff activity, not a lead.

The fifth, `eastreach-contractor`, is the only named identity attached to all four external addresses (`203.0.113.41`, `198.51.100.22`, `203.0.113.17`, `203.0.113.88`). That narrows the field but does not finish the job: a contractor could plausibly work from more than one external address, and three of the four IPs above generate hundreds of events each without doing anything obviously final. Picking the wrong one wastes the rest of the investigation on an address that never does anything destructive.

The sixth group carries no `userIdentity.userName` at all: thirteen calls, spread across `203.0.113.88` and `s3.amazonaws.com`. CloudTrail leaves that field empty for calls made under a temporary role session rather than a long-lived IAM user, so a missing username here is itself a signal, something in this account is already operating as an assumed role, from the same address the contractor also uses. That thread gets picked up once the attacker session is reconstructed below.

Picking among four candidate IPs by volume alone is unreliable, so the better anchor is the single rarest, most consequential action in the entire dataset: a call that destroys evidence. If exactly one IP owns that call, everything upstream of it belongs to the same attacker session by definition.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.eventName == "PurgeQueue")] | length' events.json

1

$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.eventName == "PurgeQueue")] | first | .sourceIPAddress' events.json

203.0.113.88
```

Only one `PurgeQueue` call exists in the whole account, and it comes from `203.0.113.88`. That is the live attacker IP. Checking the other three external addresses confirms they never reach that call at all:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.41" or .sourceIPAddress == "198.51.100.22" or .sourceIPAddress == "203.0.113.17")] | length' events.json

470

$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select((.sourceIPAddress == "203.0.113.41" or .sourceIPAddress == "198.51.100.22" or .sourceIPAddress == "203.0.113.17")
           and .eventName == "PurgeQueue")] | length' events.json

0
```

Four hundred seventy events across those three roaming addresses, entirely recon (`ListSecrets`, `ListBuckets`, `ListRoles`, and similar calls, almost all denied), and none of them ever complete anything destructive. That is the same contractor's credential scanning the account from several vantage points without ever completing an attack. `203.0.113.88` is the only one that actually finishes an attack.

## Reconstructing the attacker's session

With one IP identified, pulling every event attributed to it and sorting by time turns three thousand unrelated records into a single readable session:

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson) | select(.sourceIPAddress == "203.0.113.88")] |
  sort_by(.eventTime)[] |
  [.eventTime, .eventName,
   (.userIdentity.sessionContext.sessionIssuer.userName // .userIdentity.userName // "?"),
   (.errorCode // "ok")] | join("  ")' events.json

2026-07-14T07:33:29.943Z  GetCallerIdentity   eastreach-contractor      ok
2026-07-14T07:33:30.530Z  ListSecrets         eastreach-contractor      ok
2026-07-14T07:33:31.320Z  GetSecretValue      eastreach-contractor      AccessDeniedException
2026-07-14T07:33:31.325Z  GetSecretValue      eastreach-contractor      AccessDeniedException
2026-07-14T07:33:31.904Z  GetSecretValue      eastreach-contractor      AccessDeniedException
2026-07-14T07:33:32.651Z  GetSecretValue      eastreach-contractor      ok
2026-07-14T07:33:33.449Z  AssumeRole          eastreach-contractor      AccessDenied
2026-07-14T07:33:34.040Z  AssumeRole          eastreach-contractor      ok
2026-07-14T07:33:34.923Z  GetCallerIdentity   eastreach-dispatch-role   ok
2026-07-14T07:33:35.441Z  GetQueueAttributes  eastreach-dispatch-role   AccessDeniedException
2026-07-14T07:33:36.229Z  ReceiveMessage      eastreach-dispatch-role   ok
2026-07-14T07:33:37.017Z  SendMessage         eastreach-dispatch-role   ok
2026-07-14T07:33:37.555Z  Decrypt             eastreach-dispatch-role   ok
2026-07-14T07:33:37.940Z  Publish             eastreach-dispatch-role   ok
2026-07-14T07:33:38.334Z  PutItem             eastreach-dispatch-role   ok
2026-07-14T07:33:38.952Z  ListObjectsV2       eastreach-dispatch-role   ok
2026-07-14T07:33:39.574Z  GetObject           eastreach-dispatch-role   ok
2026-07-14T07:33:41.581Z  GetTrailStatus      eastreach-dispatch-role   ok
2026-07-14T07:33:42.342Z  PurgeQueue          eastreach-dispatch-role   ok
```

> **Timestamps are per-instance.** The absolute times above came from one live run. Every other instance shifts the clock but keeps the same nineteen events in the same order, with the same IPs and usernames throughout.

Reading top to bottom: the session opens as an IAM user (`eastreach-contractor`), confirms its own identity, lists available secrets, and then hits three secrets it cannot read before finally reading one it can. That pattern (several denied reads followed by one success) means there is more than one candidate secret in the account, and the attacker's own IAM policy is drawing the line between them, not luck. The identity column then switches from `eastreach-contractor` to `eastreach-dispatch-role` in the middle of the two `AssumeRole` calls, which is the pivot point of the whole attack: everything before it runs as a long-lived IAM user, everything after runs as temporary role credentials.

After the pivot, the session probes a queue it cannot read the attributes of, then successfully drains a different queue, writes a message back into it, unwraps something with KMS, publishes to SNS, writes a DynamoDB item, reads an S3 object, checks CloudTrail's own trail status, and finally purges the queue it wrote to. That ordering (queue write, decrypt, publish, database write, only then a trail-status check, only then destruction) reads like a deliberate sequence: inject the fraudulent data first, propagate it through the downstream services that act on it, confirm whether anyone is watching, and only then erase the queue evidence.

## Cross-referencing the manifest exfiltration

CloudTrail's `GetObject` record proves an S3 API call happened and against which bucket and key, but the control-plane audit event does not carry the same operation vocabulary that S3 server access logs use, and one of the graded questions asks for that access-log operation field specifically. The briefing scopes investigator access to a separate log-delivery bucket, so the pivot is straightforward: list it, sync it locally, and grep for the exact object key on the attacker's IP.

```bash
$ aws s3 ls s3://eastreach-manifest-access-logs/eastreach-watchpost-manifests/

2026-07-14 14:33:28      97459 2026-06-30-01-33-28-2e9fad477901
2026-07-14 14:33:28      97359 2026-06-30-19-33-28-503ba3fd890a
2026-07-14 14:33:28      96728 2026-07-01-13-33-28-2e886bf6ac5e
...  (twenty log objects delivered on this instance, exact count and names vary)
2026-07-14 14:33:39        620 2026-07-14-07-33-39-ce411f797a6d4dab

$ mkdir -p /tmp/access-logs
$ aws s3 sync s3://eastreach-manifest-access-logs/eastreach-watchpost-manifests/ /tmp/access-logs/

$ grep signed-routing-bundle.json /tmp/access-logs/* | grep 203.0.113.88

/tmp/access-logs/2026-07-14-07-33-39-ce411f797a6d4dab:09778fa77b49a530a9c83b9bf3f58e799e765bc4647e7c2860ed73adb2882326 eastreach-watchpost-manifests [14/Jul/2026:07:33:39 +0000] 203.0.113.88 arn:aws:sts::719384620571:assumed-role/eastreach-dispatch-role/dispatch-runner BBC21BB2E7BC45A0 REST.GET.OBJECT signed-routing-bundle.json "GET /eastreach-watchpost-manifests/signed-routing-bundle.json HTTP/1.1" 200 - 621 621 1 0 "-" "Boto3/1.29.7 md/Botocore#1.29.7 ua/2.0 os/linux#5.15.0-107-generic md/arch#x86_64 lang/python#3.10.12 md/pyimpl#CPython cfg/retry-mode#standard Botocore/1.29.7" - f4ac44dcbf9f4f7fb26c922d80601681== SigV4 - AuthHeader 127.0.0.1:4566 - - - us-east-1
```

The record ties together everything already established: it fires two seconds after CloudTrail's `GetObject` for the same object, the caller ARN matches the assumed-role session from the pivot, and the source IP is the same live attacker address. The seventh field, `REST.GET.OBJECT`, is the operation name S3 access logs use for this read. CloudTrail's `eventName` and the S3 access log's operation field describe the same underlying call in two different vocabularies, and only the second one is what the graded question is asking for.

## Establishing the pre-attack boundary

One question falls outside the nineteen-event chain entirely: it asks for the last legitimate use of the pending queue before the hijack, which by definition has to come from the internal shift traffic, not from the attacker IP. Now that the target queue name is known from the live chain's `ReceiveMessage` call, the same query pattern used to separate internal from external traffic earlier answers it directly: filter every `10.23.x` `ReceiveMessage` against that queue, sort by time, and take the last one before the attack window opens.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress | startswith("10.23."))
  | select(.eventName == "ReceiveMessage")
  | select((.requestParameters.queueUrl // .requestParameters.QueueUrl // "") | contains("eastreach-scout-recall-pending"))] |
  sort_by(.eventTime) | last | [.eventTime, .sourceIPAddress] | join("  ")' events.json

2026-07-14T07:33:27.387Z  10.23.87.41
```

That drain happens 2.5 seconds before the attacker's first `GetCallerIdentity` call at `07:33:29.943Z`. That gap is the boundary between the legitimate shift and the live diversion: everything on `10.23.87.41` before it is routine queue polling, everything after belongs to the attack.

## What the reconstruction shows

1. Twelve internal `10.23.x` addresses generate roughly 2000-3000 shift events across four dispatch staff accounts, none of which ever touch `AssumeRole`, `Decrypt`, `Publish`, or `PurgeQueue`. This is routine activity, not signal.
2. `eastreach-contractor` operates from four external addresses. Three of them (`203.0.113.41`, `198.51.100.22`, `203.0.113.17`) generate hundreds of failed recon calls each and never complete a destructive action. The fourth (`203.0.113.88`) is the only one that reaches `PurgeQueue`, which makes it the reliable anchor for the entire investigation.
3. On that IP, the identity flips from `IAMUser` to `AssumedRole` at a single `AssumeRole` call, immediately preceded by a denied `AssumeRole` against a different role. The failed attempt and the successful one share the same secret-reading context, which is what ties the failed attempt to the same session rather than an unrelated error.
4. Once pivoted, the session runs a fixed sequence across six AWS services in under nine seconds: read the pending queue, inject a message, decrypt routing material, publish an alert, write a database row, then read and exfiltrate a manifest object, check the CloudTrail trail's status, and purge the queue.
5. CloudTrail's `GetObject` and the S3 access log's `REST.GET.OBJECT` describe the same exfiltration event from two different logging layers, both keyed to the same object, timestamp window, and source IP.

# Solution

## Answering the questions

### [1/18] What is the source IP on the last ReceiveMessage before a non-internal IP performs ReceiveMessage on that same queue?

The attack chain shows the target queue is `eastreach-scout-recall-pending`. Filtering every internal (`10.23.x`) `ReceiveMessage` against that queue and taking the latest one by timestamp gives the final legitimate drain before the diversion begins.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress | startswith("10.23."))
  | select(.eventName == "ReceiveMessage")
  | select((.requestParameters.queueUrl // .requestParameters.QueueUrl // "") | contains("eastreach-scout-recall-pending"))] |
  sort_by(.eventTime) | last | .sourceIPAddress' events.json

10.23.87.41
```

- Answer: `10.23.87.41`

### [2/18] From which external IP did the contractor perform the full scout diversion attack (including PurgeQueue)?

`PurgeQueue` occurs exactly once across the whole account, and it is the most reliable anchor available: reading its `sourceIPAddress` identifies the live attacker without having to first decide which of the four contractor IPs matters.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.eventName == "PurgeQueue")] |
  first | .sourceIPAddress' events.json

203.0.113.88
```

- Answer: `203.0.113.88`

### [3/18] On the live diversion source IP, which secret name returned AccessDenied on the first denied GetSecretValue call?

The reconstructed session shows three consecutive denied `GetSecretValue` calls before a successful one, meaning more than one secret is in play. Filtering to denied Secrets Manager reads on the attacker IP and taking the earliest by timestamp isolates which secret was probed first.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventSource == "secretsmanager.amazonaws.com"
           and .eventName == "GetSecretValue"
           and (.errorCode // "") != "")] |
  sort_by(.eventTime) | first | .requestParameters.secretId' events.json

eastreach/dispatch-signing-draft
```

- Answer: `eastreach/dispatch-signing-draft`

### [4/18] Which secret name was successfully read before the role assumption?

The same filter with the error-code condition inverted (no `errorCode` present) isolates the one `GetSecretValue` call that actually succeeded, which happens immediately before the first `AssumeRole` attempt.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventName == "GetSecretValue"
           and (.errorCode // "") == "")] |
  first | .requestParameters.secretId' events.json

eastreach/dispatch-signing
```

- Answer: `eastreach/dispatch-signing`

### [5/18] Which IAM role name did the attacker fail to assume before the successful pivot? (role name only, not ARN)

The reconstructed chain shows two `AssumeRole` calls back to back: a denied one immediately followed by a successful one. Reading the `roleArn` off the denied call and taking the segment after the final slash gives the role name the attacker tried and failed to reach first.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventName == "AssumeRole"
           and (.errorCode // "") != "")] |
  sort_by(.eventTime) | first | .requestParameters.roleArn' events.json | awk -F/ '{print $NF}'

eastreach-archive-reader
```

- Answer: `eastreach-archive-reader`

### [6/18] Which IAM role ARN was successfully assumed to control watchpost routing?

The `AssumeRole` call with no error code, one step after the failed one, is the actual pivot. Its `roleArn` is the role that carries the rest of the session's permissions.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventName == "AssumeRole"
           and (.errorCode // "") == "")] |
  first | .requestParameters.roleArn' events.json

arn:aws:iam::719384620571:role/eastreach-dispatch-role
```

- Answer: `arn:aws:iam::719384620571:role/eastreach-dispatch-role`

### [7/18] What roleSessionName was used on the successful AssumeRole?

The same event carries a `roleSessionName`, which becomes the session identifier that shows up later in the S3 access log's caller ARN, confirming the two logging layers describe the same actor.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventName == "AssumeRole"
           and (.errorCode // "") == "")] |
  first | .requestParameters.roleSessionName' events.json

dispatch-runner
```

- Answer: `dispatch-runner`

### [8/18] What IAM identity type does CloudTrail record for API calls made after the successful role pivot?

Every event after the pivot carries a `userIdentity.sessionContext.sessionIssuer.userName` of `eastreach-dispatch-role` instead of a direct `userName`, which is how CloudTrail marks temporary credentials. Reading `userIdentity.type` on any such event confirms the identity kind.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and (.userIdentity.sessionContext.sessionIssuer.userName // "") == "eastreach-dispatch-role")] |
  first | .userIdentity.type' events.json

AssumedRole
```

- Answer: `AssumedRole`

### [9/18] What is the SQS queue name targeted for the fraudulent scout recall order?

The first post-pivot `ReceiveMessage` on the attacker IP reads from the queue that later receives the forged order. Its `queueUrl` ends in the queue name.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventName == "ReceiveMessage")] |
  first | (.requestParameters.queueUrl // .requestParameters.QueueUrl // "")' events.json | awk -F/ '{print $NF}'

eastreach-scout-recall-pending
```

- Answer: `eastreach-scout-recall-pending`

### [10/18] What order_id value was injected in the fraudulent scout recall order?

The `SendMessage` call right after that `ReceiveMessage` writes a JSON-encoded body back into the same queue. Decoding `messageBody` and reading `order_id` gives the forged order's identifier.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventName == "SendMessage")] |
  first | (.requestParameters.messageBody // "{}") | fromjson | .order_id' events.json

ER-DIV-9941
```

- Answer: `ER-DIV-9941`

### [11/18] What route_override destination did the attacker set in the fraudulent order?

The same decoded body carries a `route_override` field, which is the destination the forged order is trying to redirect traffic to.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventName == "SendMessage")] |
  first | (.requestParameters.messageBody // "{}") | fromjson | .route_override' events.json

quietmarch-depot-11/bypass-C
```

- Answer: `quietmarch-depot-11/bypass-C`

### [12/18] What KMS keyId did the attacker use when decrypting the routing envelope after SendMessage?

Immediately after writing the forged message, the session calls KMS `Decrypt`, which is how a routing envelope gets unwrapped before the diversion can be acted on downstream. Its `keyId` identifies the key used.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventSource == "kms.amazonaws.com"
           and .eventName == "Decrypt")] |
  first | .requestParameters.keyId' events.json

arn:aws:kms:us-east-1:719384620571:alias/eastreach/watchpost-routing-key
```

- Answer: `arn:aws:kms:us-east-1:719384620571:alias/eastreach/watchpost-routing-key`

### [13/18] What SNS topic name received the diversion alert Publish call?

Right after the decrypt, the session publishes to SNS. Reading `topicArn` and taking the segment after the final colon gives the topic name that carried the diversion alert.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventSource == "sns.amazonaws.com"
           and .eventName == "Publish")] |
  first | .requestParameters.topicArn' events.json | awk -F: '{print $NF}'

eastreach-diversion-alerts
```

- Answer: `eastreach-diversion-alerts`

### [14/18] What DynamoDB table name received the forged ledger PutItem?

The `PutItem` call that follows the SNS publish is the point where the diversion gets written into a persistent ledger table, giving the forged order a durable record.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventSource == "dynamodb.amazonaws.com"
           and .eventName == "PutItem")] |
  first | .requestParameters.tableName' events.json

eastreach-watchpost-ledger
```

- Answer: `eastreach-watchpost-ledger`

### [15/18] What is the S3 access log operation field for the GetObject on signed-routing-bundle.json from the external IP?

CloudTrail's `GetObject` confirms an object read happened but does not carry the S3 access log's own operation vocabulary. Pulling the synced access logs and filtering for the object key on the attacker IP surfaces the matching delivery record directly.

```bash
$ grep signed-routing-bundle.json /tmp/access-logs/* | grep 203.0.113.88 | awk '{print $8}'

REST.GET.OBJECT
```

- Answer: `REST.GET.OBJECT`

### [16/18] What is the name of the CloudTrail trail the attacker verified before purging queue evidence?

Right before the destructive call, the session runs `GetTrailStatus`, which is the attacker checking whether the account's audit trail is actively recording before doing anything irreversible. Its `name` parameter identifies the trail that was checked.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventName == "GetTrailStatus")] |
  first | .requestParameters.name' events.json

eastreach-watchpost-trail
```

- Answer: `eastreach-watchpost-trail`

### [17/18] Which API action destroyed the queue evidence at the end of the attack chain?

Sorting every SQS event on the attacker IP by time and taking the last one gives the terminal action of the session: the same `PurgeQueue` call used earlier as the anchor for isolating this IP in the first place.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and .eventSource == "sqs.amazonaws.com")] |
  sort_by(.eventTime) | last | .eventName' events.json

PurgeQueue
```

- Answer: `PurgeQueue`

### [18/18] Which IAM user name owned the long-lived access key used to start the attack chain?

Before the pivot, every event on the attacker IP carries `userIdentity.type` of `IAMUser` rather than `AssumedRole`. Reading `userIdentity.userName` on the earliest such event identifies the long-lived identity that kicked off the whole session.

```bash
$ jq -r '[.Events[] | (.CloudTrailEvent | fromjson)
  | select(.sourceIPAddress == "203.0.113.88"
           and (.userIdentity.type // "") == "IAMUser")] |
  sort_by(.eventTime) | first | .userIdentity.userName' events.json

eastreach-contractor
```

- Answer: `eastreach-contractor`
