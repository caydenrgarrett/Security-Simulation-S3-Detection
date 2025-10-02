# Ransomware on S3: Simulation and Detection <br>

![image alt](https://docs.aws.amazon.com/images/security-ir/latest/userguide/images/aspects-of-incident-response.png)

## Project Overview
This project explores simulation and detection of ransomware activity targeting Amazon S3 buckets. The focus is on threat hunting, detection, and response using AWS-native tools and services. It involves simulating potential ransomware behaviors and analyzing how cloud monitoring services can help detect, investigate, and respond to such threats.

## Tools & Services Used
- **Amazon Athena**: Queried log data and identified suspicious activity.
- **AWS CloudTrail**: Investigated key events to detect anomalies and potential indicators of compromise.
- **Amazon CloudWatch**: Monitored metrics to detect abnormal data retrieval and deletion.
- **AWS Billing & Cost Usage Reports (CUR)**: Identified unusual billing spikes as potential ransomware indicators.
- **Amazon GuardDuty**: Reviewed findings related to S3 tampering and other malicious activity.

## Platform Used
- AWS Workshop: [AWS CIRT – Unauthorized IAM Credential Use](https://catalog.workshops.aws/aws-cirt-unauthorized-iam-credential-use)

## Skills Developed
- **Cloud threat detection and response** with AWS services.
- **Log analysis and query writing** with Amazon Athena.
- **Understanding of S3 ransomware risks** and detection methods.
- **Practical knowledge** of cloud-native monitoring and security tooling.
- **Hands-on experience** with incident response workflows in AWS.

## Prerequisites (one-time setup)
- Enable S3 server access logs or CloudTrail Data Events for S3 object-level operations; send to `s3://your-logs-bucket/...`.
- Enable CloudTrail Management Events for IAM/S3 config changes; send to the same or another bucket.
- Enable GuardDuty and (optionally) export findings to S3.
- Enable AWS Billing & Cost and Usage Reports (CUR) with Athena integration.
- Create an Athena workgroup/output location.

## Using the Athena Playbook: Step-by-step

### Step 1 — Create Athena database and tables

- Create database:
```sql
CREATE DATABASE IF NOT EXISTS secops;
```

- CloudTrail (management + data events) table:
```sql
CREATE EXTERNAL TABLE IF NOT EXISTS secops.cloudtrail_all (
  eventversion string,
  useridentity struct<
    type:string,
    principalid:string,
    arn:string,
    accountid:string,
    invokedby:string,
    accesskeyid:string,
    userName:string,
    sessioncontext: struct<
      attributes: struct<mfaauthenticated:string, creationdate:string>,
      sessionissuer: struct<type:string, principalId:string, arn:string, accountId:string, userName:string>
    >
  >,
  eventtime string,
  eventsource string,
  eventname string,
  awsregion string,
  sourceipaddress string,
  useragent string,
  errorcode string,
  errormessage string,
  requestparameters string,
  responseelements string,
  additionalEventData string,
  requestid string,
  eventid string,
  readonly string,
  resources array<struct<arn:string, accountid:string, type:string>>,
  eventtype string,
  apiversion string,
  recipientaccountid string,
  serviceeventdetails string,
  sharedeventid string,
  vpcendpointid string
)
PARTITIONED BY (`region` string, `year` string, `month` string, `day` string)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://your-logs-bucket/AWSLogs/your-account-id/CloudTrail/'
TBLPROPERTIES (
  'projection.enabled'='true',
  'projection.region.values'='us-east-1,us-east-2,us-west-1,us-west-2,eu-west-1,eu-west-2,eu-central-1,ap-south-1,ap-southeast-1,ap-southeast-2,ap-northeast-1,ap-northeast-2',
  'projection.year.range'='2022,2035',
  'projection.month.range'='1,12',
  'projection.day.range'='1,31',
  'storage.location.template'='s3://your-logs-bucket/AWSLogs/your-account-id/CloudTrail/${region}/${year}/${month}/${day}/'
);
```

- S3 server access logs (optional; if enabled):
```sql
CREATE EXTERNAL TABLE IF NOT EXISTS secops.s3_access_logs (
  bucket_owner string,
  bucket string,
  request_datetime string,
  remote_ip string,
  requester string,
  request_id string,
  operation string,
  key string,
  request_uri string,
  http_status int,
  error_code string,
  bytes_sent bigint,
  object_size bigint,
  total_time int,
  turn_around_time int,
  referrer string,
  user_agent string,
  version_id string,
  host_id string,
  signature_version string,
  cipher_suite string,
  authentication_type string,
  host_header string,
  tls_version string
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
WITH SERDEPROPERTIES (
  'input.regex'='([^ ]*) ([^ ]*) \\([^\\]]*)\\) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) "([^"]*)" ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) "([^"]*)" "([^"]*)" ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*)'
)
LOCATION 's3://your-s3-access-logs-bucket/';
```

- GuardDuty findings (if exported to S3 as JSON):
```sql
CREATE EXTERNAL TABLE IF NOT EXISTS secops.guardduty_findings (
  schemaVersion string,
  id string,
  arn string,
  type string,
  resource json,
  service json,
  severity double,
  title string,
  description string,
  updatedAt string,
  createdAt string,
  region string,
  accountId string
)
PARTITIONED BY (`year` string, `month` string, `day` string)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://your-guardduty-exports/';
```

- CUR (use your generated Athena view/table name from Billing console):
```sql
SELECT 1; -- placeholder to validate connectivity; replace with your CUR table
```

### Step 2 — Choose a time window
Set your analysis window by replacing the example timestamps below:
- Start: `2025-09-01T00:00:00Z`
- End:   `2025-09-02T00:00:00Z`

### Step 3 — Hunt queries (CloudTrail S3 Data + Management)

- Mass deletes by principal/bucket (DeleteObject, DeleteObjects):
```sql
WITH events AS (
  SELECT
    from_iso8601_timestamp(eventtime) AS et,
    coalesce(useridentity.arn, useridentity.sessioncontext.sessionissuer.arn) AS actor,
    eventname,
    regexp_extract(requestparameters, '"bucketName":"([^"]+)"', 1) AS bucket,
    regexp_extract(requestparameters, '"key":"([^"]+)"', 1) AS object_key
  FROM secops.cloudtrail_all
  WHERE eventsource = 's3.amazonaws.com'
    AND eventname IN ('DeleteObject','DeleteObjects')
    AND from_iso8601_timestamp(eventtime)
      BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z') AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
)
SELECT
  date_trunc('minute', et) AS minute_window,
  actor,
  bucket,
  count(*) AS delete_events
FROM events
GROUP BY 1,2,3
HAVING count(*) >= 100
ORDER BY delete_events DESC;
```

- Versioning disabled or suspended (PutBucketVersioning):
```sql
SELECT
  from_iso8601_timestamp(eventtime) AS et,
  coalesce(useridentity.arn, useridentity.sessioncontext.sessionissuer.arn) AS actor,
  eventname,
  regexp_extract(requestparameters, '"bucketName":"([^"]+)"', 1) AS bucket,
  requestparameters
FROM secops.cloudtrail_all
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'PutBucketVersioning'
  AND regexp_like(requestparameters, '"Status":"(Suspended|Disabled)"')
  AND from_iso8601_timestamp(eventtime)
    BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z') AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
ORDER BY et DESC;
```

- Bucket encryption disabled or removed (PutBucketEncryption/DeleteBucketEncryption):
```sql
SELECT
  from_iso8601_timestamp(eventtime) AS et,
  coalesce(useridentity.arn, useridentity.sessioncontext.sessionissuer.arn) AS actor,
  eventname,
  regexp_extract(requestparameters, '"bucketName":"([^"]+)"', 1) AS bucket,
  requestparameters
FROM secops.cloudtrail_all
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('PutBucketEncryption','DeleteBucketEncryption')
  AND (
    eventname = 'DeleteBucketEncryption'
    OR regexp_like(requestparameters, '"SSEAlgorithm":"(null|")')
  )
  AND from_iso8601_timestamp(eventtime)
    BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z') AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
ORDER BY et DESC;
```

- Lifecycle changed to rapid expiration (PutBucketLifecycleConfiguration):
```sql
SELECT
  from_iso8601_timestamp(eventtime) AS et,
  coalesce(useridentity.arn, useridentity.sessioncontext.sessionissuer.arn) AS actor,
  regexp_extract(requestparameters, '"bucketName":"([^"]+)"', 1) AS bucket,
  requestparameters
FROM secops.cloudtrail_all
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'PutBucketLifecycleConfiguration'
  AND regexp_like(requestparameters, '"Expiration":\{\"Days\":[0-9]{1,2}\}')
  AND from_iso8601_timestamp(eventtime)
    BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z') AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
ORDER BY et DESC;
```

- Public ACL/policy changes (PutBucketAcl/PutBucketPolicy/DeleteBucketPolicy):
```sql
SELECT
  from_iso8601_timestamp(eventtime) AS et,
  coalesce(useridentity.arn, useridentity.sessioncontext.sessionissuer.arn) AS actor,
  eventname,
  regexp_extract(requestparameters, '"bucketName":"([^"]+)"', 1) AS bucket,
  requestparameters
FROM secops.cloudtrail_all
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('PutBucketAcl','PutBucketPolicy','DeleteBucketPolicy')
  AND from_iso8601_timestamp(eventtime)
    BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z') AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
ORDER BY et DESC;
```

- Recon + encryptor pattern: ListObjects burst → GetObject surge → DeleteObject surge:
```sql
WITH base AS (
  SELECT
    from_iso8601_timestamp(eventtime) AS et,
    coalesce(useridentity.arn, useridentity.sessioncontext.sessionissuer.arn) AS actor,
    eventname,
    regexp_extract(requestparameters, '"bucketName":"([^"]+)"', 1) AS bucket
  FROM secops.cloudtrail_all
  WHERE eventsource = 's3.amazonaws.com'
    AND eventname IN ('ListObjects','ListObjectsV2','GetObject','DeleteObject','DeleteObjects')
    AND from_iso8601_timestamp(eventtime)
      BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z') AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
),
win AS (
  SELECT date_trunc('minute', et) AS minute_window, actor, bucket,
    count_if(eventname IN ('ListObjects','ListObjectsV2')) AS list_ct,
    count_if(eventname = 'GetObject') AS get_ct,
    count_if(eventname IN ('DeleteObject','DeleteObjects')) AS del_ct
  FROM base
  GROUP BY 1,2,3
)
SELECT *
FROM win
WHERE list_ct >= 50 OR get_ct >= 200 OR del_ct >= 100
ORDER BY minute_window DESC, (get_ct + del_ct) DESC;
```

- Unfamiliar source IPs or user agents performing deletes:
```sql
SELECT
  from_iso8601_timestamp(eventtime) AS et,
  coalesce(useridentity.arn, useridentity.sessioncontext.sessionissuer.arn) AS actor,
  sourceipaddress,
  useragent,
  regexp_extract(requestparameters, '"bucketName":"([^"]+)"', 1) AS bucket,
  eventname
FROM secops.cloudtrail_all
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('DeleteObject','DeleteObjects')
  AND sourceipaddress NOT LIKE 'AWS Internal%'
  AND NOT regexp_like(lower(useragent), 'aws-sdk|boto|aws-cli|s3fs|aws-internal')
  AND from_iso8601_timestamp(eventtime)
    BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z') AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
ORDER BY et DESC;
```

- IAM risk actions shaping ransomware blast radius:
```sql
SELECT
  from_iso8601_timestamp(eventtime) AS et,
  eventname,
  coalesce(useridentity.arn, useridentity.sessioncontext.sessionissuer.arn) AS actor,
  sourceipaddress,
  requestparameters
FROM secops.cloudtrail_all
WHERE eventsource IN ('iam.amazonaws.com','s3.amazonaws.com')
  AND eventname IN (
    'CreateAccessKey','UpdateAccessKey','CreateUser','AttachUserPolicy',
    'PutUserPolicy','PutRolePolicy','PutBucketPolicy','PutBucketAcl'
  )
  AND from_iso8601_timestamp(eventtime)
    BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z') AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
ORDER BY et DESC;
```

### Step 4 — S3 access log anomaly checks (if using server access logs)

- Sudden spike in DELETE or PUT by requester and bucket:
```sql
SELECT
  substr(request_datetime, 1, 20) AS minute_window,
  bucket,
  requester,
  sum(CASE WHEN operation LIKE '%DELETE%' THEN 1 ELSE 0 END) AS del_ct,
  sum(CASE WHEN operation LIKE '%REST.PUT.OBJECT%' THEN 1 ELSE 0 END) AS put_ct,
  sum(CASE WHEN operation LIKE '%REST.GET.OBJECT%' THEN 1 ELSE 0 END) AS get_ct
FROM secops.s3_access_logs
WHERE from_iso8601_timestamp(
        regexp_replace(request_datetime, ' ', 'T')
      ) BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z')
          AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
GROUP BY 1,2,3
HAVING del_ct >= 100 OR put_ct >= 200 OR get_ct >= 1000
ORDER BY del_ct DESC, put_ct DESC, get_ct DESC;
```

- Non-corporate user-agents or external IPs deleting objects:
```sql
SELECT
  request_datetime,
  bucket,
  requester,
  remote_ip,
  user_agent,
  operation,
  key
FROM secops.s3_access_logs
WHERE operation LIKE '%DELETE%'
  AND NOT regexp_like(lower(user_agent), 'aws-sdk|boto|aws-cli|internal')
  AND remote_ip NOT LIKE '10.%' AND remote_ip NOT LIKE '192.168.%' AND remote_ip NOT LIKE '172.16.%'
ORDER BY request_datetime DESC;
```

### Step 5 — GuardDuty confirmation

- S3-related high-severity findings in the window:
```sql
SELECT
  from_iso8601_timestamp(createdAt) AS created_ts,
  id,
  type,
  severity,
  title,
  description,
  region
FROM secops.guardduty_findings
WHERE severity >= 5
  AND (
    type LIKE 'Impact:%' OR
    type LIKE 'Exfiltration:%' OR
    type LIKE 'UnauthorizedAccess:%' OR
    lower(title) LIKE '%s3%'
  )
  AND from_iso8601_timestamp(createdAt)
    BETWEEN from_iso8601_timestamp('2025-09-01T00:00:00Z') AND from_iso8601_timestamp('2025-09-02T00:00:00Z')
ORDER BY severity DESC, created_ts DESC;
```

### Step 6 — Billing & CUR anomaly checks

- Spikes in S3 request counts (Requests-Tier1/2) by day:
```sql
SELECT
  bill_payer_account_id,
  CAST(line_item_usage_start_date AS date) AS usage_date,
  product_product_name,
  line_item_operation,
  SUM(CAST(line_item_usage_amount AS double)) AS total_requests
FROM cur_database.cur_table -- replace with your CUR table/view
WHERE product_product_name = 'Amazon Simple Storage Service'
  AND line_item_operation IN ('Requests-Tier1','Requests-Tier2')
  AND CAST(line_item_usage_start_date AS date) BETWEEN date '2025-09-01' AND date '2025-09-07'
GROUP BY 1,2,3,4
ORDER BY usage_date, total_requests DESC;
```

- Spikes in S3 DataTransfer-Internet-Out (possible exfiltration):
```sql
SELECT
  CAST(line_item_usage_start_date AS date) AS usage_date,
  line_item_operation,
  SUM(CAST(line_item_usage_amount AS double)) AS gb_out
FROM cur_database.cur_table
WHERE product_product_name = 'Amazon Simple Storage Service'
  AND line_item_operation LIKE 'DataTransfer-Internet-%'
  AND CAST(line_item_usage_start_date AS date) BETWEEN date '2025-09-01' AND date '2025-09-07'
GROUP BY 1,2
ORDER BY usage_date, gb_out DESC;
```

### Step 7 — Correlate and respond

- Triangulate the 5–10 minute windows where:
  - CloudTrail shows List → Get → Delete spikes.
  - GuardDuty flags S3 tampering/exfiltration.
  - CUR shows request/transfer anomalies.
  - Access logs show unfamiliar user agents/IPs.

- Immediate response steps:
  - Block access keys or sessions for suspicious `actor`.
  - Apply S3 bucket policy deny-by-default with exception for incident role.
  - Enable or re-enable versioning and MFA delete.
  - Suspend lifecycle rules that expire rapidly.
  - Initiate restore from versioned objects or backups.
  - Start Amazon Detective workbook if available.

## Notes and customization
- Replace `s3://your-logs-bucket`, `your-account-id`, and region lists with your environment specifics.
- Update the analysis time window in all queries.
- If you share your actual S3 log prefixes/table names, you can further tailor the CREATE TABLE statements and regex extracts for your schemas.

## Future Improvements
- **Automate detection queries** with Athena + Lambda.
- **Build a CloudWatch dashboard** for real-time ransomware detection.
- **Integrate Amazon Detective** for deeper forensic investigations.
- **Expand simulation** to include cross-service impacts (EC2, IAM, etc.).


