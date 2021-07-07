# Construct

This repo contains a sample construct (`./cis_alarms.ts`) which implements the Security Hub CIS requirements as per documentation: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html 

The construct creates CloudWatch Metric and the required Alarm. The CloudTrail, Cloudwatch log group and SnsTopic are expected to already be in place.

A sample stack is found at `securityhub_stack.ts`