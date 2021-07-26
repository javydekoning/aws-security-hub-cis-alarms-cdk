import {
  App,
  Stack,
  StackProps,
  aws_sns as sns,
  aws_logs as logs,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

import { CisFilterPatterns, CisCloudTrailAlarm } from './cis_alarms';

const app = new App();

class SecHubStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Import PreExisting CloudTrail Organizations Log Group
    const logGroup = logs.LogGroup.fromLogGroupName(
      this,
      'orgtrail',
      'aws-cloudtrail-org-logs'
    );

    // Import PreExisting SnsTopics
    const snsTopic = sns.Topic.fromTopicArn(
      this,
      'myExistingSnsTopic',
      'arn:aws:sns:<region>:<account>:<name>'
    );

    Object.entries(CisFilterPatterns).forEach(([key, value]) => {
      new CisCloudTrailAlarm(this, key, {
        logGroup,
        snsTopic,
        filterPatternString: value,
      });
    });
  }
}

new SecHubStack(app, 'SecHubStack');
