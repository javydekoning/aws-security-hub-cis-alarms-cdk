import { Construct } from 'constructs';
import {
  Duration,
  aws_logs as logs,
  aws_cloudwatch as cloudwatch,
  aws_cloudwatch_actions as cw_actions,
  aws_sns as sns,
} from 'aws-cdk-lib';

export enum CisFilterPatterns {
  'CIS_1_1_ROOT_ACCOUNT_USAGE' = '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}',
  'CIS_3_1_UNAUTHORIZED_API_CALLS' = '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}',
  'CIS_3_2_CONSOLE_SIGNIN_WITHOUT_MFA' = '{($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")}',
  'CIS_3_3_ROOT_ACCOUNT_USAGE' = '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}',
  'CIS_3_4_IAM_POLICY_CHANGES' = '{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}',
  'CIS_3_5_CLOUDTRAIL_CHANGES' = '{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}',
  'CIS_3_6_CONSOLE_AUTHENTICATION_FAILURE' = '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}',
  'CIS_3_7_DISABLE_OR_DELETE_CMK' = '{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}',
  'CIS_3_8_S3_BUCKET_POLICY_CHANGES' = '{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}',
  'CIS_3_9_AWS_CONFIG_CHANGES' = '{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}',
  'CIS_3_10_SECURITY_GROUP_CHANGES' = '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}',
  'CIS_3_11_NETWORK_ACL_CHANGES' = '{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}',
  'CIS_3_12_NETWORK_GATEWAY_CHANGES' = '{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}',
  'CIS_3_13_ROUTE_TABLE_CHANGES' = '{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}',
  'CIS_3_14_VPC_CHANGES' = '{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}',
}

export interface CisCloudTrailAlarmProps {
  logGroup: logs.ILogGroup;
  filterPatternString: string;
  snsTopic: sns.ITopic;
}

export class CisCloudTrailAlarm extends Construct {
  constructor(scope: Construct, id: string, props: CisCloudTrailAlarmProps) {
    super(scope, id);

    const filter = new logs.MetricFilter(this, 'Filter', {
      filterPattern: logs.FilterPattern.literal(props.filterPatternString),
      logGroup: props.logGroup,
      metricName: 'CIS-Metric-' + id,
      metricNamespace: 'LogMetrics',
    });

    const metric = new cloudwatch.Metric({
      metricName: 'CIS-Metric-' + id,
      namespace: 'LogMetrics',
      period: Duration.minutes(5),
      statistic: 'sum',
    });

    const alarm = new cloudwatch.Alarm(this, 'Alarm', {
      evaluationPeriods: 1,
      metric: metric,
      threshold: 0,
      alarmName: 'CIS-Alarm-' + id,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    alarm.addAlarmAction(new cw_actions.SnsAction(props.snsTopic));
  }
}
