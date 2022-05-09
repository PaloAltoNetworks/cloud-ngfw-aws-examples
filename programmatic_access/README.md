# CloudNGFW Programmatic Access Token

## Help
```bash
usage: get_pa_token.py [-h] [--region REGION] [--profile PROFILE] --role-arn ROLE_ARN --get-token-url GET_TOKEN_URL [--debug]

Parameters need to get programmatic access token for Cloud NGFW.

optional arguments:
  -h, --help            show this help message and exit
  --region REGION       Specify the aws region
  --profile PROFILE     Specify the aws profile which can assume the role arn
  --role-arn ROLE_ARN   Specify the role arn with Cloud NGFW programmatic access tags
  --get-token-url GET_TOKEN_URL
                        Cloud NGFW get token url for specific role
  --debug               Enable debug output
```

## CloudFirewallAdmin
```bash
python3 get_pa_token.py \
--profile <aws-profile> \
--region <aws-region> \
--role-arn <aws-iam-role-arn> \
--get-token-url https://api.us-east-1.aws.cloudngfw.paloaltonetworks.com/v1/mgmt/tokens/cloudfirewalladmin
```

## CloudRulestackAdmin
```bash
python3 get_pa_token.py \
--profile <profile> \
--region <region> \
--role-arn <aws-iam-role-arn> \
--get-token-url https://api.us-east-1.aws.cloudngfw.paloaltonetworks.com/v1/mgmt/tokens/cloudrulestackadmin
```

## CloudGlobalRulestackAdmin
```bash
python3 get_pa_token.py \
--profile <profile> \
--region <region> \
--role-arn <aws-iam-role-arn> \
--get-token-url https://api.us-east-1.aws.cloudngfw.paloaltonetworks.com/v1/mgmt/tokens/cloudglobalrulestackadmin
```
