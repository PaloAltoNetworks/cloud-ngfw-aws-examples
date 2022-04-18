"""
This module contains an example to get the programmatic access token for Cloud NGFW tenant

Pre-requisites:
1. Cloud NGFW tenant is created from Cloud NGFW console
2. AWS Account is onboarded to the above tenant
3. IAM roles with necessary Cloud NGFW tags are created in the client account

How to run this tool:
python get_pa_token.py \
--profile <aws-profile> \
--region <aws-region> \
--role-arn <aws-iam-role-arn> \
--get-token-url https://api.us-east-1.aws.cloudngfw.com/v1/mgmt/tokens/cloudfirewalladmin
"""
import argparse
import json
import logging
import requests

from auth_aws_iam import AuthAwsIam
from pa_utils import (
    pa_logger,
    HTTP_VERB_GET,
)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parameters need to get programmatic access token for Cloud NGFW.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--region",
                        dest="region",
                        default="us-east-1",
                        required=False,
                        metavar="REGION",
                        type=str,
                        help="Specify the aws region",
                        )
    parser.add_argument("--profile",
                        dest="profile",
                        required=False,
                        metavar="PROFILE",
                        type=str,
                        help="Specify the aws profile which can assume the role arn",
                        )
    parser.add_argument("--role-arn",
                        dest="rolearn",
                        required=True,
                        metavar="ROLE_ARN",
                        type=str,
                        help="Specify the role arn with Cloud NGFW programmatic access tags",
                        )
    parser.add_argument("--get-token-url",
                        dest="gettokenurl",
                        required=True,
                        metavar="GET_TOKEN_URL",
                        type=str,
                        help="Cloud NGFW get token url for specific role",
                        )
    parser.add_argument("--debug",
                        dest="debug",
                        default=False,
                        action="store_true",
                        help="Enable debug output",
                        )

    args = parser.parse_args()
    pa_logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    pa_logger.info(f"ARGS: {args}")
    pa_logger.debug(f"Region: {args.region}")
    pa_logger.debug(f"Profile: {args.profile}")
    pa_logger.debug(f"RoleArn: {args.rolearn}")
    pa_logger.debug(f"GetTokenUrl: {args.gettokenurl}")

    _auth_iam = AuthAwsIam(
        region=args.region,
        role_to_assume=args.rolearn,
        profile_to_assume=args.profile,
    )
    pa_logger.debug(f"AccessKey: {_auth_iam.access_key}")
    pa_logger.debug(f"SecretKey: {_auth_iam.secret_key}")
    pa_logger.debug(f"SessionToken: {_auth_iam.session_token}")

    body = {
        "ExpiryTime": 60
    }

    request_url = args.gettokenurl

    headers = _auth_iam.get_headers(HTTP_VERB_GET, request_url, body)

    session = requests.session()
    response = requests.get(request_url, headers=headers, data=json.dumps(body), verify=False)
    pa_logger.debug(f"ResponseText: {response.text}")

    resp_dict = response.json()
    assert resp_dict['ResponseStatus']['ErrorCode'] == 0

    pa_logger.info(f"Cloud NGFW Programmatic Access Token: {resp_dict['Response']['TokenId']}")
    pa_logger.info(f"Cloud NGFW Subscription Key: {resp_dict['Response']['SubscriptionKey']}")
