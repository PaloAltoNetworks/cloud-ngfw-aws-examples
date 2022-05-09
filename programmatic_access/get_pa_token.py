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
import logging
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from auth_aws_iam import AuthAwsIam
from pa_utils import (
    pa_logger,
    HTTP_VERB_GET,
)


def get_request_url(url, query_params_dict=None):
    pa_logger.debug(f"URL: {url}")
    pa_logger.debug(f"QUERY PARAMS: {query_params_dict}")
    request_url = url

    if query_params_dict is not None:
        request_url = f"{request_url}?"
        for key, value in query_params_dict.items():
            request_url = f"{request_url}{key}={value}&"
        request_url = request_url[:-1]

    pa_logger.debug(f"Request URL: {request_url}")
    return request_url


if __name__ == "__main__":
    # Setup Environment
    urllib3.disable_warnings(InsecureRequestWarning)

    # Parse Arguments
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
                        dest="role_arn",
                        required=True,
                        metavar="ROLE_ARN",
                        type=str,
                        help="Specify the role arn with Cloud NGFW programmatic access tags",
                        )
    parser.add_argument("--get-token-url",
                        dest="get_token_url",
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

    pa_logger.debug(f"ARGS: {args}")
    pa_logger.debug(f"Region: {args.region}")
    pa_logger.debug(f"Profile: {args.profile}")
    pa_logger.debug(f"RoleArn: {args.role_arn}")
    pa_logger.debug(f"GetTokenUrl: {args.get_token_url}")

    # Get AWS IAM temporary credentials
    _auth_iam = AuthAwsIam(
        region=args.region,
        role_to_assume=args.role_arn,
        profile_to_assume=args.profile,
    )
    pa_logger.debug(f"AccessKey: {_auth_iam.access_key}")
    pa_logger.debug(f"SecretKey: {_auth_iam.secret_key}")
    pa_logger.debug(f"SessionToken: {_auth_iam.session_token}")

    # Request Body
    body_dict = {}

    # Request Query Params
    query_params_dict = {
        "expirytime": 60,
    }

    # Headers
    sign_url = get_request_url(
        url=args.get_token_url,
        query_params_dict=query_params_dict,
    )

    headers = _auth_iam.get_headers(HTTP_VERB_GET, sign_url, body_dict)

    # Request
    response = requests.get(
        url=args.get_token_url,
        headers=headers,
        json=body_dict,
        params=query_params_dict,
        verify=False,
    )
    pa_logger.debug(f"ResponseUrl: {response.url}")
    pa_logger.debug(f"ResponseStatusCode: {response.status_code}")
    pa_logger.debug(f"ResponseText: {response.text}")

    # Parse response
    resp_dict = response.json()
    assert resp_dict['ResponseStatus']['ErrorCode'] == 0

    # Output
    pa_logger.info(f"Cloud NGFW Programmatic Access Token: {resp_dict['Response']['TokenId']}")
    pa_logger.info(f"Cloud NGFW Subscription Key: {resp_dict['Response']['SubscriptionKey']}")
