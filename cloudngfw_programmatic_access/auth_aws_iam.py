"""
This module uses following AWS documentation as reference
Ref: https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
"""
import boto3
import datetime
import hashlib
import hmac
import json

from urllib.parse import urlparse

from pa_utils import (
    pa_logger,
    ROLE_SESSION_NAME_DEFAULT,
)


class AuthAwsIam:
    """
    This class contains methods and utilities to get the AWS v4 signature signed headers to call AWS service endpoints
    using IAM authentication.
    """

    def __init__(
            self,
            region,
            role_to_assume,
            profile_to_assume=None,
            api_key=None,
    ):
        self.access_key = None
        self.secret_key = None
        self.session_token = None
        self.region = region
        self.api_key = api_key
        self.profile = profile_to_assume
        self.role_to_assume = role_to_assume
        self.role_session_name = ROLE_SESSION_NAME_DEFAULT

        SESSION = boto3.Session(profile_name=self.profile)
        self.sts_client = SESSION.client('sts')

        self.set_role_credentials()

    def set_credentials(self, access_key, secret_key, session_token):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token

    def set_role_credentials(self):
        pa_logger.debug(f"Profile: {self.profile}, RoleToAssume: {self.role_to_assume}")

        try:
            response = self.sts_client.assume_role(
                RoleArn=self.role_to_assume,
                RoleSessionName=self.role_session_name
            )
            pa_logger.debug(f"AssumeRole response: {response}")

            credentials = response['Credentials']
            pa_logger.debug(f"Credentials: {credentials}")

            self.set_credentials(
                access_key=credentials['AccessKeyId'],
                secret_key=credentials['SecretAccessKey'],
                session_token=credentials['SessionToken'],
            )

        except Exception as e:
            pa_logger.error(f"Failed to assume role. Error: {e}")

    @staticmethod
    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    @staticmethod
    def get_signature_key(key, date_stamp, regionName, serviceName):
        """
        Ref: https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
        """
        kDate = AuthAwsIam.sign(('AWS4' + key).encode('utf-8'), date_stamp)
        kRegion = AuthAwsIam.sign(kDate, regionName)
        kService = AuthAwsIam.sign(kRegion, serviceName)
        kSigning = AuthAwsIam.sign(kService, 'aws4_request')
        return kSigning

    def get_headers(self, method, url, body):
        """
        Ref: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        """
        service = 'execute-api'

        # Create a date for headers and the credential string
        t = datetime.datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        # Date w/o time, used in credential scope
        date_stamp = t.strftime('%Y%m%d')

        request_parameters = json.dumps(body)

        url_splits = urlparse(url)
        host = url_splits.netloc
        # ************* TASK 1: CREATE A CANONICAL REQUEST *************
        # Step 1 is to define the verb (GET, POST, etc.)
        pa_logger.debug(f"Method: {method}")

        # Step 2: Create canonical URI--the part of the URI from domain to query
        # string (use '/' if no path)
        canonical_uri = url_splits.path

        # Step 3: Create the canonical query string. In this example, request
        # parameters are passed in the body of the request and the query string
        # is blank.
        canonical_querystring = url_splits.query

        # Step 4: Create the canonical headers. Header names must be trimmed
        # and lowercase, and sorted in code point order from low to high.
        # Note that there is a trailing \n.
        canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'
        if self.session_token is not None:
            canonical_headers = canonical_headers + 'x-amz-security-token:' + self.session_token + '\n'

        # Step 5: Create the list of signed headers. This lists the headers
        # in the canonical_headers list, delimited with ";" and in alpha order.
        # Note: The request can include any headers; canonical_headers and
        # signed_headers include those that you want to be included in the
        # hash of the request. "Host" and "x-amz-date" are always required.
        # For DynamoDB, content-type and x-amz-target are also required.
        signed_headers = 'host;x-amz-date'
        if self.session_token is not None:
            signed_headers = signed_headers + ';x-amz-security-token'

        # Step 6: Create payload hash. In this example, the payload (body of
        # the request) contains the request parameters.
        payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()

        # Step 7: Combine elements to create canonical request
        canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' \
            + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

        # ************* TASK 2: CREATE THE STRING TO SIGN*************
        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = date_stamp + '/' + self.region + '/' + service + '/' + 'aws4_request'
        string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + \
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

        # ************* TASK 3: CALCULATE THE SIGNATURE *************
        # Create the signing key using the function defined above.
        signing_key = AuthAwsIam.get_signature_key(self.secret_key, date_stamp, self.region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

        # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        # Put the signature information in a header named Authorization.
        authorization_header = algorithm + ' ' + 'Credential=' + self.access_key + '/' + \
            credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

        # For DynamoDB, the request can include any headers, but MUST include "host", "x-amz-date",
        # "x-amz-target", "content-type", and "Authorization". Except for the authorization
        # header, the headers must be included in the canonical_headers and signed_headers values, as
        # noted earlier. Order here is not significant.
        # # Python note: The 'host' header is added automatically by the Python 'requests' library.
        headers = {
            'X-Amz-Date': amz_date,
            'Authorization': authorization_header
        }

        if self.session_token is not None:
            headers['X-Amz-Security-Token'] = self.session_token

        pa_logger.debug(f"Canonical Request: {canonical_request}")
        pa_logger.debug(f"String To Sign: {string_to_sign}")

        if self.api_key:
            headers['x-api-key'] = self.api_key

        pa_logger.debug(f"Headers: {headers}")
        return headers
