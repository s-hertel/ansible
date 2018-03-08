#!/usr/bin/python
#
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This Ansible library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'core'}


DOCUMENTATION = '''
---
module: s3_bucket
short_description: Manage S3 buckets in AWS, Ceph, Walrus and FakeS3
description:
    - Manage S3 buckets in AWS, Ceph, Walrus and FakeS3
version_added: "2.0"
requirements: [ boto3 ]
author: "Rob White (@wimnat)"
options:
  force:
    description:
      - When trying to delete a bucket, delete all keys in the bucket first (an s3 bucket must be empty for a successful deletion)
    type: bool
    default: 'no'
  name:
    description:
      - Name of the s3 bucket
    required: true
  policy:
    description:
      - The JSON policy as a string.
  s3_url:
    description:
      - S3 URL endpoint for usage with Ceph, Eucalypus, fakes3, etc. Otherwise assumes AWS
    aliases: [ S3_URL ]
  ceph:
    description:
      - Enable API compatibility with Ceph. It takes into account the S3 API subset working
        with Ceph in order to provide the same module behaviour where possible.
    version_added: "2.2"
  requester_pays:
    description:
      - With Requester Pays buckets, the requester instead of the bucket owner pays the cost
        of the request and the data download from the bucket.
    type: bool
    default: 'no'
  state:
    description:
      - Create or remove the s3 bucket
    required: false
    default: present
    choices: [ 'present', 'absent' ]
  tags:
    description:
      - tags dict to apply to bucket
  versioning:
    description:
      - Whether versioning is enabled or disabled (note that once versioning is enabled, it can only be suspended)
    type: bool
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Create a simple s3 bucket
- s3_bucket:
    name: mys3bucket

# Create a simple s3 bucket on Ceph Rados Gateway
- s3_bucket:
    name: mys3bucket
    s3_url: http://your-ceph-rados-gateway-server.xxx
    ceph: true

# Remove an s3 bucket and any keys it contains
- s3_bucket:
    name: mys3bucket
    state: absent
    force: yes

# Create a bucket, add a policy from a file, enable requester pays, enable versioning and tag
- s3_bucket:
    name: mys3bucket
    policy: "{{ lookup('file','policy.json') }}"
    requester_pays: yes
    versioning: yes
    tags:
      example: tag1
      another: tag2

'''

import json
import os

import ansible.module_utils.six.moves.urllib.parse as urlparse
from ansible.module_utils.six import string_types
from ansible.module_utils.basic import to_text
from ansible.module_utils.aws.core import AnsibleAWSModule
from ansible.module_utils.ec2 import compare_policies, ec2_argument_spec, boto3_tag_list_to_ansible_dict, ansible_dict_to_boto3_tag_list
from ansible.module_utils.ec2 import get_aws_connection_info, boto3_conn

try:
    from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError
except ImportError:
    pass  # handled by AnsibleAWSModule


def create_or_update_bucket(s3_client, module, location):

    policy = module.params.get("policy")
    name = module.params.get("name")
    requester_pays = module.params.get("requester_pays")
    tags = module.params.get("tags")
    versioning = module.params.get("versioning")
    changed = False

    try:
        s3_client.head_bucket(Bucket=name)
    except EndpointConnectionError as e:
        module.fail_json_aws(e, msg="Invalid endpoint provided: %s" % to_text(e))
    except ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            # Bucket does not exist, we create it
            configuration = {}
            if location not in ('us-east-1', None):
                configuration['LocationConstraint'] = location
            try:
                if len(configuration) > 0:
                    s3_client.create_bucket(Bucket=name, CreateBucketConfiguration=configuration)
                else:
                    s3_client.create_bucket(Bucket=name)
                changed = True
            except (BotoCoreError, ClientError) as e:
                module.fail_json_aws(e, msg="Failed while creating bucket")
        else:
            module.fail_json_aws(e, msg="Failed to check bucket presence")
    except BotoCoreError as e:
        module.fail_json_aws(e, msg="Failed to check bucket presence")

    # Versioning
    try:
        versioning_status = s3_client.get_bucket_versioning(Bucket=name)
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg="Failed to get bucket versioning")

    if versioning is not None:
        required_versioning = None
        if versioning and versioning_status.get('Status') != "Enabled":
            required_versioning = 'Enabled'
        elif not versioning and versioning_status.get('Status') == "Enabled":
            required_versioning = 'Suspended'

        if required_versioning:
            try:
                s3_client.put_bucket_versioning(Bucket=name, VersioningConfiguration={'Status': required_versioning})
                changed = True
            except (BotoCoreError, ClientError) as e:
                module.fail_json_aws(e, msg="Failed to update bucket versioning")

            try:
                versioning_status = s3_client.get_bucket_versioning(Bucket=name)
            except (BotoCoreError, ClientError) as e:
                module.fail_json_aws(e, msg="Failed to get updated versioning for bucket")

    # This output format is there to ensure compatibility with previous versions of the module
    versioning_return_value = {
        'Versioning': versioning_status.get('Status', 'Disabled'),
        'MfaDelete': versioning_status.get('MFADelete', 'Disabled'),
    }

    # Requester pays
    try:
        requester_pays_status = s3_client.get_bucket_request_payment(Bucket=name).get('Payer')
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg="Failed to get bucket request payment")

    payer = 'Requester' if requester_pays else 'BucketOwner'
    if requester_pays_status != payer:
        s3_client.put_bucket_request_payment(Bucket=name, RequestPaymentConfiguration={'Payer': payer})
        changed = True

    # Policy
    try:
        current_policy = json.loads(s3_client.get_bucket_policy(Bucket=name).get('Policy'))
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            current_policy = None
        else:
            module.fail_json_aws(e, msg="Failed to get bucket policy")
    except BotoCoreError as e:
        module.fail_json_aws(e, msg="Failed to get bucket policy")

    if policy is not None:
        if isinstance(policy, string_types):
            policy = json.loads(policy)

        if not policy and current_policy:
            try:
                s3_client.delete_bucket_policy(Bucket=name)
            except (BotoCoreError, ClientError) as e:
                module.fail_json_aws(e, msg="Failed to delete bucket policy")
            changed = True

        elif compare_policies(current_policy, policy):
            try:
                s3_client.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
            except (BotoCoreError, ClientError) as e:
                module.fail_json_aws(e, msg="Failed to update bucket policy")
            changed = True
            current_policy = policy

    # Tags
    try:
        current_tags = s3_client.get_bucket_tagging(Bucket=name).get('TagSet')
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchTagSet':
            current_tags = None
        else:
            module.fail_json_aws(e, msg="Failed to get bucket tags")
    except BotoCoreError as e:
        module.fail_json_aws(e, msg="Failed to get bucket tags")

    if current_tags is None:
        current_tags_dict = {}
    else:
        current_tags_dict = boto3_tag_list_to_ansible_dict(current_tags)

    if tags is not None:
        if current_tags_dict != tags:
            if tags:
                try:
                    s3_client.put_bucket_tagging(Bucket=name, Tagging={'TagSet': ansible_dict_to_boto3_tag_list(tags)})
                except (BotoCoreError, ClientError) as e:
                    module.fail_json_aws(e, msg="Failed to update bucket tags")
            else:
                try:
                    s3_client.delete_bucket_tagging(Bucket=name)
                except (BotoCoreError, ClientError) as e:
                    module.fail_json_aws(e, msg="Failed to delete bucket tags")
            current_tags_dict = tags
            changed = True

    module.exit_json(changed=changed, name=name, versioning=versioning_return_value,
                     requester_pays=requester_pays, policy=current_policy, tags=current_tags_dict)


def paginated_list(s3_client, **pagination_params):
    pg = s3_client.get_paginator('list_objects_v2')
    for page in pg.paginate(**pagination_params):
        yield [data['Key'] for data in page.get('Contents', [])]


def destroy_bucket(s3_client, module):

    force = module.params.get("force")
    name = module.params.get("name")
    changed = False
    try:
        s3_client.head_bucket(Bucket=name)
    except EndpointConnectionError as e:
        module.fail_json_aws(e, msg="Invalid endpoint provided: %s" % to_text(e))
    except ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            # Bucket already absent
            module.exit_json(changed=changed)
        else:
            module.fail_json_aws(e, msg="Failed to check bucket presence")
    except BotoCoreError as e:
        module.fail_json_aws(e, msg="Failed to check bucket presence")

    if force:
        # if there are contents then we need to delete them before we can delete the bucket
        try:
            for keys in paginated_list(s3_client, Bucket=name):
                formatted_keys = [{'Key': key} for key in keys]
                if formatted_keys:
                    s3_client.delete_objects(Bucket=name, Delete={'Objects': formatted_keys})
            changed = True
        except (BotoCoreError, ClientError) as e:
            module.fail_json_aws(e, msg="Failed while deleting bucket")

    try:
        s3_client.delete_bucket(Bucket=name)
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg="Failed to delete bucket")
    changed = True

    module.exit_json(changed=changed)


def is_fakes3(s3_url):
    """ Return True if s3_url has scheme fakes3:// """
    if s3_url is not None:
        return urlparse.urlparse(s3_url).scheme in ('fakes3', 'fakes3s')
    else:
        return False


def is_walrus(s3_url):
    """ Return True if it's Walrus endpoint, not S3

    We assume anything other than *.amazonaws.com is Walrus"""
    if s3_url is not None:
        o = urlparse.urlparse(s3_url)
        return not o.hostname.endswith('amazonaws.com')
    else:
        return False


def get_s3_client(module, aws_connect_kwargs, location, ceph, s3_url):
    if s3_url and ceph:  # TODO - test this
        ceph = urlparse(s3_url)
        params = dict(module=module, conn_type='client', resource='s3', use_ssl=ceph.scheme == 'https', region=location, endpoint=s3_url, **aws_connect_kwargs)
    elif is_fakes3(s3_url):
        fakes3 = urlparse(s3_url)
        port = fakes3.port
        if fakes3.scheme == 'fakes3s':
            protocol = "https"
            if port is None:
                port = 443
        else:
            protocol = "http"
            if port is None:
                port = 80
        params = dict(module=module, conn_type='client', resource='s3', region=location,
                      endpoint="%s://%s:%s" % (protocol, fakes3.hostname, to_text(port)),
                      use_ssl=fakes3.scheme == 'fakes3s', **aws_connect_kwargs)
    elif is_walrus(s3_url):
        walrus = urlparse(s3_url).hostname
        params = dict(module=module, conn_type='client', resource='s3', region=location, endpoint=walrus, **aws_connect_kwargs)
    else:
        params = dict(module=module, conn_type='client', resource='s3', region=location, endpoint=s3_url, **aws_connect_kwargs)
    return boto3_conn(**params)


def main():

    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            force=dict(required=False, default='no', type='bool'),
            policy=dict(required=False, default=None, type='json'),
            name=dict(required=True, type='str'),
            requester_pays=dict(default='no', type='bool'),
            s3_url=dict(aliases=['S3_URL'], type='str'),
            state=dict(default='present', type='str', choices=['present', 'absent']),
            tags=dict(required=False, default=None, type='dict'),
            versioning=dict(default=None, type='bool'),
            ceph=dict(default='no', type='bool')
        )
    )

    module = AnsibleAWSModule(argument_spec=argument_spec)

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)

    if region in ('us-east-1', '', None):
        # default to US Standard region
        location = 'us-east-1'
    else:
        # Boto uses symbolic names for locations but region strings will
        # actually work fine for everything except us-east-1 (US Standard)
        location = region

    s3_url = module.params.get('s3_url')
    ceph = module.params.get('ceph')

    # allow eucarc environment variables to be used if ansible vars aren't set
    if not s3_url and 'S3_URL' in os.environ:
        s3_url = os.environ['S3_URL']

    if ceph and not s3_url:
        module.fail_json(msg='ceph flavour requires s3_url')

    # Look at s3_url and tweak connection settings
    # if connecting to Ceph RGW, Walrus or fakes3
    if s3_url:
        for key in ['validate_certs', 'security_token', 'profile_name']:
            aws_connect_kwargs.pop(key, None)
    s3_client = get_s3_client(module, aws_connect_kwargs, location, ceph, s3_url)

    if s3_client is None:  # this should never happen
        module.fail_json(msg='Unknown error, failed to create s3 connection, no information from boto.')

    state = module.params.get("state")

    if state == 'present':
        create_or_update_bucket(s3_client, module, location)
    elif state == 'absent':
        destroy_bucket(s3_client, module)


if __name__ == '__main__':
    main()
