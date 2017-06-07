#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
---
module: ec2_vpc_vpn
short_description: Create, modify, and delete EC2 VPN connections.
description:
  - This module creates, modifies, and deletes VPN connections. Idempotence is achieved by using the filters
    options or specifying the VPN connection identifier.
version_added: "2.4"
author: "Sloane Hertel (@s-hertel)"
options:
  state:
    description:
      - The desired state of the VPN connection.
    choices: ['present', 'absent']
    default: present
    required: no
  customer_gateway_id:
    description:
      - The ID of the customer gateway.
  connection_type:
    description:
      - The type of VPN connection.
    choices: ['ipsec.1']
    default: ipsec.1
  vpn_gateway_id:
    description:
      - The ID of the virtual private gateway.
  vpn_connection_id:
    description:
      - The ID of the VPN connection. Required to modify or delete a connection if the filters option does not provide a unique match.
  tags:
    description:
      - Tags to attach to the VPN connection.
  purge_tags:
    description:
      - Whether or not to delete VPN connections tags that are associated with the connection but not specified in the task.
    type: bool
    default: false
  static_only:
    description:
      - Indicates whether the VPN connection uses static routes only. Static routes must be used for devices that don't support BGP.
    default: False
    required: no
  filters:
    description:
      - An alternative to using vpn_connection_id. If multiple matches are found, vpn_connection_id is required.
        If one of the following suboptions is a list of items to filter by, only one item needs to match to find the VPN
        that correlates. e.g. if the filter 'cidr' is ['194.168.2.0/24', '192.168.2.0/24'] and the VPN route only has the
        destination cidr block of '192.168.2.0/24' it will be found with this filter (assuming there are not multiple
        VPNs that are matched). Another example: if the filter 'vpn' is equal to ['vpn-ccf7e7ad', 'vpn-cb0ae2a2'] and one
        of of the VPNs has the state deleted (exists but is unmodifiable) and the other exists and is not deleted,
        it will be found via this filter.
    type: dict
    suboptions:
      cgw-config:
        description:
          - The customer gateway configuration of the VPN as a string (in the format of the return value) or a list of those strings.
      static-routes-only:
        description:
          - The type of routing; true or false.
      cidr:
        description:
          - The destination cidr of the VPN's route as a string or a list of those strings.
      bgp:
        description:
          - The BGP ASN number associated with a BGP device. Only works if the connection is attached.
            TODO: This filtering option is currently not working.
      vpn:
        description:
          - The VPN connection id as a string or a list of those strings.
      vgw:
        description:
          - The virtual private gateway as a string or a list of those strings.
      tag-keys:
        description:
          - The key of a tag as a string or a list of those strings.
      tag-values:
        description:
          - The value of a tag as a string or a list of those strings.
      tags:
        description:
          - A dict of key value pairs.
      cgw:
        description:
          - The customer gateway id as a string or a list of those strings.
  routes:
    description:
      - Routes to add to the connection.
  purge_routes:
    description:
      - Whether or not to delete VPN connections routes that are not specified in the task.
  check_mode:
    description:
      - See what changes will be made before making them.
    default: False
    type: bool
    required: no
"""

EXAMPLES = """
# Note: None of these examples set aws_access_key, aws_secret_key, or region.
# It is assumed that their matching environment variables are set.

- name: create a VPN connection
  ec2_vpc_vpn:
    state: present
    vpn_gateway_id: vgw-XXXXXXXX
    customer_gateway_id: cgw-XXXXXXXX

- name: modify VPN connection tags
  ec2_vpc_vpn:
    state: present
    vpn_connection_id: vpn-XXXXXXXX
    tags:
      Name: ansible-tag-1
      Other: ansible-tag-2

- name: delete a connection
  ec2_vpc_vpn:
    vpn_connection_id: vpn-XXXXXXXX
    state: absent

- name: modify VPN tags (identifying VPN by filters)
  ec2_vpc_vpn:
    state: present
    filters:
      cidr: 194.168.1.0/24
      tag-keys:
        - Ansible
        - Other
    tags:
      New: Tag
    purge_tags: true
    static_only: true

- name: add routes and remove any preexisting ones
  ec2_vpc_vpn:
    state: present
    filters:
      vpn: vpn-XXXXXXXX
    routes:
      - 195.168.2.0/24
      - 196.168.2.0/24
    purge_routes: true

- name: remove all routes
  ec2_vpc_vpn:
    state: present
    vpn_connection_id: vpn-XXXXXXXX
    routes: []
    purge_routes: true

- name: delete a VPN identified by filters
  ec2_vpc_vpn:
    state: absent
    filters:
      tags:
        Ansible: Tag
"""

RETURN = """
changed:
  description: if the connection has changed
  type: bool
  returned: always
  sample:
    changed: true
customer_gateway_configuration:
  description: the configuration of the connection
  type: str
customer_gateway_id:
  description: the customer gateway connected via the connection
  type: str
  sample:
    customer_gateway_id: cgw-1220c87b
vpn_gateway_id:
  description: the virtual private gateway connected via the connection
  type: str
  sample:
    vpn_gateway_id: vgw-cb0ae2a2
options:
  static_routes_only:
    description: the type of routing option
    type: bool
    sample:
      static_routes_only: true
routes:
  description: the connection routes
  type: list
  sample:
    routes: [{
              'destination_cidr_block': '192.168.1.0/24',
              'state': 'available'
            }]
state:
  description: the status of the connection
  type: string
  sample:
    state: available
tags:
  description: the tags associated with the connection
  type: dict
  sample:
    tags:
      name: ansible-test
      other: tag
type:
  description: the type of connection
  type: str
  sample:
    type: "ipsec.1"
vgw_telemetry:
  type: list
  description: the telemetry for the VPN tunnel
  sample:
    vgw_telemetry: [{
                     'outside_ip_address': 'string',
                     'status': 'up',
                     'last_status_change': datetime(2015, 1, 1),
                     'status_message': 'string',
                     'accepted_route_count': 123
                    }]
vpn_connection_id:
  description: the identifier for the VPN connection
  type: str
  sample:
    vpn_connection_id: vpn-781e0e19
"""

# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.ec2 import (boto3_conn, get_aws_connection_info, ec2_argument_spec,
                                      snake_dict_to_camel_dict, camel_dict_to_snake_dict,
                                      boto3_tag_list_to_ansible_dict, ansible_dict_to_boto3_tag_list,
                                      compare_aws_tags)
import traceback

try:
    import boto3
    import botocore
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class VPNConnectionException(Exception):
    def __init__(self, msg, exception=None, response=None):
        self.msg = msg
        self.error_traceback = exception
        self.response = response


def find_connection(connection, module_params, vpn_connection_id=None):
    ''' Looks for a unique VPN connection. Uses find_connection_response() to return the connection found, None,
        or raise an error if there were multiple viable connections. '''

    check_mode = module_params.get('check_mode')
    filters = module_params.get('filters')

    # vpn_connection_id may be provided via module option; takes precedence over any filter values
    if not vpn_connection_id and module_params.get('vpn_connection_id'):
        vpn_connection_id = module_params.get('vpn_connection_id')

    if isinstance(vpn_connection_id, str):
        vpn_connection_id = [vpn_connection_id]

    formatted_filter = []
    # if vpn_connection_id is provided it will take precedence over any filters since it is a unique identifier
    if not vpn_connection_id:
        formatted_filter = create_filter(module_params, provided_filters=filters)

    # see if there is a unique matching connection
    try:
        if vpn_connection_id:
            existing_conn = connection.describe_vpn_connections(DryRun=check_mode,
                                                                VpnConnectionIds=vpn_connection_id,
                                                                Filters=formatted_filter)
        else:
            existing_conn = connection.describe_vpn_connections(DryRun=check_mode,
                                                                Filters=formatted_filter)
    except botocore.exceptions.ClientError as e:
        raise VPNConnectionException(msg="Failed while describing VPN connection.", exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    return find_connection_response(connections=existing_conn)


def add_routes(connection, vpn_connection_id, routes_to_add, check_mode):
    if check_mode:
        return

    try:
        for route in routes_to_add:
            response = connection.create_vpn_connection_route(VpnConnectionId=vpn_connection_id,
                                                              DestinationCidrBlock=route)
    except botocore.exceptions.ClientError as e:
        raise VPNConnectionException(msg="Failed while adding routes to the VPN connection.",
                                     exception=traceback.format_exc(), response=e.response)


def remove_routes(connection, vpn_connection_id, routes_to_remove, check_mode):
    if check_mode:
        return
    try:
        for route in routes_to_remove:
            response = connection.delete_vpn_connection_route(VpnConnectionId=vpn_connection_id,
                                                              DestinationCidrBlock=route)
    except botocore.exceptions.ClientError as e:
        raise VPNConnectionException(msg="Failed while adding routes to VPN connection.",
                                     exception=traceback.format_exc(), response=e.response)


def create_filter(module_params, provided_filters):
    ''' Creates a filter using the user-specified parameters and unmodifiable options that may have been specified in the task '''
    boto3ify_filter = {'cgw-config': 'customer-gateway-configuration',
                       'static-routes-only': 'option.static-routes-only',
                       'cidr': 'route.destination-cidr-block',
                       'bgp': 'bgp-asn',
                       'vpn': 'vpn-connection-id',
                       'vgw': 'vpn-gateway-id',
                       'tag-keys': 'tag-key',
                       'tag-values': 'tag-value',
                       'tags': 'tag',
                       'cgw': 'customer-gateway-id'}

    # unmodifiable options and their filter name counterpart
    param_to_filter = {"customer_gateway_id": "customer-gateway-id",
                       "vpn_gateway_id": "vpn-gateway-id",
                       "vpn_connection_id": "vpn-connection-id"}

    flat_filter_dict = {}
    formatted_filter = []

    for raw_param in dict(provided_filters):

        # fix filter names to be recognized by boto3
        if raw_param in boto3ify_filter:
            param = boto3ify_filter[raw_param]
            provided_filters[param] = provided_filters[raw_param]
            del provided_filters[raw_param]
        elif raw_param in list(boto3ify_filter.items()):
            param = raw_param
        else:
            raise VPNConnectionException(msg="%s is not a valid filter." % raw_param)

        # reformat filters with special formats
        if param == 'tag':
            for key in provided_filters[param]:
                formatted_key = 'tag:' + key
                if isinstance(provided_filters[param][key], list):
                    flat_filter_dict[formatted_key] = str(provided_filters[param][key])
                else:
                    flat_filter_dict[formatted_key] = [str(provided_filters[param][key])]
        elif param == 'option.static-routes-only':
            flat_filter_dict[param] = [str(provided_filters[param]).lower()]
        else:
            if isinstance(provided_filters[param], list):
                flat_filter_dict[param] = provided_filters[param]
            else:
                flat_filter_dict[param] = [str(provided_filters[param])]

    # if customer_gateway, vpn_gateway, or vpn_connection was specified in the task but not the filter, add it
    for param in param_to_filter:
        if param_to_filter[param] not in flat_filter_dict and module_params.get(param):
            flat_filter_dict[param_to_filter[param]] = [module_params.get(param)]

    # change the flat dict into something boto3 will understand
    formatted_filter = [{'Name': key, 'Values': flat_filter_dict[key]} for key in flat_filter_dict]

    return formatted_filter


def find_connection_response(connections=None):
    ''' Determine if there is a viable unique match in the connections described. Returns the unique VPN connection if one is found,
        returns None if the connection does not exist, raise an error if multiple matches are found. '''

    # Found no connections
    if not connections or 'VpnConnections' not in connections:
        return None

    # Too many results
    elif connections and len(connections['VpnConnections']) > 1:
        viable = []
        for each in connections['VpnConnections']:
            # deleted connections are not modifiable
            if each['State'] not in ("deleted", "deleting"):
                viable.append(each)
        if len(viable) == 1:
            # Found one viable result; return unique match
            return viable[0]
        elif len(viable) == 0:
            # Found a result but it was deleted already; since there was only one viable result create a new one
            return None
        else:
            raise VPNConnectionException(msg="More than one matching VPN connection was found. "
                                         "To modify or delete a VPN please specify vpn_connection_id or add filters.")

    # Found unique match
    elif connections and len(connections['VpnConnections']) == 1:
        # deleted connections are not modifiable
        if connections['VpnConnections'][0]['State'] not in ("deleted", "deleting"):
            return connections['VpnConnections'][0]
        # Found the result but it was deleted already; since there was only one result create a new one
        else:
            return None

    # Matches were an empty list
    else:
        return None


def create_connection(connection, customer_gateway_id, static_only, vpn_gateway_id, connection_type, check_mode):
    ''' Creates a VPN connection '''
    if not (customer_gateway_id and vpn_gateway_id):
        raise VPNConnectionException(msg="No matching connection was found. To create a new connection you must provide "
                                     "both vpn_gateway_id and customer_gateway_id.")
    try:
        vpn = connection.create_vpn_connection(DryRun=check_mode,
                                               Type=connection_type,
                                               CustomerGatewayId=customer_gateway_id,
                                               VpnGatewayId=vpn_gateway_id,
                                               Options={'StaticRoutesOnly': static_only})
    except botocore.exceptions.ClientError as e:
        raise VPNConnectionException(msg="Failed to create VPN connection: %s" % e.message, exception=traceback.format_exc(), response=e.response)

    return vpn['VpnConnection']


def delete_connection(connection, vpn_connection_id, check_mode):
    ''' Deletes a VPN connection '''
    try:
        connection.delete_vpn_connection(DryRun=check_mode,
                                         VpnConnectionId=vpn_connection_id)
    except botocore.exceptions.ClientError as e:
        raise VPNConnectionException(msg="Failed to delete the VPN connection: %s" % e.message, exception=traceback.format_exc(), response=e.response)


def add_tags(connection, vpn_connection_id, add, check_mode):
    try:
        connection.create_tags(DryRun=check_mode,
                               Resources=[vpn_connection_id],
                               Tags=add)
        #                       Tags=ansible_dict_to_boto3_tag_list(add))
    except botocore.exceptions.ClientError as e:
        raise VPNConnectionException(msg="Failed to add the tags: %s." % add,
                                     exception=traceback.format_exc(), response=e.response)


def remove_tags(connection, vpn_connection_id, remove, check_mode):
    # format tags since they are a list in the format ['tag1', 'tag2', 'tag3']
    key_dict_list = [{'Key': tag} for tag in remove]
    try:
        connection.delete_tags(DryRun=check_mode,
                               Resources=[vpn_connection_id],
                               Tags=key_dict_list)
        #                       Tags=ansible_dict_to_boto3_tag_list(remove))
    except botocore.exceptions.ClientError as e:
        raise VPNConnectionException(msg="Failed to remove the tags: %s." % remove,
                                     exception=traceback.format_exc(), response=e.response)


def check_for_update(connection, module_params, vpn_connection_id):
    ''' Determines if there are any tags or routes that need to be updated. Ensures non-modifiable attributes aren't expected to change. '''
    tags = module_params.get('tags')
    routes = module_params.get('routes')
    purge_tags = module_params.get('purge_tags')
    purge_routes = module_params.get('purge_routes')

    vpn_connection = find_connection(connection, module_params, vpn_connection_id=vpn_connection_id)
    current_attrs = camel_dict_to_snake_dict(vpn_connection)

    # Initialize changes dict
    changes = {'tags_to_add': [],
               'tags_to_remove': [],
               'routes_to_add': [],
               'routes_to_remove': []}

    # Get changes to tags
    if 'tags' in current_attrs:
        current_tags = boto3_tag_list_to_ansible_dict(current_attrs['tags'], u'key', u'value')
        tags_to_add, changes['tags_to_remove'] = compare_aws_tags(current_tags, tags, purge_tags)
        changes['tags_to_add'] = ansible_dict_to_boto3_tag_list(tags_to_add)
    elif tags:
        current_tags = {}
        tags_to_add, changes['tags_to_remove'] = compare_aws_tags(current_tags, tags, purge_tags)
        changes['tags_to_add'] = ansible_dict_to_boto3_tag_list(tags_to_add)
    # Get changes to routes
    if 'Routes' in vpn_connection:
        current_routes = [route['DestinationCidrBlock'] for route in vpn_connection['Routes']]
        if purge_routes:
            changes['routes_to_remove'] = [old_route for old_route in current_routes if old_route not in routes]
        changes['routes_to_add'] = [new_route for new_route in routes if new_route not in current_routes]

    # Check if nonmodifiable attributes are attempted to be modified
    for attribute in current_attrs:
        if attribute in ("tags", "routes", "state"):
            continue
        elif attribute == 'options':
            will_be = module_params.get('static_only', None)
            is_now = bool(current_attrs[attribute]['static_routes_only'])
            attribute = 'static_only'
        elif attribute == 'type':
            will_be = module_params.get("connection_type", None)
            is_now = current_attrs[attribute]
        else:
            is_now = current_attrs[attribute]
            will_be = module_params.get(attribute, None)

        if will_be is not None and to_text(will_be) != to_text(is_now):
            raise VPNConnectionException(msg="You cannot modify %s, the current value of which is %s. Modifiable VPN connection "
                                         "attributes are tags and routes. The value you tried to change it to is %s." % (attribute, is_now, will_be))

    return changes


def make_changes(connection, vpn_connection_id, changes, check_mode):
    '''
    changes is a dict with the keys 'tags_to_add', 'tags_to_remove', 'routes_to_add', 'routes_to_remove',
    the values of which are lists (generated by check_for_update()).
    '''

    changed = False

    if changes['tags_to_add']:
        changed = True
        add_tags(connection, vpn_connection_id, changes['tags_to_add'], check_mode)

    if changes['tags_to_remove']:
        changed = True
        remove_tags(connection, vpn_connection_id, changes['tags_to_remove'], check_mode)

    if changes['routes_to_add']:
        changed = True
        add_routes(connection, vpn_connection_id, changes['routes_to_add'], check_mode)

    if changes['routes_to_remove']:
        changed = True
        remove_routes(connection, vpn_connection_id, changes['routes_to_remove'], check_mode)

    return changed


def ensure_present(connection, module_params):
    ''' Creates and adds tags to a VPN connection. If the connection already exists update tags. '''
    check_mode = module_params.get('check_mode')
    vpn_connection = find_connection(connection, module_params)
    changed = False

    # No match but vpn_connection_id was specified.
    if not vpn_connection and module_params.get('vpn_connection_id'):
        raise VPNConnectionException(msg="There is no VPN connection available or pending with that id. Did you delete it?")

    # Unique match was found. Check if attributes provided differ.
    elif vpn_connection:
        vpn_connection_id = vpn_connection['VpnConnectionId']
        # check_for_update returns a dict with the keys tags_to_add, tags_to_remove, routes_to_add, routes_to_remove
        changes = check_for_update(connection, module_params, vpn_connection_id)
        changed = make_changes(connection, vpn_connection_id, changes, check_mode)
        # get latest version of vpn_connection
        vpn_connection = find_connection(connection, module_params, vpn_connection_id=vpn_connection_id)

    # No match was found. Create and tag a connection and add routes.
    else:
        changed = True
        vpn_connection = create_connection(connection,
                                           customer_gateway_id=module_params.get('customer_gateway_id'),
                                           static_only=module_params.get('static_only'),
                                           vpn_gateway_id=module_params.get('vpn_gateway_id'),
                                           connection_type=module_params.get('connection_type'),
                                           check_mode=check_mode)
        changes = check_for_update(connection, module_params, vpn_connection['VpnConnectionId'])
        _ = make_changes(connection, vpn_connection['VpnConnectionId'], changes, check_mode)

    # get latest version if a change has been made and make tags output nice before returning it
    if vpn_connection:
        vpn_connection = find_connection(connection, module_params, vpn_connection['VpnConnectionId'])
        if 'Tags' in vpn_connection:
            vpn_connection['Tags'] = boto3_tag_list_to_ansible_dict(vpn_connection['Tags'])

    return changed, vpn_connection


def ensure_absent(connection, module_params):
    ''' Deletes a VPN connection if it exists. '''
    vpn_connection = find_connection(connection, module_params)

    if vpn_connection:
        delete_connection(connection, vpn_connection['VpnConnectionId'], module_params.get('check_mode'))
        changed = True
    else:
        changed = False

    return changed, {}


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            filters=dict(type='dict', default={}),
            vpn_gateway_id=dict(type='str'),
            tags=dict(default={}, type='dict'),
            check_mode=dict(default=False, type='bool'),
            connection_type=dict(default='ipsec.1', type='str'),
            static_only=dict(default=False, type='bool'),
            customer_gateway_id=dict(type='str'),
            vpn_connection_id=dict(type='str'),
            purge_tags=dict(type='bool', default=False),
            routes=dict(type='list', default=[]),
            purge_routes=dict(type='bool', default=False),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    # Retrieve any AWS settings from the environment.
    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)

    if not region:
        module.fail_json(msg="Either region or AWS_REGION or EC2_REGION environment variable or boto config aws_region or ec2_region must be set.")

    connection = boto3_conn(module, conn_type='client',
                            resource='ec2', region=region,
                            endpoint=ec2_url, **aws_connect_kwargs)

    state = module.params.get('state')
    parameters = dict(module.params)

    try:
        if state == 'present':
            changed, response = ensure_present(connection, parameters)
        elif state == 'absent':
            changed, response = ensure_absent(connection, parameters)
    except VPNConnectionException as e:
        if e.response and e.error_traceback:
            module.fail_json(msg=e.msg, exception=e.error_traceback, **camel_dict_to_snake_dict(e.response))
        elif e.error_traceback:
            module.fail_json(msg=e.msg, exception=e.error_traceback)
        else:
            module.fail_json(msg=e.msg)

    facts_result = dict(changed=changed, **camel_dict_to_snake_dict(response))

    module.exit_json(**facts_result)

if __name__ == '__main__':
    main()
