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
DOCUMENTATION = '''
module: ec2_vpc_dhcp_options
short_description: Create, delete, update dhcp_options_sets.
  Requires Boto3, botocore and json.
description:
  - Read the AWS documentation for DHCP Options Sets for the correct json Values
    U(http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_DHCP_Options.html)
  - It is not possible to update an existing dhcp_options_set therefore any
    changes require the old one to be deleted and a new one to be created
  - If the old dhcp_option_set is associated with a VPC or multiple VPCs
    this association will be re-created for the new / updated dhcp_option_set.
version_added: "2.1"
  state:
    description:
      - present to ensure resource is created or updated.
      - absent to remove resource
    required: false
    default: present
    choices: [ "present", "absent"]
  name:
    description:
      - Name Tag used for tagging and identifying the resource
    required: true
  domain_name:
    description:
      - If you're using AmazonProvidedDNS in us-east-1, specify ec2.internal.
        If you're using AmazonProvidedDNS in another region, specify
        region.compute.internal
        Otherwise, specify a domain name (for example, MyCompany.com).
    required false
  tags:
    description:
      - List of Tags
    required: false
  domain_name_servers:
    description:
      - The IP addresses of up to four domain name servers
    required: false
  ntp_servers:
    description:
      - The IP addresses of up to four Network Time Protocol (NTP) servers.
    requied: false
  netbios_name_servers:
    description:
      - The IP addresses of up to four NetBIOS name servers.
    required: false
  netbios_node_type:
    description:
      - The NetBIOS node type (1, 2, 4, or 8).
        AWS recommends that you specify 2.
    required: false
author: Mike Mochan(@mmochan)
extends_documentation_fragment: aws
'''

EXAMPLES = '''
# Complete example to create or update with all options specified.
- name: Create DHCP Options
  ec2_vpc_dhcp_options:
    state: present
    region: ap-southeast-2
    name: dhcp-vpc01-x-business
    domain_name:
      - my.aws.com.au
      - my.company.com.au
      - ap-southeast-2.compute.internal
    tags:
      CostCode: x-business
      Project: X
      Vpc: '01'
    domain_name_servers:
      - 192.168.1.1
      - 192.168.9.32
    ntp_servers:
      - 192.168.1.100
    netbios_name_servers:
      - 192.155.44.34
    netbios_node_type: 2
  register: dhcp

# Update the Tags.
- name: Update DHCP Options Tags
  ec2_vpc_dhcp_options:
    state: present
    region: ap-southeast-2
    name: dhcp-vpc01-x-business
    tags:
      CostCode: y-business
      Project: Y
      Vpc: '10'
  register: dhcp

# Example to delete.
- name: Create DHCP Options
  ec2_vpc_dhcp_options:
    state: absent
    region: ap-southeast-2
    name: dhcp-vpc01-x-business
  register: dhcp
'''

RETURN = '''
task:
  description: details about the tast that was started
  type: complex
  sample: "TODO: include sample"
'''
try:
   import json
   import botocore
   import boto3
   HAS_BOTO3 = True
except ImportError:
   HAS_BOTO3 = False

import time


def load(module):
    params = []
    if module.params.get('domain_name'):
        params.append({'Key': 'domain-name',
                       'Values': module.params.get('domain_name')})
    if module.params.get('domain_name_servers'):
        params.append({'Key': 'domain-name-servers',
                       'Values': module.params.get('domain_name_servers')})
    if module.params.get('ntp_servers'):
        params.append({'Key': 'ntp-servers',
                       'Values': module.params.get('ntp_servers')})
    if module.params.get('netbios_name_servers'):
        params.append({'Key': 'netbios-name-servers',
                       'Values': module.params.get('netbios_name_servers')})
    if module.params.get('netbios_node_type'):
        params.append({'Key': 'netbios-node-type',
                       'Values': module.params.get('netbios_node_type')})
    return params


def configuration_present(client, name):
    return client.describe_dhcp_options(Filters=[{'Name': 'tag:Name',
                                                  'Values': [name]}])


def has_changed(option_set, module):
    current_options = option_set['DhcpOptions'][0]['DhcpConfigurations']
    current_tags = option_set['DhcpOptions'][0]['Tags']
    included_params = [params['Key'] for params in load(module)]
    existing_params = [keys['Key'] for keys in current_options]
    content = []
    if not included_params:
        module.fail_json(msg="One of the Option names must be supplied [domain_name, domain_name_servers, ntp_servers, netbios_name_servers, netbios_node_type]")

    if sorted(included_params) != sorted(existing_params):
        return True
    if sorted(existing_params) != sorted(included_params):
        return True
    for entry in current_options:
        for val in entry['Values']:
            content.append(val['Value'])
        module_param = module.params.get(entry['Key'].replace("-", "_"))
        if module_param:
            if sorted(content) != sorted(module_param):
                return True
        content = []
    tags = {}
    for tag in current_tags:
        tags[tag["Key"]] = tag["Value"]
    tags.pop("Name")
    if tags != module.params.get('tags'):
        return True
    return False


def create_dhcp_options(client, resource, module):
    try:
        changed = True
        response = client.create_dhcp_options(DhcpConfigurations=load(module))
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))
    create_tags(resource, module, response['DhcpOptions']['DhcpOptionsId'])
    return (changed, response['DhcpOptions']['DhcpOptionsId'])


def create_tags(resource, module, dhcp_id):
    tag_array = []
    if module.params.get('tags'):
        for tag, value in module.params.get('tags').iteritems():
            tag_array.append({'Key': tag, 'Value': value})
        tag_array.append({'Key': "Name", 'Value': module.params.get('name')})
        dhcp_options = resource.DhcpOptions(dhcp_id)
        try:
            dhcp_options.create_tags(Tags=tag_array)
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=str(e))
    else:
        tag_array.append({'Key': "Name", 'Value': module.params.get('name')})
        dhcp_options = resource.DhcpOptions(dhcp_id)
        try:
            dhcp_options.create_tags(Tags=tag_array)
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=str(e))


def associated_vpcs(client, dhcp_id):
    response = client.describe_vpcs(Filters=[{'Name': "dhcp-options-id",
                                              'Values': [dhcp_id]}])
    return response['Vpcs']


def associate_dhcp_options(resource, vpc, dhcp):
    vpc = resource.Vpc(vpc['VpcId'])
    try:
        vpc.associate_dhcp_options(DhcpOptionsId=dhcp)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def delete_dhcp_options(client, module, dhcp):
    try:
        return client.delete_dhcp_options(DhcpOptionsId=dhcp)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def update(client, resource, module, option_set):
    dhcp = resource.DhcpOptions(option_set['DhcpOptions'][0]['DhcpOptionsId'])
    vpcs = associated_vpcs(client, dhcp.id)
    for vpc in vpcs:
        associate_dhcp_options(resource, vpc, "default")
    delete_dhcp_options(client, module, dhcp.id)
    dhcp_id = create_dhcp_options(client, resource, module)[-1]
    create_tags(resource, module, dhcp_id)
    for vpc in vpcs:
        associate_dhcp_options(resource, vpc, dhcp_id)
    changed = True
    return (changed, dhcp_id)


def setup(client, resource, module):
    option_set = configuration_present(client, module.params.get('name'))
    if len(option_set['DhcpOptions']) > 1:
        module.fail_json(msg="WARNING - Found duplicate DHCP Options Set")
    if not option_set['DhcpOptions']:
        (changed, results) = create_dhcp_options(client, resource, module)
        return (changed, results)
    if has_changed(option_set, module) is True:
        (changed, results) = update(client, resource, module, option_set)
        return (changed, results)
    else:
        changed = False
        results = option_set['DhcpOptions'][0]['DhcpOptionsId']
        return (changed, results)


def remove(client, resource, module):
    option_set = configuration_present(client, module.params.get('name'))
    dhcp_id = option_set['DhcpOptions'][0]['DhcpOptionsId']
    if option_set['DhcpOptions']:
        dhcp = resource.DhcpOptions(dhcp_id)
        vpcs = associated_vpcs(client, dhcp.id)
        for vpc in vpcs:
            associate_dhcp_options(resource, vpc, "default")
        results = delete_dhcp_options(client, module, dhcp.id)
        return (True, results)
    changed = False
    results = "Nothing to see here"
    return (changed, results)


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        state=dict(default='present', choices=['present', 'absent']),
        name=dict(required=True),
        region=dict(required=True),
        tags=dict(),
        domain_name=dict(),
        domain_name_servers=dict(),
        name_servers=dict(),
        ntp_servers=dict(),
        netbios_name_servers=dict(),
        netbios_node_type=dict(type="list")
        )
    )
    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO3:
        module.fail_json(msg='json and boto3 is required.')

    state = module.params.get('state').lower()

    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        client = boto3_conn(module, conn_type='client', resource='ec2', region=region, endpoint=ec2_url, **aws_connect_kwargs)
        resource = boto3_conn(module, conn_type='resource', resource='ec2', region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except botocore.exceptions.NoCredentialsError, e:
        module.fail_json(msg="Can't authorize connection - "+str(e))

    if state == 'present':
        (changed, results) = setup(client, resource, module)
    else:
        (changed, results) = remove(client, resource, module)
    module.exit_json(changed=changed, dhcp_option_result=results)


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()