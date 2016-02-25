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
module: elastic_search
short_description: create and delete ElasticSearch clusters.
description:
  - Read the AWS Documentation for Elasticsearch Service (Amazon ES)
    U(http://aws.amazon.com/documentation/elasticsearch-service/)
version_added: "2.1"
options:
  domain_name:
    description:
      - The name of the Elasticsearch domain that you are creating.
    required: true
  instance_type:
    description:
      - The instance type for an Elasticsearch cluster.
    default: m3.medium.elasticsearch
    required: false
  count:
    description:
      - The number of instances in the specified domain cluster.
    default: 1.
    required: false
  master_enabled:
    description:
      - A boolean value to indicate whether a dedicated master node is enabled.
    required: false
  master_type:
    description:
      - The instance type for a dedicated master node.
    required: false
  master_count:
    description:
      - Total number of dedicated master nodes, active and on standby.
    required: false
  zone_aware:
    description:
      - A boolean value to indicate whether zone awareness is enabled.
      - If zone awareness is enabled, instance count should be at least 2
    required: false
  esb_options:
    description:
      - esb_enabled - Specifies whether EBS-based storage is enabled.
      - volume_type - Specifies the volume type *standard, gp2, io1).
      - size - Integer to specify the size of an EBS volume.
      - iops - Specifies the IOPD for a Provisioned IOPS EBS volume (SSD).
    default: null
    required: false
  policy:
    description:
      -  IAM access policy as a JSON-formatted string.
    required: false
  snapshot_start_hour:
    description:
      - Option to set time, in UTC format, of the daily automated snapshot.
    default: 0
    required: false
  tags:
    description:
      - Dictionary of tags to look for and apply when creating an ES cluster
    required: false
  state:
    description:
      - Creates or modifies an ElasticSearch cluster
      - Deletes an an ElasticSearch cluster
    required: false
    choices: ['present', 'absent']
    default: present
author: Mike Mochan(@mmochan)
extends_documentation_fragment: aws
'''

EXAMPLES = '''

# Complete example to create, update and delete an ElasticSearch Cluster

- name: Create Elastic Search cluster
  elastic_search:
    region: ap-southeast-2
    domain_name: infra-logs
    policy: "{{playbook_dir}}/open_access_policy.json"
    tags:
      Environment: UAT
      Owner: Infrastructure
      Role: LogStash
      Tier: Shared
    state: present
  register: elk

- name: Update ElasticSearch cluster with a bit more grunt
  elastic_search:
    region: ap-southeast-2
    domain_name: infra-logs
    instance_type: m3.medium.elasticsearch
    count: 4
    master_enabled: True
    master_type: m3.medium.elasticsearch
    master_count: 2
    zone_aware: False
    esb_options:
      esb_enabled: True
      volume_type: standard
      size: 20
      iops: 1000
    policy: "{{playbook_dir}}/open_access_policy.json"
    snapshot_start_hour: 0
    tags:
      Environment: UAT
      Owner: Infrastructure
      Role: Logging
      Tier: Shared
    state: present
  register: elk

- name: Delete Elastic Search cluster
  elastic_search:
    region: ap-southeast-2
    domain_name: infra-logs
    state: absent
  register: elk
'''

RETURN = '''
task:
  description: The result of the create, or delete action.
  returned: success
  type: dictionary
'''

try:
    import json
    import botocore
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


#Utility methods
def format_params(module):
    params = dict()
    params['DomainName'] = module.params.get('domain_name')
    params['ElasticsearchClusterConfig'] = dict()
    params['ElasticsearchClusterConfig']['InstanceType'] = module.params.get('instance_type')
    params['ElasticsearchClusterConfig']['InstanceCount'] = module.params.get('count')
    params['ElasticsearchClusterConfig']['DedicatedMasterEnabled'] = bool(module.params.get('master_enabled'))
    if module.params.get('master_type'):
        params['ElasticsearchClusterConfig']['DedicatedMasterType'] = module.params.get('master_type')
    if module.params.get('master_count'):
        params['ElasticsearchClusterConfig']['DedicatedMasterCount'] = int(module.params.get('master_count'))
    params['ElasticsearchClusterConfig']['ZoneAwarenessEnabled'] = module.params.get('zone_aware')

    if module.params.get('esb_options'):
        params['EBSOptions'] = dict()
        esb_options = module.params.get('esb_options')
        params['EBSOptions']['EBSEnabled'] = bool(esb_options['esb_enabled'])
        params['EBSOptions']['VolumeType'] = esb_options['volume_type']
        params['EBSOptions']['VolumeSize'] = int(esb_options['size'])
        if esb_options['volume_type'] == 'io1':
            params['EBSOptions']['Iops'] = int(esb_options['iops'])

    policy = open(module.params.get('policy')).read().replace('\n', '')
    params['AccessPolicies'] = policy
    params['SnapshotOptions'] = dict()
    params['SnapshotOptions']['AutomatedSnapshotStartHour'] = module.params.get('snapshot_start_hour')    
    return params


def load_tags(module):
    tags = []
    if module.params.get('tags'):
        for name, value in module.params.get('tags').iteritems():
            tags.append({'Key': name, 'Value': str(value)})
        tags.append({'Key': "Name", 'Value': module.params.get('domain_name')})
    else:
        tags.append({'Key': "Name", 'Value': module.params.get('domain_name')})
    return tags


def tag_domain(create, client, module):
    domain = describe_elasticsearch_domain(client, module)
    params = dict()
    params['ARN'] = domain['DomainStatus']['ARN']
    if create:
        aws_tags = ""        
    else:
        aws_tags = list_tags(params['ARN'], client, module)['TagList']
        
    tags = module.params.get('tags')
    params['TagList'] = load_tags(module)
    if sorted(aws_tags) == sorted(params['TagList']):
        return False
    else:
        clear_tags = dict()
        clear_tags['TagKeys'] = [tag['Key'] for tag in params['TagList'] if tag['Key']]
        clear_tags['ARN'] = params['ARN']
        remove_tags(clear_tags, client, module)
        add_tags(params, client, module)
        return True


def update_domain_configuration(domain, client, module):
    requested_params = format_params(module)
    aws_params = dict()
    aws_params['DomainName'] = requested_params['DomainName']
    aws_params['ElasticsearchClusterConfig'] = domain['DomainConfig']['ElasticsearchClusterConfig']['Options']
    aws_params['EBSOptions'] = domain['DomainConfig']['EBSOptions']['Options']
    aws_params['SnapshotOptions'] = domain['DomainConfig']['SnapshotOptions']['Options']
    
    requested_policy = json.loads(requested_params['AccessPolicies'])
    requested_params.pop('AccessPolicies')
    aws_policy = json.loads(domain['DomainConfig']['AccessPolicies']['Options'])
    if (aws_policy == requested_policy) and (aws_params == requested_params):
        changed = False
        if tag_domain(False, client, module):
            changed = True
        return changed
    else:
        params = format_params(module)
        update_elasticsearch_domain_config(params, client, module)
        tag_domain(False, client, module)
        changed = True
        return changed
    return changed


#Invocation methods
def create_cluster(client, module):
    changed = False
    response = describe_elasticsearch_domains(client, module)
    if not response['DomainStatusList']:
        response = create_elasticsearch_domain(client, module)
        tag_domain(True, client, module)
        return True, "Creating a new Elastic Search Cluster"
    else:
        domain = describe_elasticsearch_domain_config(client, module)
        if update_domain_configuration(domain, client, module):
            return True, "Domain configuration updated"
        else:
            return False, "Domain configuration has not changed"        
    return changed, "Nothing happening here"


def delete_cluster(client, module):
    changed = False
    response = describe_elasticsearch_domains(client, module)
    if not response['DomainStatusList']:
        return False, "Nothing happening here"
    if response['DomainStatusList']:
        delete_elasticsearch_domain(client, module)
        result = describe_elasticsearch_domain_config(client, module)
        return True, "Deleting domain cluster"
    if response['DomainStatusList'][0]['Processing']:
        return False, "Cluster is processing at this time"


#Boto3 methods
def add_tags(params, client, module):
    try:
        return client.add_tags(**params)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def can_paginate():
    pass


def create_elasticsearch_domain(client, module):
    params = format_params(module)
    try:
        return client.create_elasticsearch_domain(**params)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def delete_elasticsearch_domain(client, module):
    name = module.params.get('domain_name')
    try:
        return client.delete_elasticsearch_domain(DomainName=name)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def describe_elasticsearch_domain(client, module):
    name = module.params.get('domain_name')
    try:
        return client.describe_elasticsearch_domain(DomainName=name)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def describe_elasticsearch_domain_config(client, module):
    name = module.params.get('domain_name')
    try:
        return client.describe_elasticsearch_domain_config(DomainName=name)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def describe_elasticsearch_domains(client, module):
    names = module.params.get('domain_name')
    try:
        return client.describe_elasticsearch_domains(DomainNames=[names])
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def list_domain_names(client, module):
    try:
        return client.list_domain_names(client)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def list_tags(arn, client, module):
    try:
        return client.list_tags(ARN=arn)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def remove_tags(params, client, module):
    try:
        return client.remove_tags(**params)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def update_elasticsearch_domain_config(params, client, module):
    try:
        return client.update_elasticsearch_domain_config(**params)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        domain_name=dict(required=False),
        instance_type=dict(default="m3.medium.elasticsearch", required=False),
        count=dict(default=1, required=False, type='int'),
        master_enabled=dict(default=False, required=False, type='bool'),
        master_type=dict(required=False),
        master_count=dict(required=False),
        zone_aware=dict(default=False, required=False, type='bool'),
        esb_options=dict(required=False, type="dict"),
        iops=dict(require=False),
        policy=dict(required=False),
        snapshot_start_hour=dict(default=0, required=False, type='int'),
        tags=dict(required=False, type='dict'),
        state=dict(default='present', choices=['present', 'absent']),
        ),
    )
    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO3:
        module.fail_json(msg='json and boto3 is required.')
    state = module.params.get('state').lower()
    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        client = boto3_conn(module, conn_type='client', resource='es', region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except botocore.exceptions.NoCredentialsError, e:
        module.fail_json(msg="Can't authorize connection - "+str(e))
    
    invocations = {
        "present": create_cluster,
        "absent": delete_cluster
    }

    (changed, results) = invocations[state](client, module)
    module.exit_json(changed=changed, results=results)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
