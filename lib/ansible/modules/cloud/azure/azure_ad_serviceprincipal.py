#!/usr/bin/python
#
# Copyright (c) 2020 Haiyuan Zhang, <haiyzhan@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: azure_ad_serviceprincipal

version_added: "2.10"

short_description: Manage Azure Active Directory Password

description:
        - Manage Azure Active Directory Password.

options:
    app_id:
        description:
            - Application ID.
        type: str
        required: True
    tenant:
        description:
            - The tenant ID.
        type: str
        required: True
    app_role_assignment_required:
        description:
            -  
        type: bool
    state:
        description:
            - Assert the state of Active Dirctory service principal.
            - Use C(present) to create or update a Password and use C(absent) to delete.
        default: present
        choices:
            - absent
            - present
        type: str

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    haiyuan_zhang (@haiyuazhang)

'''

EXAMPLES = '''
  - name: create ad sp
    azure_ad_serviceprincipal:
      app_id: "{{ app_id }}"
      state: present
      tenant: "{{ tenant_id }}"
'''

RETURN = '''
app_display_name:
    description:
        - App name.
    type: str
    returned: always
    sample: fredAKSCluster
app_id:
    description:
        - App ID.
    returned: always
    type: str
    sample: b6d3cf80-a95d-4c0c-bfc5-a63f08a1c301
app_role_assignment_required:
    description:
        - Require or not of app role assignment.
    returned: always
    type: bool
    sample: false
object_id:
    description:
        - Object ID.
    returned: always
    type: str
    sample: c45fae27-41ef-43c1-a2de-99f507247c13

'''

from ansible.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.graphrbac.models import GraphErrorException
except ImportError:
    # This is handled in azure_rm_common
    pass

class Actions:
    NoAction, Create, Update, Delete = range(4)


class AzureRMServicePrincipal(AzureRMModuleBaseExt):
    def __init__(self):

        self.module_arg_spec = dict(
            app_id=dict(type='str', required=True),
            tenant=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            app_role_assignment_required=dict(type='bool')
        )

        self.state = None
        self.tenant = None
        self.app_id = None
        self.app_role_assignment_required = None
        self.object_id = None
        self.results = dict(changed=False)

        super(AzureRMServicePrincipal, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                      supports_check_mode=False,
                                                      supports_tags=False,
                                                      is_ad_resource=True)
                                            
    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        response = self.get_resource()

        if response:
            if self.state == 'present':
                if self.check_update(response):
                    self.update_resource(response)
            elif self.state == 'absent':
                    self.delete_resource(response)
        else:
            if self.state == 'present':
                self.create_resource()
            elif self.state == 'absent':
                self.log("try to delete non exist resource")

        return self.results

    def create_resource(self):
        from azure.graphrbac.models import ServicePrincipalCreateParameters
        try:
            client = self.get_graphrbac_client(self.tenant)
            response = client.service_principals.create(ServicePrincipalCreateParameters(app_id=self.app_id, account_enabled=True))
            self.results['changed'] = True
            self.results.update(self.to_dict(response))
            return response
        except GraphErrorException as ge:
            self.fail("Error creating service principle, app id {0} - {1}".format(self.app_id), str(ge))

    def update_resource(self, old_response):
        try:
            from azure.graphrbac.models import ServicePrincipalUpdateParameters
            client = self.get_graphrbac_client(self.tenant)
            to_update = {}
            if self.app_role_assignment_required is not None:
                to_update['app_role_assignment_required'] = self.app_role_assignment_required

            client.service_principals.update(old_response['object_id'], to_update)
            self.results['changed'] = True
            self.results.update(self.get_resource())

        except GraphErrorException as ge:
            self.fail("Error deleting service principal app_id {0} - {1}".format(self.app_id, str(ge)))

    def delete_resource(self, response):
        try:
            client = self.get_graphrbac_client(self.tenant)
            client.service_principals.delete(response.get('object_id'))
            self.results['changed'] = True
            return True
        except GraphErrorException as ge:
            self.fail("Error deleting service principal app_id {0} - {1}".format(self.app_id, str(ge)))

    def get_resource(self):
        try:
            client = self.get_graphrbac_client(self.tenant)
            result = list(client.service_principals.list(filter="servicePrincipalNames/any(c:c eq '{}')".format(self.app_id)))
            if not result:
                return False
            result = result[0]
            return self.to_dict(result)
        except GraphErrorException as ge:
            self.log("Did not find the graph instance instance {0} - {1}".format(self.app_id, str(ge)))
            return False

    def check_update(self, response):
        app_assignment_changed = self.app_role_assignment_required is not None and self.app_role_assignment_required != response.get('app_role_assignment_required', None)
        to_be_update = False or app_assignment_changed

        return to_be_update

    def to_dict(self, object):
        return dict(
            app_id = object.app_id,
            object_id = object.object_id,
            app_display_name = object.display_name,
            app_role_assignment_required= object.app_role_assignment_required
        )


def main():
    AzureRMServicePrincipal()

if __name__ == '__main__':
    main()
