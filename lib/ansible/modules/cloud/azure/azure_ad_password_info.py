#!/usr/bin/python
#
# Copyright (c) 2020 Haiyuan Zhang, <haiyzhan@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import datetime
from dateutil.relativedelta import  relativedelta

__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: azure_ad_password_info

version_added: "2.10"

short_description: Get Azure Active Directory Password info

description:
        - Get Azure Active Directory Password value.

options:
    app_id:
        description:
            - Application ID.
        type: str
    service_principal_object_id:
        description:
            - The service principal's ID or Object ID.
        type: str
    key_id:
        description:
            - Kye ID.
        type: str
    tenant:
        description:
            - The tenant ID.
        type: str
            required: True
    end_date:
        description:
            - End date.
        type: datetime
    value:
        description:
            - Password value.
        type: str
    app_object_id:
        description:
            - Application object ID.
        type: str

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    haiyuan_zhang (@haiyuazhang)
'''

EXAMPLES = '''
  - name: get ad pass word info
    azure_ad_password_info:
      app_id: "{{ app_id }}"
      tenant: "{{ tenant_id }}"
      key_id: "{{ key_id }}"
'''

RETURN = '''
passwords:
    description:
        - Password info.
    returned: success
    type: complex
    contains:
        custom_key_identifier:
            description:
                - Custom key identifier.
            type: str
            returned: always
            sample: None
        end_date:
            description:
                - End date.
            type: str
            returned: always
            sample: 2021-06-18T06:51:25.508304+00:00
        key_id:
            description:
                - Key ID.
            type: str
            returned: always
            sample: d33d730d-63e6-45f9-b165-eb723dfa10cd
        start_date:
            description:
                - Start date.
            type: str
            returned: always
            sample: 2020-06-18T06:51:25.508304+00:00

'''

from ansible.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.graphrbac.models import GraphErrorException
    from azure.graphrbac.models import PasswordCredential
    from azure.graphrbac.models import ApplicationUpdateParameters
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureADPasswordInfo(AzureRMModuleBase):
    def __init__(self):

        self.module_arg_spec = dict(
            app_id=dict(type='str'),
            app_object_id=dict(type='str'),
            service_principal_object_id=dict(type='str'),
            key_id=dict(type='str'),
            tenant=dict(type='str', required=True),
            value=dict(type='str'),
            end_date=dict(type='str'),
        )

        self.tenant = None
        self.app_id = None
        self.service_principal_object_id = None
        self.app_object_id = None
        self.key_id = None
        self.value = None
        self.end_date = None
        self.results = dict(changed=False)

        self.client = None

        super(AzureADPasswordInfo, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                  supports_check_mode=False,
                                                  supports_tags=False,
                                                  is_ad_resource=True)
                                            
    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        self.client = self.get_graphrbac_client(self.tenant)
        self.resolve_app_obj_id()
        passwords = self.get_all_passwords()

        if self.key_id:
            filtered = [ pd for pd in passwords if pd.key_id == self.key_id]
            self.results['passwords'] = [ self.to_dict(pd) for pd in filtered]
        else:
            self.results['passwords'] = [ self.to_dict(pd) for pd in passwords]

        return self.results

    def resolve_app_obj_id(self):
        try:
            if self.app_object_id is not None:
                return
            elif self.app_id or self.service_principal_object_id:
                if not self.app_id:
                    sp = self.client.service_principals.get(self.service_principal_id)
                    self.app_id = sp.app_id
                if not self.app_id:
                    self.fail("can't resolve app via service principal object id {0}".format(self.service_principal_object_id))

                result = list(self.client.applications.list(filter="appId eq '{}'".format(self.app_id)))
                if result:
                    self.app_object_id = result[0].object_id
                else:
                    self.fail("can't resolve app via app id {0}".format(self.app_id))
            else:
                self.fail("one of the [app_id, app_object_id, service_principal_id] must be set")

        except GraphErrorException as ge:
            self.fail("error in resolve app_object_id {0}".format(str(ge)))

    def get_all_passwords(self):

        try:
            return list(self.client.applications.list_password_credentials(self.app_object_id))
        except GraphErrorException as ge:
            self.fail("failed to fetch passwords for app {0}: {1".format(self.app_object_id,str(ge)))

    @staticmethod
    def to_dict(pd):
        return dict(
            end_date=pd.end_date,
            start_date=pd.start_date,
            key_id=pd.key_id,
            custom_key_identifier=str(pd.custom_key_identifier)
        )

def main():
    AzureADPasswordInfo()

if __name__ == '__main__':
    main()
