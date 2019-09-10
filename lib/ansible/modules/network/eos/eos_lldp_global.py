#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#############################################
#                WARNING                    #
#############################################
#
# This file is auto generated by the resource
#   module builder playbook.
#
# Do not edit this file manually.
#
# Changes to this file will be over written
#   by the resource module builder.
#
# Changes should be made in the model used to
#   generate this file or in the resource module
#   builder template.
#
#############################################

"""
The module file for eos_lldp_global
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'network'
}

DOCUMENTATION = """
---
module: eos_lldp_global
version_added: 2.9
short_description: Manage Global Link Layer Discovery Protocol (LLDP) settings on Arista EOS devices.
description:
  - This module manages Global Link Layer Discovery Protocol (LLDP) settings on Arista EOS devices.
author: Nathaniel Case (@Qalthos)
options:
  config:
    description: The provided global LLDP configuration.
    type: dict
    suboptions:
      holdtime:
        description:
          - Specifies the holdtime (in sec) to be sent in packets.
        type: int
      reinit:
        description:
          - Specifies the delay (in sec) for LLDP initialization on any interface.
        type: int
      timer:
        description:
          - Specifies the rate at which LLDP packets are sent (in sec).
        type: int
      tlv_select:
        description:
          - Specifies the LLDP TLVs to enable or disable.
        type: dict
        suboptions:
          link_aggregation:
            description:
              - Enable or disable link aggregation TLV.
            type: bool
          management_address:
            description:
              - Enable or disable management address TLV.
            type: bool
          max_frame_size:
            description:
              - Enable or disable maximum frame size TLV.
            type: bool
          port_description:
            description:
              - Enable or disable port description TLV.
            type: bool
          system_capabilities:
            description:
              - Enable or disable system capabilities TLV.
            type: bool
          system_description:
            description:
              - Enable or disable system description TLV.
            type: bool
          system_name:
            description:
              - Enable or disable system name TLV.
            type: bool
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
    - merged
    - replaced
    - deleted
    default: merged
"""
EXAMPLES = """
# Using merged
#
# ------------
# Before State
# ------------
#
# veos# show run | section lldp
# lldp timer 3000
# lldp holdtime 100
# lldp reinit 5
# no lldp tlv-select management-address
# no lldp tlv-select system-description

- name: Merge provided LLDP configuration with the existing configuration
  eos_lldp_global:
    config:
      holdtime: 100
      tlv_select:
        management_address: False
        port_description: False
        system_description: True
    state: merged

# -----------
# After state
# -----------
#
# veos# show run | section lldp
# lldp timer 3000
# lldp holdtime 100
# lldp reinit 5
# no lldp tlv-select management-address
# no lldp tlv-select port-description


# Using replaced
#
# ------------
# Before State
# ------------
#
# veos# show run | section lldp
# lldp timer 3000
# lldp holdtime 100
# lldp reinit 5
# no lldp tlv-select management-address
# no lldp tlv-select system-description

- name: Replace existing LLDP device configuration with provided configuration
  eos_lldp_global:
    config:
      holdtime: 100
      tlv_select:
        management_address: False
        port_description: False
        system_description: True
    state: replaced

# -----------
# After state
# -----------
#
# veos# show run | section lldp
# lldp holdtime 100
# no lldp tlv-select management-address
# no lldp tlv-select port-description


# Using deleted
#
# ------------
# Before State
# ------------
#
# veos# show run | section lldp
# lldp timer 3000
# lldp holdtime 100
# lldp reinit 5
# no lldp tlv-select management-address
# no lldp tlv-select system-description

- name: Delete existing LLDP configurations from the device
  eos_lldp_global:
    state: deleted

# -----------
# After state
# -----------
#
# veos# show run | section ^lldp


"""
RETURN = """
before:
  description: The configuration as structured data prior to module invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['lldp holdtime 100', 'no lldp timer', 'lldp tlv-select system-description']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.eos.argspec.lldp_global.lldp_global import Lldp_globalArgs
from ansible.module_utils.network.eos.config.lldp_global.lldp_global import Lldp_global


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Lldp_globalArgs.argument_spec,
                           supports_check_mode=True)

    result = Lldp_global(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
