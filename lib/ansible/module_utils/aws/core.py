#
#  Copyright 2017 Michael De La Rue | Ansible
#
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


"""This module adds shared support for generic Amazon AWS modules

**This code is not yet ready for use in user modules.  As of 2017**
**and through to 2018, the interface is likely to change**
**aggressively as the exact correct interface for ansible AWS modules**
**is identified.  In particular, until this notice goes away or is**
**changed, methods may disappear from the interface.  Please don't**
**publish modules using this except directly to the main Ansible**
**development repository.**

In order to use this module, include it as part of a custom
module as shown below.

  from ansible.module_utils.aws import AnsibleAWSModule
  module = AnsibleAWSModule(argument_spec=dictionary, supports_check_mode=boolean
                            mutually_exclusive=list1, required_together=list2)

The 'AnsibleAWSModule' module provides similar, but more restricted,
interfaces to the normal Ansible module.  It also includes the
additional methods for connecting to AWS using the standard module arguments

  try:
      m.aws_connect(resource='lambda') # - get an AWS connection.
  except Exception:
      m.fail_json_aws(Exception, msg="trying to connect") # - take an exception and make a decent failure


"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils.ec2 import HAS_BOTO3, camel_dict_to_snake_dict, ec2_argument_spec, boto3_conn, get_aws_connection_info
import traceback

try:
    from botocore.utils import ArgumentGenerator
    from botocore.stub import Stubber
    HAS_DIFF_REQ = True
except ImportError:
    HAS_DIFF_REQ = False

# We will also export HAS_BOTO3 so end user modules can use it.
__all__ = ('AnsibleAWSModule', 'HAS_BOTO3',)


class AnsibleAWSModule(object):
    """An ansible module class for AWS modules

    AnsibleAWSModule provides an a class for building modules which
    connect to Amazon Web Services.  The interface is currently more
    restricted than the basic module class with the aim that later the
    basic module class can be reduced.  If you find that any key
    feature is missing please contact the author/Ansible AWS team
    (available on #ansible-aws on IRC) to request the additional
    features needed.
    """
    default_settings = {
        "default_args": True,
        "check_boto3": True,
        "auto_retry": True,
        "module_class": AnsibleModule
    }

    def __init__(self, **kwargs):
        local_settings = {}
        for key in AnsibleAWSModule.default_settings:
            try:
                local_settings[key] = kwargs.pop(key)
            except KeyError:
                local_settings[key] = AnsibleAWSModule.default_settings[key]
        self.settings = local_settings

        if local_settings["default_args"]:
            # ec2_argument_spec contains the region so we use that; there's a patch coming which
            # will add it to aws_argument_spec so if that's accepted then later we should change
            # over
            argument_spec_full = ec2_argument_spec()
            try:
                argument_spec_full.update(kwargs["argument_spec"])
            except (TypeError, NameError):
                pass
            kwargs["argument_spec"] = argument_spec_full

        self._module = AnsibleAWSModule.default_settings["module_class"](**kwargs)

        if local_settings["check_boto3"] and not HAS_BOTO3:
            self._module.fail_json(
                msg='Python modules "botocore" or "boto3" are missing, please install both')

        self.check_mode = self._module.check_mode
        self._diff = self._module._diff
        self._name = self._module._name

    @property
    def params(self):
        return self._module.params

    def exit_json(self, *args, **kwargs):
        return self._module.exit_json(*args, **kwargs)

    def fail_json(self, *args, **kwargs):
        return self._module.fail_json(*args, **kwargs)

    def debug(self, *args, **kwargs):
        return self._module.debug(*args, **kwargs)

    def warn(self, *args, **kwargs):
        return self._module.warn(*args, **kwargs)

    def client(self, service):
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(self, boto3=True)
        return boto3_conn(self, conn_type='client', resource=service,
                          region=region, endpoint=ec2_url, **aws_connect_kwargs)

    def resource(self, service):
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(self, boto3=True)
        return boto3_conn(self, conn_type='resource', resource=service,
                          region=region, endpoint=ec2_url, **aws_connect_kwargs)

    def fail_json_aws(self, exception, msg=None):
        """call fail_json with processed exception

        function for converting exceptions thrown by AWS SDK modules,
        botocore, boto3 and boto, into nice error messages.
        """
        last_traceback = traceback.format_exc()

        # to_native is trusted to handle exceptions that str() could
        # convert to text.
        try:
            except_msg = to_native(exception.message)
        except AttributeError:
            except_msg = to_native(exception)

        if msg is not None:
            message = '{0}: {1}'.format(msg, except_msg)
        else:
            message = except_msg

        try:
            response = exception.response
        except AttributeError:
            response = None

        if response is None:
            self._module.fail_json(msg=message, exception=last_traceback)
        else:
            self._module.fail_json(msg=message, exception=last_traceback,
                                   **camel_dict_to_snake_dict(response))

    def call_method(self, client, method, output_to_input={}, extra_output={}, **params):
        '''
            output_to_input is a mapping of any output parameters that have a corresponding input parameter
            extra_output is a mapping of any output parameters that might have a known value but have no corresponding input - useful if a module only uses exit_json after describing a would-be created/modified thing
        '''
        if self._diff and HAS_DIFF_REQ:
            arg_gen = ArgumentGenerator()
            resp_stub = Stubber(client)
            op = client.meta.method_to_api_mapping.get(method)
            output_shape = arg_gen.generate_skeleton(client._service_model.operation_model(op).output_shape)

            # Generate response
            resp = {}
            simple_dict_output = dict(output_shape)
            for output_key in simple_dict_output.keys():
                # FIXME work with nested return structures
                if output_key in output_to_input:
                    resp[output_key] = params.get(output_to_input[output_key])
                elif output_key in extra_output:
                    resp[output_key] = extra_output[output_key]
                else:
                    resp[output_key] = simple_dict_output[output_key]

            # Validate input parameters but mock out the response
            resp_stub.add_response(method, resp)
            with resp_stub:
                return getattr(client, method)(**params)
        elif self._diff:
            self.fail_json(msg="botocore.utils and botocore.stub are required for diff mode")

        else:
            return getattr(client, method)(**params)
