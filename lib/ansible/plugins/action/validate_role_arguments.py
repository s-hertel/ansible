# Copyright: (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from os.path import basename

from ansible.errors import AnsibleError
from ansible.module_utils.six import string_types
from ansible.plugins.action import ActionBase
from ansible.playbook.role import Role
from ansible.playbook.role.include import RoleInclude
from ansible.utils.vars import combine_vars

from ansible.module_utils.common.validation import (
    check_type_bool,
    check_type_bits,
    check_type_bytes,
    check_type_float,
    check_type_int,
    check_type_jsonarg,
    check_type_list,
    check_type_dict,
    check_type_path,
    check_type_raw,
    check_type_str,
)


class ActionModule(ActionBase):

    _VALID_ARGS = frozenset(('name', 'tasks_from', 'defaults_from', 'vars_from'))

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)

        self.errors = []
        self.role_name = None

    def load_role(self):
        name = self._task.args.get('name')
        from_files = dict(
            (k.replace('_from', ''), basename(v)) for k, v in self._task.args.items() if k in ('tasks_from', 'defaults_from', 'vars_from')
        )

        if not name and self._task._role:
            name = self._task._role.get_name()
        elif not name:
            self.errors.append('A role name is required validate_role_arguments')
            return None

        if self._task._role and self._task._role.get_name() == name and not from_files:
            role = self._task._role
        else:
            ri = RoleInclude.load(
                {'name': name},
                play=self._task._parent._play,
                current_role_path=None,
                variable_manager=self._task._variable_manager,
                loader=self._task._loader,
                collection_list=self._task.collections
            )
            role = Role.load(ri, play=self._task._parent._play)
            role._from_files = from_files

        self.role_name = role.get_name()

        return role

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}

        super(ActionModule, self).run(tmp, task_vars)

        role = self.load_role()

        if self.errors:
            return {'failed': True, 'msg': 'Role argument validation failed', 'errors': self.errors}

        entry_point = role._from_files.get('tasks', 'main')
        arg_spec_for_entry = role._arg_specs.get(entry_point, {}).get('options', {})

        role_vars = combine_vars(role.get_default_vars(), role.get_vars())
        available_vars = combine_vars(role_vars, task_vars)

        self._check_options(available_vars, arg_spec_for_entry)

        if self.errors:
            return {'failed': True, 'msg': 'Role argument validation failed', 'errors': self.errors}
        elif role._arg_specs and not arg_spec_for_entry:
            err = "The role '%s' has not defined an entry in meta/arguments_spec.yml for the entry point '%s'" % (self.role_name, entry_point)
            return {'failed': True, 'msg': 'Role argument validation failed', 'errors': [err]}
        elif not role._arg_specs:
            return {'skipped': True, 'msg': "Role argument validation was skipped. No meta/argument_specs.yml defined for role '%s'" % (self.role_name)}
        else:
            return {'msg': 'Successfully validated the role arguments'}

    def _check_options(self, available_vars, specification, option_type='option'):
        # Handle deprecated options and aliases?
        # FIXME: consolidate with AnsibleModule option handler

        CHECK_ARGUMENT_TYPES_DISPATCHER = {
            'str': check_type_str,
            'list': check_type_list,
            'dict': check_type_dict,
            'bool': check_type_bool,
            'int': check_type_int,
            'float': check_type_float,
            'path': check_type_path,
            'raw': check_type_raw,
            'jsonarg': check_type_jsonarg,
            'json': check_type_jsonarg,
            'bytes': check_type_bytes,
            'bits': check_type_bits,
        }

        for option_name, option_spec in specification.items():
            required = option_spec.get('required', False)
            default = option_spec.get('default', None)
            wanted = option_spec.get('type', 'str')
            choices = option_spec.get('choices')

            value = available_vars.get(option_name)

            if required and value is None:
                self.errors.append("The {0} '{1}' is required".format(option_type, option_name))

            if value is not None:
                try:
                    # Update the role with converted values?
                    value = CHECK_ARGUMENT_TYPES_DISPATCHER.get(wanted)(value)
                except (ValueError, TypeError):
                    self.errors.append("The {0} '{1}' should be a type {2}".format(option_type, option_name, wanted))

                if choices and value not in choices:
                    self.errors.append("The {0} '{1}' should be one of {2}".format(option_type, option_name, choices))

            if wanted == 'dict':
                self._check_options(value, option_spec.get('options', {}), option_type='suboption')
            if wanted == 'list' and option_spec.get('elements') == 'dict':
                for suboption_vars in value:
                    self._check_options(suboption_vars, option_spec.get('options', {}), option_type='suboption')
