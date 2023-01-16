# (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    name: prompt
    type: notification
    short_description: read from stdin
    description:
      - Read user input until a condition is met and then add it to the queue.
      - The default condition for complete input is a carriage return or newline.
      - The default interrupt condition is ctrl+C.
      - User input will be a string, or None in the case of interrupt.
    version_added: "2.15"
    options: {}
'''

from ansible.plugins.callback import CallbackBase
from ansible.utils.display import Display


display = Display()


class CallbackModule(CallbackBase):

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'prompt'
    # CALLBACK_NEEDS_ENABLED = True

    def v2_runner_on_intermediate_prompt(self, response_queue, prompt_kwargs):
        user_input = display.do_non_blocking_read_until(**prompt_kwargs)
        response_queue.put(user_input)
