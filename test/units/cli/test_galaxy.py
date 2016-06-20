# (c) 2016, Adrian Likins <alikins@redhat.com>
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

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.compat.six import PY3
from ansible.compat.tests import unittest

from ansible.galaxy.token import GalaxyToken  # added this
from ansible.cli import CLI  # added this
from mock import patch
from mock import MagicMock
import ansible
from ansible.errors import AnsibleError, AnsibleOptionsError


try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

from nose.plugins.skip import SkipTest

if PY3:
    raise SkipTest('galaxy is not ported to be py3 compatible yet')

from ansible.cli.galaxy import GalaxyCLI

class TestGalaxy(unittest.TestCase):
    def setUp(self):
        self.default_args = []

    def test_init(self):
        galaxy_cli = GalaxyCLI(args=self.default_args)
        self.assertTrue(isinstance(galaxy_cli, GalaxyCLI))

    def test_display_min(self):
        gc = GalaxyCLI(args=self.default_args)
        role_info = {'name': 'some_role_name'}
        display_result = gc._display_role_info(role_info)
        self.assertTrue(display_result.find('some_role_name') >-1)

    def test_display_galaxy_info(self):
        gc = GalaxyCLI(args=self.default_args)
        galaxy_info = {}
        role_info = {'name': 'some_role_name',
                     'galaxy_info': galaxy_info}
        display_result = gc._display_role_info(role_info)
        if display_result.find('\t\tgalaxy_tags:') > -1:
            self.fail('Expected galaxy_tags to be indented twice')

    def test_display_role_info(self):
        gc = GalaxyCLI(args=self.default_args)
        galaxy_info = {}
        role_info = {'name': 'foo', 'description': 'bar'}
        display_result = gc._display_role_info(role_info)
        self.assertTrue(display_result == u'\nRole: foo\n\tdescription: bar')

    @patch.object(GalaxyToken, "__init__", return_value=None)  # mocks file being opened/created
    def test_parse(self, mocked_token):
        ''' tests that a options parser is created for bin/ansible '''
        for arguments in [[], ["list", "info"], ["bad_arg", "list"], ["bad_arg", "invalid"]]:    
            gc = GalaxyCLI(args=arguments)
            
            first_arg = False
            for arg in arguments:
                if arg in gc.VALID_ACTIONS:
                    first_arg = arg  # used for testing after the parser is created
                    break  # stop searching after a valid action is found
                     
            if first_arg == False:   # a lack of valid args raises an error
                with patch('sys.argv', ["-c"]):
                    self.assertRaises(AnsibleOptionsError, gc.parse)
            else:
                with patch('sys.argv', ["-c"]): 
                    created_parser = gc.parse()
                self.assertTrue(created_parser == True)
                self.assertTrue(isinstance(gc.parser, ansible.cli.SortedOptParser))
                self.assertTrue(isinstance(gc.galaxy, ansible.galaxy.Galaxy))
                self.assertTrue(gc.action)
                self.assertTrue(gc.options.roles_path == ['/etc/ansible/roles'])
                self.assertTrue(gc.action == first_arg)
                self.assertNotIn(first_arg, arguments)

    @patch.object(GalaxyToken, "__init__", return_value=None)  # mocks file being opened/created
    def test_run(self, mocked_token):
        ''' verifies that the GalaxyCLI object's api is created and that gc.execute is called. '''
        gc = GalaxyCLI(args=["install"])
        with patch('sys.argv', ["-c", "-v", '--ignore-errors', 'imaginary_role']):
            galaxy_parser = gc.parse()
        gc.execute = MagicMock()
        with patch.object(CLI, "run", return_value=None) as mock_obj: # mocked to elimate config file message to identify whether file or default is used
            gc.run()
        self.assertTrue(gc.execute.called)
        self.assertTrue(isinstance(gc.api, ansible.galaxy.api.GalaxyAPI))

    @patch.object(GalaxyToken, "__init__", return_value=None)  # mocks file being opened/created
    def test_exit_without_ignore(self, mock):
        ''' tests that GalaxyCLI exits with the error specified '''
        gc = GalaxyCLI(args=["install"])
        with patch('sys.argv', ["-c", "-v"]):
            galaxy_parser = gc.parse()
        with patch.object(CLI, "run", return_value=None) as mock_obj:  # mocked to eliminate config file message to identify whether file or default is used
            self.assertRaises(AnsibleError, gc.run)

