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

from nose.plugins.skip import SkipTest
import ansible
import os
import getpass

from mock import patch, call
from ansible.errors import AnsibleError

if PY3:
    raise SkipTest('galaxy is not ported to be py3 compatible yet')

from ansible.cli.galaxy import GalaxyCLI

class TestGalaxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Prompting the testing to provide credentials will not happen by default and is not required for most tests. This is simply an option to improve the thoroughness of testing.
        if 'GALAXY_CREDS_PROMPT' in os.environ.keys():
            try:
                #authentication may be declined and tests inhibited will be avoided
                cls.auth = True
                # using getpass to ensure tester sees message (unlike raw_input)
                cls.galaxy_username = getpass.getpass("\nPress ENTER to opt out of any of the authentication prompts.\nYour information will not be displayed.\nEnter your Ansible-Galaxy/Github username: ")
                cls.galaxy_password = getpass.getpass("Enter your Ansible-Galaxy/Github password: ")
                cls.github_token = getpass.getpass("Enter/Copy + paste Github Personal Access Token to login to Ansible-Galaxy: ")
                cls.import_repo = getpass.getpass("To test importing a role please provide the name of a valid github repo (containing a role) belonging to the username provided above: ")
            except getpass.GetPassWarning:
                cls.auth = False
        else:
            cls.auth = False    
    
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

    @patch.object(ansible.utils.display.Display, "display")  # eliminating messages flushed to screen
    def test_execute_import(self, mocked_display):
        # regardless of internet or credentials, always runs mocked-out tests to ensure correct functions are called
        # testing case when sufficient info is not provided
        gc = GalaxyCLI(args=["import"])
        with patch('sys.argv', ["-c", "username"]):
            galaxy_parser = gc.parse()
        super(GalaxyCLI, gc).run()
        gc.api = ansible.galaxy.api.GalaxyAPI(gc.galaxy)
        self.assertRaises(AnsibleError, gc.execute_import)

        # testing case when gc.options.check_status == False
        gc = GalaxyCLI(args=["import"])
        with patch('sys.argv', ["-c", "username", "password"]):
            galaxy_parser = gc.parse()
        with patch.object(ansible.galaxy.api.GalaxyAPI, "create_import_task") as mock_create_import:
            with patch.object(ansible.galaxy.api.GalaxyAPI, "get_import_task") as mock_get_import:
                mock_get_import.side_effect = [
                                                [{'summary_fields':{'task_messages':[]}, 'state':'SUCCESS'}]
                                                ]
                super(GalaxyCLI, gc).run()
                gc.api = ansible.galaxy.api.GalaxyAPI(gc.galaxy)
                completed = gc.execute_import()
                self.assertTrue(completed == 0)
                mock_create_import.assert_called_once_with('username', 'password', reference=None)
        
        # testing case when gc.option.check_status == True
        gc = GalaxyCLI(args=["import"])
        with patch('sys.argv', ["-c", "username", "password"]):
            galaxy_parser = gc.parse()
        gc.options.check_status = True
        with patch.object(ansible.galaxy.api.GalaxyAPI, "get_import_task") as mock_get_import:
            mock_get_import.side_effect = [
                                            [{'id':'ID'}],
                                            [{'summary_fields':{'task_messages':[]}, 'state':'SUCCESS'}]
                                            ]                                
            super(GalaxyCLI, gc).run()
            gc.api = ansible.galaxy.api.GalaxyAPI(gc.galaxy)
            completed = gc.execute_import()
            self.assertTrue(completed == 0)
            mock_get_import.assert_called_with(task_id='ID')

        # This test requires internet connection. Using try/except to ensure internet is working rather than fail tests requiring connection while offline.
        try:
            # import tests require credentials
            if self.auth:
                logged_in = False

                ### setting up - trying to login; required to test import ###
                gc = GalaxyCLI(args=["login"])
                if self.galaxy_username and self.galaxy_password:
                    with patch('sys.argv', ["-c", self.galaxy_username, self.galaxy_password]):
                        galaxy_parser = gc.parse()
                    # patching because we only ask once for authentication
                    with patch('__builtin__.raw_input', return_value= self.galaxy_username):
                        with patch('getpass.getpass', return_value=self.galaxy_password):
                            gc.run()
                            logged_in = True
                elif self.github_token:
                    with patch('sys.argv', ["-c", "--github-token", self.github_token]):
                        galaxy_parser = gc.parse()
                    gc.run()
                    logged_in = True

                ### running tests if setup was successful ###
                if logged_in:
                    # testing with correct arguments if possible
                    if self.galaxy_username and self.import_repo:  # tests fail if invalid credentials are provided by the tester

                        # testing when gc.options.check_status == False and gc.options.wait == True
                        gc.args = ["import"]
                        with patch('sys.argv', ["-c", self.galaxy_username, self.import_repo]):
                            galaxy_parser = gc.parse()
                        super(GalaxyCLI, gc).run()
                        gc.api = ansible.galaxy.api.GalaxyAPI(gc.galaxy)
                        completed = gc.execute_import()
                        self.assertTrue(completed==0)
    
                        # testing when gc.options.check_status == False and gc.options.wait == False
                        gc.args = ["import"]
                        with patch('sys.argv', ["-c", self.galaxy_username, self.import_repo]):
                            galaxy_parser = gc.parse()
                        gc.options.wait = False
                        super(GalaxyCLI, gc).run()
                        gc.api = ansible.galaxy.api.GalaxyAPI(gc.galaxy)
                        completed = gc.execute_import()
                        self.assertTrue(completed==0)

                        # testing when gc.options.check_status == True
                        gc.args = ["import"]
                        with patch('sys.argv', ["-c", self.galaxy_username, self.import_repo]):
                            galaxy_parser = gc.parse()
                        gc.options.check_status = True
                        super(GalaxyCLI, gc).run()
                        gc.api = ansible.galaxy.api.GalaxyAPI(gc.galaxy)
                        completed = gc.execute_import()
                        self.assertTrue(completed==0)

        except (SSLValidationError, AnsibleError) as e:
            if str(e) == "Bad credentials":
                raise
            elif "Failed to get data from the API server" or "Failed to validate the SSL certificate" in e.message:
                raise SkipTest(' there is a test case within this method that requires an internet connection and a valid CA certificate installed; this part of the method is skipped when one or both of these requirements are not provided\n ... ok ')
            else:
                raise
