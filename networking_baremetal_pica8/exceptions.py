#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib import exceptions as n_exc


class DriverEntrypointLoadError(n_exc.NeutronException):
    message = 'Failed to load entrypoint %(entry_point)s: %(err)s'


class DriverValidationError(n_exc.NeutronException):
    message = 'Failed driver validation for device %(device)s: %(err)s'


class DeviceConnectionError(n_exc.NeutronException):
    message = 'Driver failed connecting to device %(device)s: %(err)s'


class PreConfiguredAggrergateNotFound(n_exc.NeutronException):
    message = ('Driver could not find the aggregate ID for the pre-configured '
               'link aggregate for links %(links)s on device %(device)s.')
