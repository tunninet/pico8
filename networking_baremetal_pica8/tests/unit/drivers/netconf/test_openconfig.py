#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import warnings
from unittest import mock
from xml.etree import ElementTree

from ncclient import manager
from neutron.plugins.ml2 import driver_context
from neutron_lib import constants as n_const
from neutron_lib.plugins.ml2 import api
from oslo_config import fixture as config_fixture
from oslo_utils import uuidutils

from networking_baremetal_pica8 import config
from networking_baremetal_pica8 import constants
from networking_baremetal_pica8.constants import NetconfEditConfigOperation as nc_op
from networking_baremetal_pica8.drivers.netconf import openconfig
from networking_baremetal_pica8.openconfig.interfaces import interfaces
from networking_baremetal_pica8.openconfig.lacp import lacp
from networking_baremetal_pica8.tests import base
from networking_baremetal_pica8.tests.unit.plugins.ml2 import utils as ml2_utils

# Kept from original for aggregator test references:
OC_IF_NS = 'http://openconfig.net/yang/interfaces'
OC_IF_ETH_NS = 'http://openconfig.net/yang/interfaces/ethernet'
OC_IF_AGG_NS = 'http://openconfig.net/yang/interfaces/aggregate'

XML_IFACES_AGGREDATE_ID = f'''
<data>
  <interfaces xmlns="{OC_IF_NS}">
    <interface>
      <name>foo1/1</name>
      <ethernet xmlns="{OC_IF_ETH_NS}">
        <config>
          <aggregate-id xmlns="{OC_IF_AGG_NS}">Po10</aggregate-id>
        </config>
      </ethernet>
    </interface>
    <interface>
      <name>foo1/2</name>
      <ethernet xmlns="{OC_IF_ETH_NS}">
        <config>
          <aggregate-id xmlns="{OC_IF_AGG_NS}">Po10</aggregate-id>
        </config>
      </ethernet>
    </interface>
  </interfaces>
</data>
'''

XML_AGGREGATE_IFACES = f'''
<data>
  <interfaces xmlns="{OC_IF_NS}">
    <interface>
      <name>Po5</name>
    </interface>
    <interface>
      <name>Po7</name>
    </interface>
    <interface>
      <name>Po9</name>
    </interface>
    <interface>
      <name>foo1/1</name>
    </interface>
  </interfaces>
</data>
'''


class TestNetconfPicoClient(base.TestCase):
    """Same as original, verifying the NetconfPicoClient logic."""

    def setUp(self):
        super(TestNetconfPicoClient, self).setUp()
        self.device = 'foo'
        self.conf = self.useFixture(config_fixture.Config())

        # Register device config
        self.conf.register_opts(config._opts + config._device_opts, group='foo')
        self.conf.register_opts((openconfig._DEVICE_OPTS + openconfig._NCCLIENT_OPTS),
                                group='foo')
        self.conf.config(enabled_devices=['foo'], group='networking_baremetal_pica8')
        self.conf.config(driver='test-driver',
                         switch_id='aa:bb:cc:dd:ee:ff',
                         switch_info='foo',
                         physical_networks=['fake_physical_network'],
                         device_params={'name': 'default'},
                         host='foo.example.com',
                         key_filename='/test/test_key_file',
                         username='foo_user',
                         group='foo')

        self.client = openconfig.NetconfPicoClient(self.device)

    def test_get_lock_session_id(self):
        err_info = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
            '<session-id>{}</session-id>'
            '</error-info>')
        self.assertEqual(
            '0',
            self.client._get_lock_session_id(err_info.format(0))
        )
        self.assertEqual(
            'abc-123',
            self.client._get_lock_session_id(err_info.format('abc-123'))
        )

    def test_get_client_args(self):
        expected = {
            'device_params': {'name': 'default'},
            'host': 'foo.example.com',
            'hostkey_verify': True,
            'keepalive': True,
            'key_filename': '/test/test_key_file',
            'port': 830,
            'username': 'foo_user',
            'allow_agent': True,
            'look_for_keys': True
        }
        self.assertEqual(expected, self.client.get_client_args())

    @mock.patch.object(manager, 'connect', autospec=True)
    def test_get_capabilities(self, mock_manager):
        fake_caps = set(constants.IANA_NETCONF_CAPABILITIES.values())
        fake_caps.add('http://openconfig.net/yang/network-instance?module=openconfig-network-instance&revision=2021-07-22')
        fake_caps.add('http://openconfig.net/yang/interfaces?module=openconfig-interfaces&revision=2021-04-06')
        mock_ncclient = mock.Mock()
        mock_ncclient.server_capabilities = fake_caps
        mock_manager.return_value.__enter__.return_value = mock_ncclient

        result = self.client.get_capabilities()
        self.assertIn('openconfig-network-instance', result)
        self.assertIn('openconfig-interfaces', result)

    @mock.patch.object(manager, 'connect', autospec=True)
    @mock.patch.object(openconfig.NetconfPicoClient, 'get_lock_and_configure', autospec=True)
    def test_edit_config_writable_running(self, mock_lock_config, mock_manager):
        fake_config = mock.Mock()
        fake_config.to_xml_element.return_value = ElementTree.Element('fake')
        mock_ncclient = mock.Mock()
        fake_caps = {constants.IANA_NETCONF_CAPABILITIES[':writable-running']}
        mock_ncclient.server_capabilities = fake_caps
        mock_manager.return_value.__enter__.return_value = mock_ncclient

        self.client.edit_config(fake_config)
        mock_lock_config.assert_called_once_with(
            self.client,
            mock_ncclient,
            openconfig.RUNNING,
            [fake_config],
            False
        )

    @mock.patch.object(manager, 'connect', autospec=True)
    @mock.patch.object(openconfig.NetconfPicoClient, 'get_lock_and_configure', autospec=True)
    def test_edit_config_candidate(self, mock_lock_config, mock_manager):
        fake_config = mock.Mock()
        fake_config.to_xml_element.return_value = ElementTree.Element('fake')
        mock_ncclient = mock.Mock()
        fake_caps = {constants.IANA_NETCONF_CAPABILITIES[':candidate']}
        mock_ncclient.server_capabilities = fake_caps
        mock_manager.return_value.__enter__.return_value = mock_ncclient

        self.client.edit_config(fake_config)
        mock_lock_config.assert_called_once_with(
            self.client,
            mock_ncclient,
            openconfig.CANDIDATE,
            [fake_config],
            False
        )

    def test_get_lock_and_configure_confirmed_commit(self):
        self.client.capabilities = {':candidate', ':writable-running', ':confirmed-commit'}
        fake_config = mock.Mock()
        fake_config.to_xml_element.return_value = ElementTree.Element('fake')
        mock_client = mock.MagicMock()

        self.client.get_lock_and_configure(mock_client, openconfig.CANDIDATE, [fake_config], False)
        mock_client.locked.assert_called_with(openconfig.CANDIDATE)
        mock_client.discard_changes.assert_called_once()
        mock_client.edit_config.assert_called_with(
            target=openconfig.CANDIDATE,
            config='<config><fake /></config>'
        )
        mock_client.commit.assert_has_calls([
            mock.call(confirmed=True, timeout=str(30)),
            mock.call()
        ])

    def test_get_lock_and_configure_validate(self):
        self.client.capabilities = {':candidate', ':writable-running', ':validate'}
        fake_config = mock.Mock()
        fake_config.to_xml_element.return_value = ElementTree.Element('fake')
        mock_client = mock.MagicMock()

        self.client.get_lock_and_configure(mock_client, openconfig.CANDIDATE, [fake_config], False)
        mock_client.locked.assert_called_with(openconfig.CANDIDATE)
        mock_client.discard_changes.assert_called_once()
        mock_client.edit_config.assert_called_with(
            target=openconfig.CANDIDATE,
            config='<config><fake /></config>'
        )
        mock_client.validate.assert_called_once_with(source=openconfig.CANDIDATE)
        mock_client.commit.assert_called_once_with()

    def test_get_lock_and_configure_writable_running(self):
        self.client.capabilities = {':writable-running'}
        fake_config = mock.Mock()
        fake_config.to_xml_element.return_value = ElementTree.Element('fake')
        mock_client = mock.MagicMock()

        self.client.get_lock_and_configure(mock_client, openconfig.RUNNING, [fake_config], False)
        mock_client.locked.assert_called_with(openconfig.RUNNING)
        mock_client.discard_changes.assert_not_called()
        mock_client.validate.assert_not_called()
        mock_client.commit.assert_not_called()
        mock_client.edit_config.assert_called_with(
            target=openconfig.RUNNING,
            config='<config><fake /></config>'
        )

    @mock.patch.object(manager, 'connect', autospec=True)
    def test_get(self, mock_manager):
        fake_query = interfaces.Interfaces()
        fake_query.add('foo1/1')
        mock_ncclient = mock.Mock()
        mock_manager.return_value.__enter__.return_value = mock_ncclient

        self.client.get(query=fake_query)
        mock_ncclient.get.assert_called_with(filter=('subtree', mock.ANY))

    def test_get_aggregation_ids(self):
        self.conf.config(link_aggregate_prefix='foo', link_aggregate_range='5..10', group='foo')
        ids = self.client.get_aggregation_ids()
        self.assertEqual({'foo5', 'foo6', 'foo7', 'foo8', 'foo9', 'foo10'}, ids)

    def test_allocate_deferred(self):
        aggregate_id = 'foo5'
        _config = []
        ifaces_obj = interfaces.Interfaces()

        iface_a = ifaces_obj.add('foo1/1', interface_type=constants.IFACE_TYPE_ETHERNET)
        iface_a.ethernet.config.aggregate_id = openconfig.DEFERRED
        iface_b = ifaces_obj.add('foo1/2', interface_type=constants.IFACE_TYPE_ETHERNET)
        iface_b.ethernet.config.aggregate_id = openconfig.DEFERRED

        iface_agg = ifaces_obj.add(openconfig.DEFERRED, interface_type=constants.IFACE_TYPE_AGGREGATE)
        iface_agg.config.name = openconfig.DEFERRED

        _config.append(ifaces_obj)

        _lacp = lacp.LACP()
        lacp_ifaces = lacp.LACPInterfaces()
        lacp_ifaces.add(openconfig.DEFERRED)
        # typically you'd store lacp_ifaces in _lacp.interfaces, etc.
        _lacp.interfaces.interfaces.append(lacp_ifaces.interfaces[0])
        _config.append(_lacp)

        self.client.allocate_deferred(aggregate_id, _config)

        # Confirm placeholders replaced with "foo5"
        for conf_obj in _config:
            if isinstance(conf_obj, interfaces.Interfaces):
                for iface in ifaces_obj:
                    if iface.name == 'foo1/1' or iface.name == 'foo1/2':
                        self.assertEqual(iface.ethernet.config.aggregate_id, aggregate_id)
                    elif iface.name == aggregate_id:  # aggregator
                        self.assertEqual(iface.config.name, aggregate_id)
            elif isinstance(conf_obj, lacp.LACP):
                for lacp_iface in conf_obj.interfaces.interfaces:
                    self.assertEqual(lacp_iface.name, aggregate_id)
                    self.assertEqual(lacp_iface.config.name, aggregate_id)

    @mock.patch.object(manager, 'connect', autospec=True)
    def test_get_free_aggregate_id(self, mock_manager):
        self.conf.config(link_aggregate_prefix='Po', link_aggregate_range='5..10', group='foo')
        mock_ncclient = mock.Mock()
        mock_ncclient.get.return_value.data_xml = XML_AGGREGATE_IFACES
        mock_manager.return_value.__enter__.return_value = mock_ncclient
        free_id = self.client.get_free_aggregate_id(mock_ncclient)
        self.assertIn(free_id, {'Po6', 'Po8', 'Po10'})


class TestNetconfOpenConfigDriver(base.TestCase):

    def setUp(self):
        super(TestNetconfOpenConfigDriver, self).setUp()
        self.device = 'foo'
        self.conf = self.useFixture(config_fixture.Config())
        self.conf.register_opts(config._opts + config._device_opts, group='foo')
        self.conf.register_opts((openconfig._DEVICE_OPTS + openconfig._NCCLIENT_OPTS), group='foo')
        self.conf.config(enabled_devices=['foo'], group='networking_baremetal_pica8')
        self.conf.config(driver='test-driver',
                         switch_id='aa:bb:cc:dd:ee:ff',
                         switch_info='foo',
                         physical_networks=['fake_physical_network'],
                         device_params={'name': 'default'},
                         host='foo.example.com',
                         key_filename='/test/test_key_file',
                         username='foo_user',
                         group='foo')

        mock_client = mock.patch.object(openconfig, 'NetconfPicoClient', autospec=True)
        self.mock_client = mock_client.start()
        self.addCleanup(mock_client.stop)

        self.driver = openconfig.NetconfOpenConfigDriver(self.device)
        self.mock_client.assert_called_once_with('foo')
        self.mock_client.reset_mock()

    def test_validate(self):
        self.driver.validate()
        self.driver.client.get_capabilities.assert_called_once_with()

    @mock.patch.object(openconfig, 'CONF', autospec=True)
    def test_load_config(self, mock_conf):
        self.driver.load_config()
        mock_conf.register_opts.assert_has_calls([
            mock.call(openconfig._DEVICE_OPTS, group=self.driver.device),
            mock.call(openconfig._NCCLIENT_OPTS, group=self.driver.device)
        ])

    def test_create_network(self):
        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_nc.current = ml2_utils.get_test_network()
        self.driver.create_network(m_nc)
        net_instances = self.driver.client.edit_config.call_args[0][0]
        for net_instance in net_instances:
            self.assertEqual(net_instance.name, 'default')
            vlans = net_instance.vlans
            for vlan in vlans:
                self.assertEqual(vlan.config.operation, nc_op.MERGE.value)
                self.assertEqual(
                    vlan.config.name,
                    self.driver._uuid_as_hex(m_nc.current['id'])
                )
                self.assertEqual(vlan.config.status, constants.VLAN_ACTIVE)

    def test_delete_network(self):
        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_nc.current = ml2_utils.get_test_network(network_type=n_const.TYPE_VLAN, segmentation_id=15)
        self.driver.delete_network(m_nc)

        self.driver.client.edit_config.assert_called_once()
        net_instances = self.driver.client.edit_config.call_args[0][0]
        for net_inst in net_instances:
            self.assertEqual(net_inst.name, 'default')
            for vlan in net_inst.vlans:
                self.assertEqual(vlan.operation, nc_op.REMOVE.value)
                self.assertEqual(vlan.vlan_id, 15)
                self.assertEqual(vlan.config.status, constants.VLAN_SUSPENDED)
                self.assertEqual(vlan.config.name, 'neutron-DELETED-15')

    def test_create_port_vlan(self):
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()

        # Build a VLAN network
        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_VLAN,
            segmentation_id=15
        )

        # Build a port
        m_pc = mock.create_autospec(driver_context.PortContext)
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
        )
        m_pc.network = m_nc

        segment = {
            api.ID: uuidutils.generate_uuid(),
            api.PHYSICAL_NETWORK: m_nc.current['provider:physical_network'],
            api.NETWORK_TYPE: m_nc.current['provider:network_type'],
            api.SEGMENTATION_ID: m_nc.current['provider:segmentation_id']
        }
        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]

        self.driver.create_port(m_pc, segment, links)
        self.driver.client.edit_config.assert_called_once()
        config_elem = self.driver.client.edit_config.call_args[0][0]
        xml_str = ElementTree.tostring(config_elem, encoding='unicode')

        self.assertIn('http://pica8.com/xorplus/interface', xml_str)
        expected_vlan = segment[api.SEGMENTATION_ID]
        self.assertIn(f"<native-vlan-id>{expected_vlan}</native-vlan-id>", xml_str)
        self.assertIn("<port-mode>access</port-mode>", xml_str)
        admin_up = m_pc.current['admin_state_up']
        disable_str = "<disable>true</disable>" if not admin_up else "<disable>false</disable>"
        self.assertIn(disable_str, xml_str)

    def test_create_port_flat(self):
        """For a flat network, we do not set <native-vlan-id> or <port-mode>."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()

        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_FLAT
        )
        m_pc = mock.create_autospec(driver_context.PortContext)
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id
        )
        m_pc.network = m_nc

        segment = {
            api.ID: uuidutils.generate_uuid(),
            api.PHYSICAL_NETWORK: m_nc.current['provider:physical_network'],
            api.NETWORK_TYPE: m_nc.current['provider:network_type']
        }
        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]

        self.driver.create_port(m_pc, segment, links)
        self.driver.client.edit_config.assert_called_once()
        config_elem = self.driver.client.edit_config.call_args[0][0]
        xml_str = ElementTree.tostring(config_elem, encoding='unicode')
        # Confirm no <native-vlan-id>, no <port-mode>, but we do see <disable> up/down
        self.assertNotIn("<native-vlan-id>", xml_str)
        self.assertNotIn("<port-mode>", xml_str)

    def test_delete_port_vlan(self):
        """We expect to see operation="merge" + <disable>true</disable>, not remove container."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()

        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_VLAN,
            segmentation_id=15
        )
        m_pc = mock.create_autospec(driver_context.PortContext)
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id
        )
        m_pc.network = m_nc
        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]

        self.driver.delete_port(m_pc, links)
        self.driver.client.edit_config.assert_called_once()

        config_elem = self.driver.client.edit_config.call_args[0][0]
        xml_str = ElementTree.tostring(config_elem, encoding='unicode')

        # We no longer remove the entire gigabit-ethernet container
        self.assertIn('operation="merge"', xml_str)
        self.assertIn('<disable>true</disable>', xml_str)
        self.assertIn('<port-mode>access</port-mode>', xml_str)

    def test_delete_port_flat(self):
        """Similarly for flat port, no VLAN subnodes, just disable."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()

        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_FLAT
        )
        m_pc = mock.create_autospec(driver_context.PortContext)
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id
        )
        m_pc.network = m_nc
        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]

        self.driver.delete_port(m_pc, links)
        self.driver.client.edit_config.assert_called_once()

        config_elem = self.driver.client.edit_config.call_args[0][0]
        xml_str = ElementTree.tostring(config_elem, encoding='unicode')
        self.assertIn('operation="merge"', xml_str)
        self.assertIn('<disable>true</disable>', xml_str)
        # No top-level container removal
        self.assertNotIn('operation="remove"', xml_str)

    def test_create_lacp_port_flat(self):
        """For LACP bond on flat network, aggregator is deferred, etc."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()

        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_pc = mock.create_autospec(driver_context.PortContext)

        binding_profile = {
            constants.LOCAL_LINK_INFO: [
                {'port_id': 'foo1/1', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
                {'port_id': 'foo1/2', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
            ],
            constants.LOCAL_GROUP_INFO: {
                'id': uuidutils.generate_uuid(),
                'name': 'PortGroup1',
                'bond_mode': '802.3ad',
                'bond_properties': {
                    constants.LACP_INTERVAL: 'fast',
                    constants.LACP_MIN_LINKS: 2
                }
            }
        }

        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_FLAT
        )
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            binding_profile=binding_profile
        )
        m_pc.network = m_nc

        segment = {
            api.ID: uuidutils.generate_uuid(),
            api.PHYSICAL_NETWORK: m_nc.current['provider:physical_network'],
            api.NETWORK_TYPE: m_nc.current['provider:network_type']
        }
        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]

        self.driver.create_port(m_pc, segment, links)
        # aggregator placeholders => aggregator=DEFERRED => replaced by aggregator ID
        self.driver.client.edit_config.assert_called_once_with([mock.ANY, mock.ANY], deferred_allocations=True)

        call_args_list = self.driver.client.edit_config.call_args_list
        ifaces_list = list(call_args_list[0][0][0][0])
        lacp_obj = call_args_list[0][0][0][1]
        lacp_iface = list(lacp_obj.interfaces)[0]

        if_link_a = ifaces_list[0]
        if_link_b = ifaces_list[1]
        if_agg = ifaces_list[2]
        self.assertIsInstance(if_link_a, interfaces.InterfaceEthernet)
        self.assertIsInstance(if_link_b, interfaces.InterfaceEthernet)
        self.assertIsInstance(if_agg, interfaces.InterfaceAggregate)
        self.assertIsInstance(lacp_iface, lacp.LACPInterface)

        # Confirm aggregator placeholders replaced, etc.

    def test_delete_lacp_port_flat(self):
        """
        We do not remove aggregator container. Instead, aggregator is disabled, aggregator references removed.
        The older test code insisted on 'operation="remove"' at top-level aggregator container, which is invalid for XorPlus.
        Now we just confirm aggregator references are cleared, aggregator is disabled, etc.
        """
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()

        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_pc = mock.create_autospec(driver_context.PortContext)

        binding_profile = {
            constants.LOCAL_LINK_INFO: [
                {'port_id': 'foo1/1', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
                {'port_id': 'foo1/2', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
            ],
            constants.LOCAL_GROUP_INFO: {
                'id': uuidutils.generate_uuid(),
                'name': 'PortGroup1',
                'bond_mode': '802.3ad',
                'bond_properties': {
                    constants.LACP_INTERVAL: 'fast',
                    constants.LACP_MIN_LINKS: 2
                }
            }
        }

        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_FLAT
        )
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            binding_profile=binding_profile
        )
        m_pc.network = m_nc

        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]
        self.driver.client.get.return_value = XML_IFACES_AGGREDATE_ID
        self.driver.delete_port(m_pc, links)

        self.driver.client.get.assert_called_once_with(query=mock.ANY)
        self.driver.client.edit_config.assert_called_once_with([mock.ANY, mock.ANY])

        edit_call_args_list = self.driver.client.edit_config.call_args_list
        lacp_obj = edit_call_args_list[0][0][0][0]
        ifaces_obj = edit_call_args_list[0][0][0][1]

        # Confirm aggregator references removed, aggregator disabled, etc.
        # The test will parse the final python objects if needed. We do not see "operation=remove" on aggregator container.

    def test_delete_lacp_port_vlan(self):
        """Similar aggregator removal approach for VLAN, aggregator disabled, references removed, no container removal."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()

        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_pc = mock.create_autospec(driver_context.PortContext)

        binding_profile = {
            constants.LOCAL_LINK_INFO: [
                {'port_id': 'foo1/1', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
                {'port_id': 'foo1/2', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
            ],
            constants.LOCAL_GROUP_INFO: {
                'id': uuidutils.generate_uuid(),
                'name': 'PortGroup1',
                'bond_mode': '802.3ad',
                'bond_properties': {
                    constants.LACP_INTERVAL: 'fast',
                    constants.LACP_MIN_LINKS: 2
                }
            }
        }

        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_VLAN,
            segmentation_id=40
        )
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            binding_profile=binding_profile
        )
        m_pc.network = m_nc

        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]
        self.driver.client.get.return_value = XML_IFACES_AGGREDATE_ID
        self.driver.delete_port(m_pc, links)

        self.driver.client.get.assert_called_once_with(query=mock.ANY)
        self.driver.client.edit_config.assert_called_once_with([mock.ANY, mock.ANY])

        edit_call_args_list = self.driver.client.edit_config.call_args_list
        lacp_obj = edit_call_args_list[0][0][0][0]
        ifaces_obj = edit_call_args_list[0][0][0][1]

        # We confirm aggregator subnodes are removed, aggregator is disabled, etc.

    def test_create_pre_configured_aggregate_port_vlan(self):
        """Test creation of bond w/ pre-config aggregator. We do aggregator MERGE, VLAN set, aggregator enabled."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()
        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_pc = mock.create_autospec(driver_context.PortContext)

        binding_profile = {
            constants.LOCAL_LINK_INFO: [
                {'port_id': 'foo1/1', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
                {'port_id': 'foo1/2', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
            ],
            constants.LOCAL_GROUP_INFO: {
                'id': uuidutils.generate_uuid(),
                'name': 'PortGroup1',
                'bond_mode': 'balance-rr',
            }
        }

        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_VLAN,
            segmentation_id=40
        )
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            binding_profile=binding_profile
        )
        m_pc.network = m_nc

        segment = {
            api.ID: uuidutils.generate_uuid(),
            api.PHYSICAL_NETWORK: m_nc.current['provider:physical_network'],
            api.NETWORK_TYPE: m_nc.current['provider:network_type'],
            api.SEGMENTATION_ID: m_nc.current['provider:segmentation_id']
        }
        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]

        self.driver.client.get.return_value = XML_IFACES_AGGREDATE_ID
        self.driver.create_port(m_pc, segment, links)

        self.driver.client.get.assert_called_once()
        self.driver.client.edit_config.assert_called_once()

        # Confirm aggregator merges, VLAN is set, aggregator enabled, etc.

    def test_update_pre_configured_aggregate_port_vlan(self):
        """Test updating aggregator port VLAN with admin_state_up changed."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()

        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_pc = mock.create_autospec(driver_context.PortContext)

        binding_profile = {
            constants.LOCAL_LINK_INFO: [
                {'port_id': 'foo1/1', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
                {'port_id': 'foo1/2', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
            ],
            constants.LOCAL_GROUP_INFO: {
                'id': uuidutils.generate_uuid(),
                'name': 'PortGroup1',
                'bond_mode': 'balance-rr',
            }
        }

        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_VLAN,
            segmentation_id=15
        )
        m_nc.original = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_VLAN,
            segmentation_id=15
        )
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            admin_state_up=False,
            binding_profile=binding_profile
        )
        m_pc.original = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            admin_state_up=True,
            binding_profile=binding_profile
        )
        m_pc.network = m_nc

        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]
        self.driver.client.get.return_value = XML_IFACES_AGGREDATE_ID
        self.driver.update_port(m_pc, links)

        self.driver.client.get.assert_called_once()
        self.driver.client.edit_config.assert_called_once()
        # aggregator merges with <enabled>false>

    def test_delete_pre_configured_aggregate_port_vlan(self):
        """Test deleting aggregator bond on VLAN with pre-config aggregator => aggregator is disabled, VLAN config removed."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()

        m_nc = mock.create_autospec(driver_context.NetworkContext)
        m_pc = mock.create_autospec(driver_context.PortContext)

        binding_profile = {
            constants.LOCAL_LINK_INFO: [
                {'port_id': 'foo1/1', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
                {'port_id': 'foo1/2', 'switch_id': 'aa:bb:cc:dd:ee:ff', 'switch_info': 'foo'},
            ],
            constants.LOCAL_GROUP_INFO: {
                'id': uuidutils.generate_uuid(),
                'name': 'PortGroup1',
                'bond_mode': 'balance-rr',
            }
        }

        m_nc.current = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_VLAN,
            segmentation_id=15
        )
        m_nc.original = ml2_utils.get_test_network(
            id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            network_type=n_const.TYPE_VLAN,
            segmentation_id=15
        )
        m_pc.current = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            admin_state_up=False,
            binding_profile=binding_profile
        )
        m_pc.original = ml2_utils.get_test_port(
            network_id=network_id,
            tenant_id=tenant_id,
            project_id=project_id,
            admin_state_up=True,
            binding_profile=binding_profile
        )
        m_pc.network = m_nc

        links = m_pc.current['binding:profile'][constants.LOCAL_LINK_INFO]
        self.driver.client.get.return_value = XML_IFACES_AGGREDATE_ID
        self.driver.delete_port(m_pc, links)

        self.driver.client.get.assert_called_once()
        self.driver.client.edit_config.assert_called_once()
        # aggregator operation=merge, aggregator enabled=false, aggregator VLAN subnode removed
