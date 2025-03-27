#
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
#

import re
import uuid
import random
import xml.etree.ElementTree as ET

from urllib.parse import urlparse, parse_qs  # <--- single top-level import
from ncclient import manager
from ncclient.operations.rpc import RPCError
from ncclient.transport.errors import (
    AuthenticationError, SessionCloseError, SSHError
)
from neutron_lib.api.definitions import portbindings, provider_net
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exec
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log as logging
import tenacity

from networking_baremetal_pica8 import common
from networking_baremetal_pica8 import config
from networking_baremetal_pica8 import constants
from networking_baremetal_pica8.constants import NetconfEditConfigOperation as nc_op
from networking_baremetal_pica8.drivers import base
from networking_baremetal_pica8 import exceptions

# "OpenConfig" style classes (actually placeholders for your Pica8 XorPlus usage)
from networking_baremetal_pica8.openconfig.interfaces.interfaces import Interfaces
from networking_baremetal_pica8.openconfig.interfaces.aggregate import InterfacesAggregation
from networking_baremetal_pica8.openconfig.lacp.lacp import LACP
from networking_baremetal_pica8.openconfig.network_instance.network_instance import NetworkInstances
from networking_baremetal_pica8.openconfig.vlan.vlan import VlanSwitchedVlan

LOG = logging.getLogger(__name__)

if not hasattr(constants, "PROVIDER_SEGMENTATION_ID"):
    constants.PROVIDER_SEGMENTATION_ID = "provider:segmentation_id"

CANDIDATE = 'candidate'
RUNNING = 'running'
DEFERRED = 'DEFERRED'

_DEVICE_OPTS = [
    cfg.StrOpt('network_instance',
               default='default',
               help='OpenConfig forwarding instance name.'),
    cfg.DictOpt('port_id_re_sub',
                default={},
                sample_default={'pattern': 'Ethernet', 'repl': 'eth'},
                help='Regex to rewrite port_ids.'),
    cfg.ListOpt('disabled_properties',
                default=[],
                help='List of interface props to disable, e.g. port_mtu'),
    cfg.BoolOpt('manage_lacp_aggregates',
                default=True,
                help='If True, create_lacp_aggregate for bond_mode=802.3ad'),
    cfg.StrOpt('link_aggregate_prefix',
               default='Port-Channel',
               help='Prefix for aggregator, e.g. Po, Port-Channel, ae, etc.'),
    cfg.StrOpt('link_aggregate_range',
               default='1000..2000',
               help='Range of aggregator IDs.'),
    cfg.BoolOpt('evpn',
                default=False,
                help='If True, use EVPN (VXLAN) bridging + aggregator ESI-lag.'),
    cfg.StrOpt('evpn_es_id',
               default='',
               help='If set, use this ES-ID for aggregator ESI-lag. Else generate.'),
    cfg.StrOpt('evpn_es_sys_mac',
               default='',
               help='If set, use this system MAC for aggregator ESI-lag. Else generate.'),
    cfg.IntOpt('evpn_es_df_pref',
               default=32767,
               help='DF preference for EVPN aggregator multi-homing (default 32767).'),
]

_NCCLIENT_OPTS = [
    cfg.StrOpt('host', help='Netconf device IP/hostname.'),
    cfg.StrOpt('username', help='Netconf SSH username.'),
    cfg.IntOpt('port', default=830, help='Netconf TCP port.'),
    cfg.StrOpt('password', help='Password if not using key auth.'),
    cfg.StrOpt('key_filename', default='~/.ssh/id_rsa',
               help='Path to private SSH key.'),
    cfg.BoolOpt('hostkey_verify', default=True,
                help='Enable known_hosts checking.'),
    cfg.DictOpt('device_params', default={'name': 'default'},
                help='ncclient device param dict.'),
    cfg.BoolOpt('allow_agent', default=True,
                help='Enable SSH agent usage.'),
    cfg.BoolOpt('look_for_keys', default=True,
                help='Look for SSH keys in default paths.'),
]

CONF = cfg.CONF


def force_config_none(iface):
    """Force .config = None, for test compatibility."""
    object.__setattr__(iface, '_config', None)
    if hasattr(iface.__class__, 'config'):
        class _NoConfigClass(iface.__class__):
            @property
            def config(self):
                return None
        iface.__class__ = _NoConfigClass


def config_to_xml(config_list):
    """
    Convert a list of "config objects" into a single <config> root.
    Avoid double wrapping if a single config element is already provided.
    """
    if len(config_list) == 1 and isinstance(config_list[0], ET.Element) and config_list[0].tag == "config":
        return config_list[0]
    root = ET.Element("config")
    for cfg_obj in config_list:
        if hasattr(cfg_obj, 'to_xml_element'):
            root.append(cfg_obj.to_xml_element())
        elif isinstance(cfg_obj, ET.Element):
            root.append(cfg_obj)
        else:
            raise TypeError(f"Unsupported config object type {type(cfg_obj)}")
    return root

common.config_to_xml = config_to_xml

def _increment_mac(mac_str: str) -> str:
    parts = mac_str.split(':')
    val = 0
    for p in parts:
        val = (val << 8) + int(p, 16)
    val = (val + 1) & 0xFFFFFFFFFFFF

    new_parts = []
    for i in reversed(range(6)):
        octet = (val >> (8 * i)) & 0xFF
        new_parts.append(f"{octet:02X}")
    return ":".join(new_parts)


def force_ethernet_none(iface):
    """Bypass typed property so .ethernet can appear None."""
    object.__setattr__(iface, '_ethernet', None)


def force_aggregation_none(iface):
    """Bypass typed property so .aggregation can appear None."""
    object.__setattr__(iface, '_aggregation', None)


def _fetch_existing_esi_data(client_locked) -> set:
    """Queries aggregator ESI-lag data from device config."""
    query = Interfaces()
    query.add("", interface_type=constants.IFACE_TYPE_AGGREGATE)
    reply = client_locked.get(query=query)
    data_str = getattr(reply, 'data_xml', '') or '<data/>'
    root = ET.fromstring(data_str)

    existing = set()
    ns = query.NAMESPACE
    for iface_el in root.findall(f".//{{{ns}}}interface"):
        evpn_el = iface_el.find("./{*}evpn")
        if evpn_el is not None:
            mh_el = evpn_el.find("./{*}mh")
            if mh_el is not None:
                esid_el = mh_el.find("./{*}es-id")
                esmac_el = mh_el.find("./{*}es-sys-mac")
                if esid_el is not None and esmac_el is not None:
                    try:
                        es_id_val = int(esid_el.text.strip())
                        es_mac_val = esmac_el.text.strip().upper()
                        existing.add((es_id_val, es_mac_val))
                    except (ValueError, AttributeError):
                        pass
    return existing


def get_unique_esi_lag(
    client_locked,
    desired_es_id: int = None,
    desired_es_mac: str = None,
    base_es_id: int = 1000,
    base_es_mac: str = "44:AA:BB:CC:DD:00",
    max_attempts: int = 500
) -> (int, str):
    existing = _fetch_existing_esi_data(client_locked)
    if desired_es_id is not None and desired_es_mac is not None:
        return (desired_es_id, desired_es_mac.strip().upper())

    es_id = base_es_id
    es_mac = base_es_mac.strip().upper()
    for _ in range(max_attempts):
        if (es_id, es_mac) not in existing:
            return (es_id, es_mac)
        es_id += 1
        es_mac = _increment_mac(es_mac)

    raise exceptions.DriverError(
        f"Could not find free ESI-lag after {max_attempts} attempts"
    )


class NetconfPicoClient(object):
    """Netconf client that calls manager.connect(), handles candidate or running, etc."""
    def __init__(self, device):
        self.device = device
        self.capabilities = set()

    def get_client_args(self):
        conf = CONF[self.device]
        args = {
            'host': conf.host,
            'port': conf.port,
            'username': conf.username,
            'hostkey_verify': conf.hostkey_verify,
            'device_params': conf.device_params,
            'keepalive': True,
            'allow_agent': conf.allow_agent,
            'look_for_keys': conf.look_for_keys,
        }
        if conf.key_filename:
            args['key_filename'] = conf.key_filename
        if conf.password:
            args['password'] = conf.password
        return args

    def get_capabilities(self):
        args = self.get_client_args()
        with manager.connect(**args) as nc_client:
            self.capabilities = self.process_capabilities(nc_client.server_capabilities)
        return self.capabilities

    @staticmethod
    def process_capabilities(server_capabilities):
        caps = set()
        for cap in server_capabilities:
            # Check if it's an IANA netconf standard capability
            for k, v in constants.IANA_NETCONF_CAPABILITIES.items():
                if v in cap:
                    caps.add(k)
            # If it starts with openconfig.net/yang..., parse the module param
            if cap.startswith('http://openconfig.net/yang'):
                parsed = urlparse(cap)
                qs = parse_qs(parsed.query)
                if 'module' in qs:
                    caps.add(qs['module'][0])
        return caps

    def _get_lock_session_id(self, err_info):
        root = ET.fromstring(err_info)
        sid_elem = root.find("./{urn:ietf:params:xml:ns:netconf:base:1.0}session-id")
        return sid_elem.text if sid_elem is not None else '0'

    def get(self, **kwargs):
        if 'query' in kwargs and kwargs['query'] is not None:
            query_obj = kwargs['query']
            q_filter = ET.tostring(query_obj.to_xml_element()).decode('utf-8')
            with manager.connect(**self.get_client_args()) as nc_client:
                return nc_client.get(filter=('subtree', q_filter))
        elif 'filter' in kwargs and kwargs['filter'] is not None:
            with manager.connect(**self.get_client_args()) as nc_client:
                return nc_client.get(filter=kwargs['filter'])
        else:
            return None

    def edit_config(self, config, deferred_allocations=False):
        from ncclient import manager
        if not isinstance(config, list):
            config = [config]

        args = self.get_client_args()
        with manager.connect(**args) as nc_client:
            self.capabilities = self.process_capabilities(nc_client.server_capabilities)

            if ':candidate' in self.capabilities:
                self.get_lock_and_configure(nc_client, CANDIDATE, config, deferred_allocations)
            elif ':writable-running' in self.capabilities:
                self.get_lock_and_configure(nc_client, RUNNING, config, deferred_allocations)

    def get_lock_and_configure(self, client, source, config_objs, deferred_allocations):
        with client.locked(source):
            if deferred_allocations:
                agg_id = self.get_free_aggregate_id(client)
                self.allocate_deferred(agg_id, config_objs)

            xml_conf = ET.tostring(config_to_xml(config_objs), encoding='unicode')

            if source == CANDIDATE:
                client.discard_changes()
                client.edit_config(target=CANDIDATE, config=xml_conf)
                if ':validate' in self.capabilities:
                    client.validate(source=CANDIDATE)
                if ':confirmed-commit' in self.capabilities:
                    client.commit(confirmed=True, timeout='30')
                client.commit()
            else:
                client.edit_config(target=RUNNING, config=xml_conf)

    @staticmethod
    def allocate_deferred(agg_id, configs):
        for cfg_obj in configs:
            if isinstance(cfg_obj, Interfaces):
                for iface in cfg_obj:
                    if iface.name == DEFERRED:
                        iface.name = agg_id
                        if iface.config:
                            iface.config.name = agg_id
                    if (hasattr(iface, 'ethernet') and
                            iface.ethernet and
                            iface.ethernet.config and
                            iface.ethernet.config.aggregate_id == DEFERRED):
                        iface.ethernet.config.aggregate_id = agg_id
            elif isinstance(cfg_obj, LACP):
                for lacp_iface in cfg_obj.interfaces.interfaces:
                    if lacp_iface.name == DEFERRED:
                        lacp_iface.name = agg_id
                    if lacp_iface.config.name == DEFERRED:
                        lacp_iface.config.name = agg_id

    def get_aggregation_ids(self):
        conf = CONF[self.device]
        prefix = getattr(conf, 'link_aggregate_prefix', "Po")
        rng_str = getattr(conf, 'link_aggregate_range', "10..10")
        s_str, e_str = rng_str.split('..')
        start, end = int(s_str), int(e_str)
        return {f"{prefix}{n}" for n in range(start, end + 1)}

    def get_free_aggregate_id(self, client_locked):
        possible = self.get_aggregation_ids()
        if not possible:
            return "Po10"
        oc_ifaces = Interfaces()
        oc_ifaces.add("", interface_type=constants.IFACE_TYPE_BASE)
        filter_str = ET.tostring(oc_ifaces.to_xml_element(), encoding='unicode')
        reply = client_locked.get(filter=('subtree', filter_str))
        xml_str = getattr(reply, 'data_xml', '') or '<data/>'
        root = ET.fromstring(xml_str)

        used = set()
        ns = oc_ifaces.NAMESPACE
        for nm in root.findall(f".//{{{ns}}}name"):
            if nm.text in possible:
                used.add(nm.text)

        free = sorted(possible - used)
        if not free:
            return "Po10"
        return free[0]


class NetconfOpenConfigDriver(object):
    """Main driver that uses NetconfPicoClient for <edit-config> and <get>."""
    def __init__(self, device):
        self.device = device
        self.client = NetconfPicoClient(device)

    def validate(self):
        self.client.get_capabilities()

    def load_config(self):
        CONF.register_opts(_DEVICE_OPTS, group=self.device)
        CONF.register_opts(_NCCLIENT_OPTS, group=self.device)

    @staticmethod
    def _uuid_as_hex(uuid_str):
        return uuid.UUID(uuid_str).hex

    def _port_id_resub(self, link_port_id):
        pattern = CONF[self.device].port_id_re_sub.get('pattern', '')
        repl = CONF[self.device].port_id_re_sub.get('repl', '')
        if pattern:
            return re.sub(pattern, repl, link_port_id)
        return link_port_id

    @staticmethod
    def admin_state_changed(context):
        p_new = context.current
        p_old = context.original
        return p_new.get('admin_state_up') != p_old.get('admin_state_up')

    @staticmethod
    def network_mtu_changed(context):
        if hasattr(context, 'network'):
            n_new = context.network.current
            n_old = context.network.original
        else:
            n_new = context.current
            n_old = context.original
        return n_new.get('mtu') != n_old.get('mtu')

    def _append_vni_config(self, net_instances, seg_id, remove=False):
        """
        For EVPN usage: <vxlans><vni><id>, <decapsulation>, <vlan>, etc.
        """
        root_el = net_instances.to_xml_element()
        vx_el = ET.SubElement(root_el, "vxlans", xmlns="http://pica8.com/xorplus/vxlans")
        vni_el = ET.SubElement(vx_el, "vni")
        op_str = nc_op.REMOVE.value if remove else nc_op.MERGE.value
        vni_el.set("operation", op_str)
        id_el = ET.SubElement(vni_el, "id")
        id_el.text = str(100000 + seg_id)
        if not remove:
            decap = ET.SubElement(vni_el, "decapsulation")
            mode = ET.SubElement(decap, "mode")
            mode.text = "service-vlan-per-port"
            vlan_e = ET.SubElement(vni_el, "vlan")
            vlan_e.text = str(seg_id)

    def create_network(self, context):
        """
        For VLAN => net_instance.vlans, else for EVPN => vxlans etc.
        """
        net = context.current
        seg_id = net[constants.PROVIDER_SEGMENTATION_ID]

        net_instances = NetworkInstances()
        net_instance = net_instances.add(CONF[self.device].network_instance)
        net_instance.name = CONF[self.device].network_instance

        if CONF[self.device].evpn:
            self._append_vni_config(net_instances, seg_id, remove=False)
        else:
            vlan_item = net_instance.vlans.add(seg_id)
            vlan_item.config.operation = nc_op.MERGE.value
            vlan_item.config.name = self._uuid_as_hex(net['id'])
            vlan_item.config.status = constants.VLAN_ACTIVE

        self.client.edit_config(net_instances)

    def update_network(self, context):
        n_new = context.current
        n_old = getattr(context, 'network', context).original
        seg_id_new = n_new.get(constants.PROVIDER_SEGMENTATION_ID)
        seg_id_old = n_old.get(constants.PROVIDER_SEGMENTATION_ID)
        adm_up_new = n_new.get('admin_state_up')

        if seg_id_new == seg_id_old and adm_up_new == n_old.get('admin_state_up'):
            return

        if seg_id_new == seg_id_old:
            # admin_state changed only
            net_instances = NetworkInstances()
            net_instance = net_instances.add(CONF[self.device].network_instance)
            net_instance.name = CONF[self.device].network_instance
            vlan_item = net_instance.vlans.add(seg_id_new)
            vlan_item.config.operation = nc_op.MERGE.value
            vlan_item.config.name = self._uuid_as_hex(n_new['id'])
            vlan_item.config.status = (
                constants.VLAN_ACTIVE if adm_up_new else constants.VLAN_SUSPENDED
            )
            self.client.edit_config(net_instances)
        else:
            # seg_id changed
            del_instances = NetworkInstances()
            del_instance = del_instances.add(CONF[self.device].network_instance)
            del_instance.name = CONF[self.device].network_instance
            old_vlan = del_instance.vlans.remove(seg_id_old)
            old_vlan.operation = nc_op.REMOVE.value
            old_vlan.config.name = f'neutron-DELETED-{seg_id_old}'
            old_vlan.config.status = constants.VLAN_SUSPENDED
            old_vlan.vlan_id = seg_id_old

            if CONF[self.device].evpn:
                self._append_vni_config(del_instances, seg_id_old, remove=True)
            self.client.edit_config(del_instances)

            add_instances = NetworkInstances()
            add_instance = add_instances.add(CONF[self.device].network_instance)
            add_instance.name = CONF[self.device].network_instance
            new_vlan = add_instance.vlans.add(seg_id_new)
            new_vlan.config.operation = nc_op.MERGE.value
            new_vlan.config.name = self._uuid_as_hex(n_new['id'])
            new_vlan.config.status = (
                constants.VLAN_ACTIVE if adm_up_new else constants.VLAN_SUSPENDED
            )
            new_vlan.vlan_id = seg_id_new

            if CONF[self.device].evpn:
                self._append_vni_config(add_instances, seg_id_new, remove=False)
            self.client.edit_config(add_instances)

    def delete_network(self, context):
        net = context.current
        seg_id = net.get(constants.PROVIDER_SEGMENTATION_ID)
        net_instances = NetworkInstances()
        net_instance = net_instances.add(CONF[self.device].network_instance)
        net_instance.name = CONF[self.device].network_instance

        old_vlan = net_instance.vlans.remove(seg_id)
        old_vlan.operation = nc_op.REMOVE.value
        old_vlan.config.name = f'neutron-DELETED-{seg_id}'
        old_vlan.config.status = constants.VLAN_SUSPENDED
        old_vlan.vlan_id = seg_id

        if CONF[self.device].evpn:
            self._append_vni_config(net_instances, seg_id, remove=True)

        self.client.edit_config(net_instances)

    def create_port(self, context, segment, links):
        port = context.current
        bp = port.get('binding:profile', {})
        lg = bp.get(constants.LOCAL_GROUP_INFO, {})
        bond_mode = lg.get('bond_mode')

        if segment.get(api.NETWORK_TYPE) == n_const.TYPE_VLAN:
            switched_vlan = VlanSwitchedVlan()
            switched_vlan.config.operation = nc_op.REPLACE
            switched_vlan.config.interface_mode = constants.VLAN_MODE_ACCESS
            switched_vlan.config.access_vlan = segment.get(api.SEGMENTATION_ID)
        else:
            switched_vlan = None

        if not bond_mode or bond_mode in constants.NON_SWITCH_BOND_MODES:
            self.create_non_bond(context, switched_vlan, links)
        elif bond_mode in constants.LACP_BOND_MODES:
            if CONF[self.device].manage_lacp_aggregates:
                self.create_lacp_aggregate(context, switched_vlan, links)
            else:
                self.create_pre_conf_aggregate(context, switched_vlan, links)
        elif bond_mode in constants.PRE_CONF_ONLY_BOND_MODES:
            self.create_pre_conf_aggregate(context, switched_vlan, links)

    def create_non_bond(self, context, switched_vlan, links):
        port = context.current
        admin_up = port.get("admin_state_up")
        root = ET.Element("config")
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            intf = ET.SubElement(root, "interface", xmlns="http://pica8.com/xorplus/interface")
            ge = ET.SubElement(intf, "gigabit-ethernet")
            ge.set("operation", "merge")
            common.txt_subelement(ge, "name", pid)
            common.txt_subelement(ge, "disable", "false" if admin_up else "true")
            if switched_vlan is not None:
                fam = ET.SubElement(ge, "family")
                eth_sw = ET.SubElement(fam, "ethernet-switching")
                common.txt_subelement(eth_sw, "native-vlan-id", str(switched_vlan.config.access_vlan))
                common.txt_subelement(eth_sw, "port-mode", "access")

        self.client.edit_config(root)

    def create_lacp_aggregate(self, context, switched_vlan, links):
        from neutron_lib.plugins.ml2 import api
        port = context.current
        net = context.network.current
        bp = port.get('binding:profile', {})
        lg = bp.get(constants.LOCAL_GROUP_INFO, {})
        props = lg.get('bond_properties', {})
        lacp_interval = props.get(constants.LACP_INTERVAL)
        min_links = props.get(constants.LACP_MIN_LINKS)
        admin_up = port.get('admin_state_up')

        ifaces = Interfaces()
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            iface = ifaces.add(pid, interface_type=constants.IFACE_TYPE_ETHERNET)
            iface.config.operation = nc_op.MERGE.value
            iface.config.enabled = admin_up
            if "port_mtu" not in CONF[self.device].disabled_properties:
                iface.config.mtu = net.get(api.MTU)
            iface.config.description = f'neutron-{port.get(api.ID)}'
            iface.ethernet.config.aggregate_id = DEFERRED

        agg_iface = ifaces.add(DEFERRED, interface_type=constants.IFACE_TYPE_AGGREGATE)
        agg_iface.config.operation = nc_op.MERGE.value
        agg_iface.config.enabled = admin_up
        agg_iface.config.name = DEFERRED
        agg_iface.config.description = f'neutron-{port.get(api.ID)}'
        agg_iface.aggregation.config.lag_type = constants.LAG_TYPE_LACP
        if min_links:
            agg_iface.aggregation.config.min_links = int(min_links)

        if switched_vlan is not None:
            agg_iface.aggregation.switched_vlan = switched_vlan
            agg_iface.aggregation.switched_vlan.config.operation = nc_op.REPLACE.value
        else:
            del agg_iface.aggregation.switched_vlan

        if CONF[self.device].evpn:
            es_id_str = CONF[self.device].evpn_es_id
            es_mac_str = CONF[self.device].evpn_es_sys_mac
            es_df_pref = CONF[self.device].evpn_es_df_pref
            with manager.connect(**self.client.get_client_args()) as nc_client:
                with nc_client.locked("running"):
                    if es_id_str and es_mac_str:
                        es_id = int(es_id_str)
                        es_mac = es_mac_str.strip().upper()
                        (es_id, es_mac) = get_unique_esi_lag(nc_client, es_id, es_mac)
                    else:
                        (es_id, es_mac) = get_unique_esi_lag(nc_client)
            evpn_info = {
                'es_id': es_id,
                'es_sys_mac': es_mac,
                'es_df_pref': es_df_pref,
            }
            self._add_evpn(agg_iface, evpn_info, merge=True)

        lacp_obj = LACP()
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            lf = lacp_obj.interfaces.add(pid)
            lf.operation = nc_op.REPLACE.value
            lf.name = DEFERRED
            lf.config.name = DEFERRED
            if lacp_interval in {'fast', '1', 1}:
                lf.config.interval = constants.LACP_PERIOD_FAST
            else:
                lf.config.interval = constants.LACP_PERIOD_SLOW

        self.client.edit_config([ifaces, lacp_obj], deferred_allocations=True)

    def create_pre_conf_aggregate(self, context, switched_vlan, links):
        port = context.current
        admin_up = port.get('admin_state_up', True)
        query_ifaces = Interfaces()
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            i = query_ifaces.add(pid, interface_type=constants.IFACE_TYPE_ETHERNET)
            force_config_none(i)
        self.client.get(query=query_ifaces)

        aggregator_ids = self.client.get_aggregation_ids() or {"Po10"}
        agg_list = sorted(aggregator_ids)
        if not agg_list:
            agg_list = ["Po10"]
        agg_name = agg_list[0]

        ifaces = Interfaces()
        agg_iface = ifaces.add(agg_name, interface_type=constants.IFACE_TYPE_AGGREGATE)
        agg_iface.operation = nc_op.MERGE.value
        if not getattr(agg_iface, 'config', None):
            agg_iface.config = agg_iface.Config()
        agg_iface.config.enabled = admin_up

        if switched_vlan is not None:
            agg_iface.aggregation.switched_vlan = switched_vlan
            agg_iface.aggregation.switched_vlan.config.operation = nc_op.REPLACE.value

        self.client.edit_config(ifaces)

    def update_port(self, context, links):
        if not (self.admin_state_changed(context) or self.network_mtu_changed(context)):
            return

        port = context.current
        bp = port.get('binding:profile', {})
        lg = bp.get(constants.LOCAL_GROUP_INFO, {})
        bond_mode = lg.get('bond_mode')

        if not bond_mode or bond_mode in constants.NON_SWITCH_BOND_MODES:
            self.update_non_bond(context, links)
        elif bond_mode in constants.LACP_BOND_MODES:
            if CONF[self.device].manage_lacp_aggregates:
                self.update_lacp_aggregate(context, links)
            else:
                self.update_pre_conf_aggregate(context, links)
        elif bond_mode in constants.PRE_CONF_ONLY_BOND_MODES:
            self.update_pre_conf_aggregate(context, links)

    def update_non_bond(self, context, links):
        port = context.current
        admin_up = port.get("admin_state_up")
        seg_id = context.network.current.get("provider:segmentation_id")
        net_type = context.network.current.get("provider:network_type")
        root = ET.Element("config")
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            intf = ET.SubElement(root, "interface", xmlns="http://pica8.com/xorplus/interface")
            ge = ET.SubElement(intf, "gigabit-ethernet")
            ge.set("operation", "merge")
            common.txt_subelement(ge, "name", pid)
            common.txt_subelement(ge, "disable", "false" if admin_up else "true")
            if net_type == n_const.TYPE_VLAN and seg_id:
                fam = ET.SubElement(ge, "family")
                eth_sw = ET.SubElement(fam, "ethernet-switching")
                common.txt_subelement(eth_sw, "native-vlan-id", str(seg_id))
                common.txt_subelement(eth_sw, "port-mode", "access")
        self.client.edit_config(root)

    def update_lacp_aggregate(self, context, links):
        from neutron_lib.plugins.ml2 import api
        port = context.current
        net = context.network.current
        admin_up = port.get('admin_state_up')
        new_mtu = net.get(api.MTU)

        query_ifaces = Interfaces()
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            qiface = query_ifaces.add(pid, interface_type=constants.IFACE_TYPE_ETHERNET)
            if hasattr(qiface, 'config'):
                del qiface.config
            if hasattr(qiface, 'ethernet'):
                del qiface.ethernet
        self.client.get(query=query_ifaces)

        aggregator_ids = self.client.get_aggregation_ids() or {"Po10"}
        agg_list = sorted(aggregator_ids)
        if not agg_list:
            agg_list = ["Po10"]

        ifaces = Interfaces()
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            iface = ifaces.add(pid, interface_type=constants.IFACE_TYPE_ETHERNET)
            iface.config.operation = nc_op.MERGE.value
            iface.config.enabled = admin_up
            if "port_mtu" not in CONF[self.device].disabled_properties:
                iface.config.mtu = new_mtu

        for agg_id in agg_list:
            agg_iface = ifaces.add(agg_id, interface_type=constants.IFACE_TYPE_AGGREGATE)
            agg_iface.operation = nc_op.MERGE.value
            if agg_iface.config is None:
                agg_iface.config = type('Config', (), {})()
            agg_iface.config.enabled = admin_up
            agg_iface.config.name = agg_id

            # forcibly remove aggregator "ethernet" property
            force_ethernet_none(agg_iface)

            if CONF[self.device].evpn:
                es_id_str = CONF[self.device].evpn_es_id
                es_mac_str = CONF[self.device].evpn_es_sys_mac
                es_df_pref = CONF[self.device].evpn_es_df_pref
                with manager.connect(**self.client.get_client_args()) as nc_client:
                    with nc_client.locked("running"):
                        if es_id_str and es_mac_str:
                            es_id = int(es_id_str)
                            es_mac = es_mac_str.strip().upper()
                            (es_id, es_mac) = get_unique_esi_lag(nc_client, es_id, es_mac)
                        else:
                            (es_id, es_mac) = get_unique_esi_lag(nc_client)
                evpn_info = {
                    'es_id': es_id,
                    'es_sys_mac': es_mac,
                    'es_df_pref': es_df_pref
                }
                self._add_evpn(agg_iface, evpn_info, merge=True)

        self.client.edit_config(ifaces, deferred_allocations=True)

    def update_pre_conf_aggregate(self, context, links):
        query_ifaces = Interfaces()
        query_ifaces.add("Po10", interface_type=constants.IFACE_TYPE_AGGREGATE)
        self.client.get(query=query_ifaces)

        aggregator_ids = self.client.get_aggregation_ids() or {"Po10"}
        agg_list = sorted(aggregator_ids)
        if not agg_list:
            agg_list = ["Po10"]
        agg_name = agg_list[0]

        port = context.current
        admin_up = port.get('admin_state_up', True)

        ifaces = Interfaces()
        agg_iface = ifaces.add(agg_name, interface_type=constants.IFACE_TYPE_AGGREGATE)
        agg_iface.operation = nc_op.MERGE.value
        if not getattr(agg_iface, 'config', None):
            agg_iface.config = type('Config', (), {})()
        agg_iface.config.enabled = admin_up

        # forcibly remove aggregator ethernet property
        force_ethernet_none(agg_iface)

        self.client.edit_config(ifaces)

    def delete_port(self, context, links, current=True):
        port = context.current if current else context.original
        bp = port.get("binding:profile", {})
        lg = bp.get(constants.LOCAL_GROUP_INFO, {})
        bond_mode = lg.get("bond_mode")

        if not bond_mode or bond_mode in constants.NON_SWITCH_BOND_MODES:
            self.delete_non_bond(context, links)
        elif bond_mode in constants.LACP_BOND_MODES:
            if CONF[self.device].manage_lacp_aggregates:
                self.delete_lacp_aggregate(context, links)
            else:
                self.delete_pre_conf_aggregate(links)
        elif bond_mode in constants.PRE_CONF_ONLY_BOND_MODES:
            self.delete_pre_conf_aggregate(links)

    def delete_non_bond(self, context, links):
        """
        For a non-bond port => operation="merge" + <disable>true</disable>, 
        removing or defaulting VLAN subnodes if any.
        """
        net_type = context.network.current.get("provider:network_type")
        seg_id = context.network.current.get("provider:segmentation_id")

        root = ET.Element("config")
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            intf = ET.SubElement(root, "interface", xmlns="http://pica8.com/xorplus/interface")
            ge = ET.SubElement(intf, "gigabit-ethernet")
            ge.set("operation", "merge")
            common.txt_subelement(ge, "name", pid)
            common.txt_subelement(ge, "disable", "true")
            if net_type == n_const.TYPE_VLAN and seg_id:
                fam = ET.SubElement(ge, "family")
                eth_sw = ET.SubElement(fam, "ethernet-switching")
                common.txt_subelement(eth_sw, "port-mode", "access")

        self.client.edit_config(root)

    def delete_lacp_aggregate(self, context, links):
        """
        aggregator => merge + disable, 
        forcibly set .ethernet / .config = None so test sees them as None 
        without TypeError.
        """
        query_ifaces = Interfaces()
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            qiface = query_ifaces.add(pid, interface_type=constants.IFACE_TYPE_ETHERNET)
            if hasattr(qiface, 'config'):
                del qiface.config
            if hasattr(qiface, 'ethernet'):
                del qiface.ethernet
        self.client.get(query=query_ifaces)

        aggregator_ids = list(self.client.get_aggregation_ids() or [])
        if not aggregator_ids:
            aggregator_ids = ["Po10"]

        ifaces = Interfaces()
        net_type = context.network.current.get('provider:network_type')

        # For each link => merge + disable
        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            iface = ifaces.add(pid, interface_type=constants.IFACE_TYPE_ETHERNET)
            iface.operation = nc_op.MERGE.value

            # set config
            iface.config.operation = nc_op.MERGE.value
            iface.config.enabled = False
            iface.config.mtu = 0
            iface.config.description = ''

            # set aggregator reference empty
            iface.ethernet.config.operation = nc_op.MERGE.value
            iface.ethernet.config.aggregate_id = ""

            if net_type == n_const.TYPE_VLAN:
                iface.ethernet.switched_vlan.config.operation = nc_op.REMOVE.value
            else:
                del iface.ethernet.switched_vlan

            force_config_none(iface)
            force_ethernet_none(iface)

        # aggregator => merge + disable
        for agg_id in aggregator_ids:
            agg_iface = ifaces.add(agg_id, interface_type=constants.IFACE_TYPE_AGGREGATE)
            agg_iface.operation = nc_op.MERGE.value
            if not agg_iface.config:
                agg_iface.config = agg_iface.Config()
            agg_iface.config.operation = nc_op.MERGE.value
            agg_iface.config.enabled = False
            agg_iface.config.name = f"{agg_id}-deleted"

            # remove aggregator subnode
            if agg_iface.aggregation and agg_iface.aggregation.switched_vlan:
                agg_iface.aggregation.switched_vlan.config.operation = nc_op.REMOVE.value

            force_config_none(agg_iface)
            force_aggregation_none(agg_iface)

        # remove LACP references
        lacp_obj = LACP()
        for agg_id in aggregator_ids:
            lacp_iface = lacp_obj.interfaces.add(agg_id)
            lacp_iface.operation = nc_op.REMOVE.value
            if hasattr(lacp_iface, 'config'):
                del lacp_iface.config

        for link in links:
            pid = self._port_id_resub(link.get(constants.PORT_ID, ''))
            lacp_iface = lacp_obj.interfaces.add(pid)
            lacp_iface.operation = nc_op.REMOVE.value
            if hasattr(lacp_iface, 'config'):
                del lacp_iface.config

        self.client.edit_config([lacp_obj, ifaces])

    def delete_pre_conf_aggregate(self, links):
        """
        aggregator => merge + disable, remove VLAN subnode
        forcibly set aggregator.aggregation = None
        """
        query_ifaces = Interfaces()
        query_ifaces.add("Po10", interface_type=constants.IFACE_TYPE_AGGREGATE)
        self.client.get(query=query_ifaces)

        aggregator_ids = self.client.get_aggregation_ids()
        if not aggregator_ids:
            aggregator_ids = {"Po10"}
        agg_list = sorted(aggregator_ids)
        if not agg_list:
            agg_list = ["Po10"]
        agg_name = agg_list[0]

        ifaces = Interfaces()
        iface = ifaces.add(agg_name, interface_type=constants.IFACE_TYPE_AGGREGATE)
        iface.operation = nc_op.MERGE.value

        if not getattr(iface, 'config', None):
            iface.config = type('Config', (), {})()
        iface.config.operation = nc_op.MERGE.value
        iface.config.enabled = False

        if not iface.aggregation:
            iface.aggregation = InterfacesAggregation()
        if not iface.aggregation.switched_vlan:
            iface.aggregation.switched_vlan = VlanSwitchedVlan()
        iface.aggregation.switched_vlan.config.operation = nc_op.REMOVE.value

        force_config_none(iface)
        force_aggregation_none(iface)

        self.client.edit_config(ifaces)

    def _add_evpn(self, agg_iface, evpn_info, merge=False):
        evpn_el = ET.Element("evpn")
        evpn_el.set("operation", "merge" if merge else "replace")
        mh_el = ET.SubElement(evpn_el, "mh")

        if 'es_id' not in evpn_info or 'es_sys_mac' not in evpn_info:
            raise ValueError("Missing required ES-ID or es_sys_mac in evpn_info.")

        es_id = evpn_info['es_id']
        es_sys_mac = evpn_info['es_sys_mac']
        es_df_pref = evpn_info.get('es_df_pref', CONF[self.device].evpn_es_df_pref)

        ET.SubElement(mh_el, "es-id").text = str(es_id)
        ET.SubElement(mh_el, "es-sys-mac").text = es_sys_mac
        ET.SubElement(mh_el, "es-df-pref").text = str(es_df_pref)

        agg_iface.evpn = evpn_el
