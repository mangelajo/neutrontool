import sys
import pprint

from colors import color
import osclients
import keystoneclient

pp = pprint.PrettyPrinter(indent=4)

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


class SecurityGroupScaleHealerBase():

    def __init__(self, neutron, keystone, verbose=True):
        self.neutron = neutron
        self.keystone = keystone
        self.verbose = verbose
        self._prefetch_data()

    def _prefetch_data(self):
        self._sgs = {}
        self._ports = {}
        self._tenants = {}
        self._subnets = {}
        self._fetch_tenant_list()
        self._fetch_security_groups()
        self._fetch_ports()
        self._fetch_subnets()

    def _fetch_tenant_list(self):
        if self.verbose:
            print color('blue', "Fetching tenant listing ....")
        tenants = self.keystone.tenants.list()
        for tenant in tenants:
            self._tenants[tenant.id] = tenant

    def _get_tenant(self, id):
        if id not in self._tenants:
            try:
                self._tenants[id] = self.keystone.tenants.get(id)
            except keystoneclient.openstack.common.apiclient.exceptions.NotFound:
                self._tenants[id] = None
            except keystoneclient.apiclient.exceptions.NotFound:
                self._tenants[id] = None

        return self._tenants[id]

    def _attrdict_sg(self, sg_in):
        sg = AttrDict(sg_in)
        rules = sg.security_group_rules
        sg.security_group_rules = [AttrDict(rule) for rule in rules]
        return sg

    def _fetch_security_groups(self):
        if self.verbose:
            print color('blue',"Fetching security group listing ....")
        sgs = [self._attrdict_sg(sg)
               for sg in self.neutron.list_security_groups(id=[])['security_groups']
               ]
        for security_group in sgs:
            security_group.ports = {}
            self._sgs[security_group.id] = security_group

    def _fetch_subnets(self):
        if self.verbose:
            print color('blue',"Fetching subnet listing ....")
        subnets = self.neutron.list_subnets()['subnets']
        for subnet in subnets:
            self._subnets[subnet['id']] = AttrDict(subnet)

    def _get_sg(self, sg_id):
        if sg_id not in self._sgs:
            # retrieve any missing SG (from other tenants)
            self._sgs[sg_id] = self._attrdict_sg(
                self.neutron.show_security_group(sg_id))
        return self._sgs.get(sg_id, None)

    def _get_subnet(self, subnet_id):
        if subnet_id not in self._subnets:
            subnet = self.neutron.show_subnet(subnet_id)['subnet']
            self._subnets[subnet_id] = AttrDict(subnet)

        return self._subnets.get(subnet_id, None)

    def _fetch_ports(self):
        if self.verbose:
            print color('blue', "Fetching port information ....")
        ports = [AttrDict(port) for port in self.neutron.list_ports()['ports']]
        for port in ports:
            self._ports[port.id] = port
            for sg_id in port.security_groups:
                self._sgs[sg_id].ports[port.id] = port

    def _iter_rules_with_remote_gid(self, rules):
        for rule in rules:
            if rule.remote_group_id is not None:
                yield rule

    def iter_sgs_with_remote_group_ids(self):
        sgs = []

        for sg_id, sg in self._sgs.iteritems():
            rules_rgid = list(self._iter_rules_with_remote_gid(sg.security_group_rules))
            if len(rules_rgid)>0:
                yield sg

    def _report_equivalent_subnet_CIDRs(self, sg):
        subnets = self._get_remote_subnets_from_remote_gid_rules(sg)
        if len(subnets)>0:
            print color('warning',"  Equivalent remote subnet CIDRs:")
        for __, subnet in subnets.iteritems():
            print color('warning',"    subnet: %(name)s\tCIDR: %(cidr)s" % subnet)

    def _build_cmdline_del_rule(self, rule):
        cmd = ["neutron security-group-rule-delete",
               "%(id)s"]

        return (" ".join(cmd)) % rule

    def _build_base_cmdline_add_from_rule(self, rule):
        cmd = ["neutron security-group-rule-create %(security_group_id)s",
               "--tenant-id %(tenant_id)s",
               "--direction %(direction)s",
               "--ethertype %(ethertype)s"]

        if rule.protocol:
            cmd.append("--protocol %(protocol)s")

        if rule.port_range_max:
            cmd.append("--port-range-max %(port_range_max)s")

        if rule.port_range_min:
            cmd.append("--port-range-min %(port_range_min)s")

        return (" \\\n                                ".join(cmd)) % rule

    def _build_cmdline_add_from_rule_and_subnet(self, rule, subnet):
        return (self._build_base_cmdline_add_from_rule(rule) +
                " --remote-ip-prefix %(cidr)s" % subnet)

    def _print_equivalent_subnet_rules(self, sg):
        rules = self._iter_rules_with_remote_gid(sg.security_group_rules)
        for rule in rules:
            rule_remote_ports = self._get_remote_ports_from_sg_rules([rule])
            subnets = self._get_ports_subnets(rule_remote_ports)
            if len(subnets)>0:
                for __, subnet in subnets.iteritems():
                    if ((rule.ethertype == 'IPv4' and
                         subnet.ip_version == 4) or
                        (rule.ethertype == 'IPv6' and
                         subnet.ip_version == 6)):

                        print self._build_cmdline_add_from_rule_and_subnet(
                            rule, subnet)

    def _print_remove_remote_gid_rules(self, sg):
        rules = self._iter_rules_with_remote_gid(sg.security_group_rules)
        for rule in rules:
            print self._build_cmdline_del_rule(rule)

    def _get_remote_subnets_from_remote_gid_rules(self, sg):
        rules = self._iter_rules_with_remote_gid(sg.security_group_rules)
        remote_ports = self._get_remote_ports_from_sg_rules(rules)
        return self._get_ports_subnets(remote_ports)

    def _get_ports_subnets(self, ports):
        subnets = {}
        for __, port in ports.iteritems():
            for ip in port.fixed_ips:
                subnets[ip['subnet_id']] = self._get_subnet(ip['subnet_id'])
        return subnets

    def _get_remote_ports_from_sg_rules(self, rules):
        remote_ports = {}
        for rule in rules:
            sg_rg_id = rule.remote_group_id
            remote_sg = self._get_sg(sg_rg_id)
            for port_id, port in remote_sg.ports.iteritems():
                remote_ports[port_id] = port
        return remote_ports

    def _extend_sg_info(self, sg):
        sg.unused = (sg.ports==0)
        sg.tenant = self._get_tenant(sg.tenant_id)
        if sg.unused and not sg.tenant:
            return
        sg.tenant_name = (sg.tenant.name if sg.tenant
                          else "<unknown: %s>" % sg.tenant_id)
        sg.used_str = "(NOT USED)" if sg.unused else ""
        return sg


class SecurityGroupScaleHealer(SecurityGroupScaleHealerBase):

    def sg_rpc_mitigation_report(self):
        for bad_sg in self.iter_sgs_with_remote_group_ids():
            self._extend_sg_info(bad_sg)
            print color('header',"\nsecurity_group %(id)s (%(name)s) has remote "
                                 "gid rules %(used_str)s\n  tenant: "
                                 "%(tenant_name)s" % bad_sg)

            for port_id, port in bad_sg.ports.iteritems():
                ip_addresses = ", ".join(
                    [ip['ip_address'] for ip in port.fixed_ips])
                port_info = {'id': port.id, 'ips': ip_addresses}
                print ("\tport %(id)s with ips: %(ips)s" % port_info)
            self._report_equivalent_subnet_CIDRs(bad_sg)

    def sg_rpc_mitigation_script(self):
        print "# This is a script to mitigate security groups scaling issues"
        print "# it will create alternative rules to the ones containing"
        print "# remote security group references, and delete such rules"
        print ""
        print "# This tool is BETA, Use at your own risk, please review the"
        print "# changes manually"
        print ""
        for bad_sg in self.iter_sgs_with_remote_group_ids():
            self._extend_sg_info(bad_sg)
            print "# sg %(id)s (%(name)s), tenant: %(tenant_name)s " % bad_sg
            self._print_equivalent_subnet_rules(bad_sg)
            print ""
            self._print_remove_remote_gid_rules(bad_sg)
            print ""



def build_parser():
    def extra_help():
        print ""
        print "Commands:"
        print ""
        print "sg-rpc-mitigation-report :  Report security groups with"
        print "          potential scale issues in RHOS4/5 (H/K), due"
        print "          to references to other groups in rules"
        print ""
        print "sg-rpc-mitigation-script : this command will dump a set of"
        print "          neutron commands to cleanup the rules from"
        print "          remote group references, inserting equivalent CIDR"
        print "          ranges instead"
        print ""
    parser = osclients.build_parser(extra_help)
    parser.add_argument("command",
                        type=str,
                        help="The command we want to execute")

    return parser

def main():
    options = build_parser().parse_args()
    neutron = osclients.create_neutron_client(options)
    keystone = osclients.create_keystone_client(options)
    if (options.command == 'report' or
        options.command == 'sg-rpc-mitigation-report'):
        healer = SecurityGroupScaleHealer(neutron, keystone)
        healer.sg_rpc_mitigation_report()
    elif options.command == 'sg-rpc-mitigation-script':
        healer = SecurityGroupScaleHealer(neutron, keystone, verbose=False)
        healer.sg_rpc_mitigation_script()
    else:
        print "Unknown command, try -h"
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
