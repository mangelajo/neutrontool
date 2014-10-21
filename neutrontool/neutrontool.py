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


class SecurityGroupScaleHealer():

    def __init__(self, neutron, keystone, dry_run=True):
        self.neutron = neutron
        self.keystone = keystone
        self.dry_run = dry_run
        self._prefetch_data()

    def _prefetch_data(self):
        self._sgs = {}
        self._ports = {}
        self._tenants = {}
        self._fetch_tenant_list()
        self._fetch_security_groups()
        self._fetch_ports()

    def _fetch_tenant_list(self):

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

        return self._tenants[id]

    def _attrdict_sg(self, sg_in):
        sg = AttrDict(sg_in)
        rules = sg.security_group_rules
        sg.security_group_rules = [AttrDict(rule) for rule in rules]
        return sg

    def _fetch_security_groups(self):
        print color('blue',"Fetching security group listing ....")
        sgs = [self._attrdict_sg(sg)
               for sg in self.neutron.list_security_groups(id=[])['security_groups']
               ]
        for security_group in sgs:
            security_group.ports = {}
            self._sgs[security_group.id] = security_group


    def _fetch_ports(self):
        print color('blue', "Fetching port information ....")
        ports = [AttrDict(port) for port in self.neutron.list_ports()['ports']]
        for port in ports:
            self._ports[port.id] = port
            for sg_id in port.security_groups:
                if sg_id not in self._sgs:
                    # retrieve any missing SG (from other tenants)
                    self_sgs[sg_id] = self._attrdict_sg(
                        self.neutron.show_security_group(sg_id))
                self._sgs[sg_id].ports[port.id] = port

    def _iter_rules_with_remote_gid(self, rules):
        for rule in rules:
            if rule.remote_group_id is not None:
                yield rule

    def iter_sgs_with_remote_group_ids(self):
        sgs = []

        for sg_id, sg in self._sgs.iteritems():
            rules_rgid = [self._iter_rules_with_remote_gid(sg.security_group_rules)]
            if len(rules_rgid)>0:
                yield sg

    def report(self):

        for bad_sg in self.iter_sgs_with_remote_group_ids():
            unused_sg = len(bad_sg.ports)==0
            used_str = "(NOT USED)" if unused_sg else ""
            bad_sg.used_str = used_str
            tenant = self._get_tenant(bad_sg.tenant_id)

            if unused_sg and not tenant:
                continue

            bad_sg.tenant_name = (tenant.name if tenant
                                  else "<unknown: %s>" % bad_sg.tenant_id)
            print color('header',"\nsecurity_group %(id)s (%(name)s) has remote "
                                 "gid rules %(used_str)s\n  tenant: "
                                 "%(tenant_name)s" % bad_sg)
            for port_id, port in bad_sg.ports.iteritems():
                ip_addresses = ", ".join([ip['ip_address'] for ip in port.fixed_ips])
                subnets = [ip['subnet_id'] for ip in port.fixed_ips]
                port_info = {'id': port.id, 'ips': ip_addresses}
                print ("\tport %(id)s with ips: %(ips)s" % port_info)

def build_parser():
    def extra_help():
        print ""
        print "Commands:"
        print ""
        print ("report : Report security with potential scale issues in\n"
               "         RHOS4/5 (H/K), due to references to other groups\n"
               "         in rules\n")
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
    print options.command
    if options.command == 'report':
        healer = SecurityGroupScaleHealer(neutron, keystone)
        healer.report()
    else:
        print "Unknown command, try -h"
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())