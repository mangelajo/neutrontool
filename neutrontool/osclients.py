import argparse
import os
import sys

import neutronclient.v2_0.client
import keystoneclient.v2_0.client

NEUTRON_API_VERSION = '2.0'

def _(s):
    return s

def env(*_vars, **kwargs):
    """Search for the first defined of possibly many env vars.

    Returns the first environment variable defined in vars, or
    returns the default defined in kwargs.

    """
    for v in _vars:
        value = os.environ.get(v, None)
        if value:
            return value
    return kwargs.get('default', '')

class CommandError():
    def __init__(self, error):
        self.error = error


class HelpAction(argparse.Action):
    """Provide a custom action so the -h and --help parser
    to the main app will print a list of the commands.

    The commands are determined by checking the CommandManager
    instance, passed in as the "default" value for the action.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        outputs = []
        max_len = 0
        parser.print_help()
        if self.default:
            extra_help_func = self.default
            extra_help_func()
        sys.exit(0)

def build_option_parser(description, version, extra_help_func):
    """Return an argparse option parser for this application.

    Subclasses may override this method to extend
    the parser with more global options.

    :param description: full description of the application
    :paramtype description: str
    :param version: version number for the application
    :paramtype version: str
    """
    parser = argparse.ArgumentParser(
        description=description,
        add_help=False, )
    parser.add_argument(
        '--version',
        action='version',
        version=version, )
    parser.add_argument(
        '-v', '--verbose', '--debug',
        action='count',
        dest='verbose_level',
        default=0,
        help='Increase verbosity of output and show tracebacks on'
             ' errors. You can repeat this option.')
    parser.add_argument(
        '-q', '--quiet',
        action='store_const',
        dest='verbose_level',
        const=0,
        help='Suppress output except warnings and errors.')
    parser.add_argument(
        '-h', '--help',
        action=HelpAction,
        nargs=0,
        default=extra_help_func,
        help="Show this help message and exit.")
    parser.add_argument(
        '-r', '--retries',
        metavar="NUM",
        default=0,
        help="How many times the request to the Neutron server should "
             "be retried if it fails.")
    _append_global_identity_args(parser)

    return parser

def _append_global_identity_args(parser):

    parser.add_argument(
        '--os-service-type', metavar='<os-service-type>',
        default=env('OS_NETWORK_SERVICE_TYPE', default='network'),
        help='Defaults to env[OS_NETWORK_SERVICE_TYPE] or network.')

    parser.add_argument(
        '--os-endpoint-type', metavar='<os-endpoint-type>',
        default=env('OS_ENDPOINT_TYPE', default='publicURL'),
        help='Defaults to env[OS_ENDPOINT_TYPE] or publicURL.')

    parser.add_argument(
        '--os_auth_strategy',
        default='keystone',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--os-auth-url', metavar='<auth-url>',
        default=env('OS_AUTH_URL'),
        help='Authentication URL, defaults to env[OS_AUTH_URL].')
    parser.add_argument(
        '--os_auth_url',
        help=argparse.SUPPRESS)

    project_name_group = parser.add_mutually_exclusive_group()
    project_name_group.add_argument(
        '--os-tenant-name', metavar='<auth-tenant-name>',
        default=env('OS_TENANT_NAME'),
        help='Authentication tenant name, defaults to '
             'env[OS_TENANT_NAME].')
    project_name_group.add_argument(
        '--os-project-name',
        metavar='<auth-project-name>',
        default=env('OS_PROJECT_NAME'),
        help='Another way to specify tenant name. '
             'This option is mutually exclusive with '
             ' --os-tenant-name. '
             'Defaults to env[OS_PROJECT_NAME].')

    parser.add_argument(
        '--os_tenant_name',
        help=argparse.SUPPRESS)

    project_id_group = parser.add_mutually_exclusive_group()
    project_id_group.add_argument(
        '--os-tenant-id', metavar='<auth-tenant-id>',
        default=env('OS_TENANT_ID'),
        help='Authentication tenant ID, defaults to '
             'env[OS_TENANT_ID].')
    project_id_group.add_argument(
        '--os-project-id',
        metavar='<auth-project-id>',
        default=env('OS_PROJECT_ID'),
        help='Another way to specify tenant ID. '
        'This option is mutually exclusive with '
        ' --os-tenant-id. '
        'Defaults to env[OS_PROJECT_ID].')

    parser.add_argument(
        '--os-username', metavar='<auth-username>',
        default=env('OS_USERNAME'),
        help='Authentication username, defaults to env[OS_USERNAME].')
    parser.add_argument(
        '--os_username',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--os-user-id', metavar='<auth-user-id>',
        default=env('OS_USER_ID'),
        help='Authentication user ID (Env: OS_USER_ID)')

    parser.add_argument(
        '--os_user_id',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--os-user-domain-id',
        metavar='<auth-user-domain-id>',
        default=env('OS_USER_DOMAIN_ID'),
        help='OpenStack user domain ID. '
             'Defaults to env[OS_USER_DOMAIN_ID].')

    parser.add_argument(
        '--os_user_domain_id',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--os-user-domain-name',
        metavar='<auth-user-domain-name>',
        default=env('OS_USER_DOMAIN_NAME'),
        help='OpenStack user domain name. '
             'Defaults to env[OS_USER_DOMAIN_NAME].')

    parser.add_argument(
        '--os_user_domain_name',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--os_project_id',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--os_project_name',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--os-project-domain-id',
        metavar='<auth-project-domain-id>',
        default=env('OS_PROJECT_DOMAIN_ID'),
        help='Defaults to env[OS_PROJECT_DOMAIN_ID].')

    parser.add_argument(
        '--os-project-domain-name',
        metavar='<auth-project-domain-name>',
        default=env('OS_PROJECT_DOMAIN_NAME'),
        help='Defaults to env[OS_PROJECT_DOMAIN_NAME].')

    parser.add_argument(
        '--os-cert',
        metavar='<certificate>',
        default=env('OS_CERT'),
        help="Path of certificate file to use in SSL "
             "connection. This file can optionally be "
             "prepended with the private key. Defaults "
             "to env[OS_CERT].")

    parser.add_argument(
        '--os-cacert',
        metavar='<ca-certificate>',
        default=env('OS_CACERT', default=None),
        help="Specify a CA bundle file to use in "
             "verifying a TLS (https) server certificate. "
             "Defaults to env[OS_CACERT].")

    parser.add_argument(
        '--os-key',
        metavar='<key>',
        default=env('OS_KEY'),
        help="Path of client key to use in SSL "
             "connection. This option is not necessary "
             "if your key is prepended to your certificate "
             "file. Defaults to env[OS_KEY].")

    parser.add_argument(
        '--os-password', metavar='<auth-password>',
        default=env('OS_PASSWORD'),
        help='Authentication password, defaults to env[OS_PASSWORD].')
    parser.add_argument(
        '--os_password',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--os-region-name', metavar='<auth-region-name>',
        default=env('OS_REGION_NAME'),
        help='Authentication region name, defaults to '
               'env[OS_REGION_NAME].')
    parser.add_argument(
        '--os_region_name',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--os-token', metavar='<token>',
        default=env('OS_TOKEN'),
        help='Authentication token, defaults to env[OS_TOKEN].')
    parser.add_argument(
        '--os_token',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--http-timeout', metavar='<seconds>',
        default=env('OS_NETWORK_TIMEOUT', default=None), type=float,
        help='Timeout in seconds to wait for an HTTP response. Defaults '
             'to env[OS_NETWORK_TIMEOUT] or None if not specified.')

    parser.add_argument(
        '--os-url', metavar='<url>',
        default=env('OS_URL'),
        help='Defaults to env[OS_URL].')
    parser.add_argument(
        '--os_url',
        help=argparse.SUPPRESS)

    parser.add_argument(
        '--insecure',
        action='store_true',
        default=env('NEUTRONCLIENT_INSECURE', default=False),
        help="Explicitly allow neutronclient to perform \"insecure\" "
             "SSL (https) requests. The server's certificate will "
             "not be verified against any certificate authorities. "
             "This option should be used with caution.")


def build_parser(extra_help_func=None):
    return build_option_parser('neutron-tools','0.1', extra_help_func)



def create_neutron_client(options=None):
    if not options:
        parser = build_parser()
        options = parser.parse_args()

    client = neutronclient.v2_0.client.Client(
        token=options.os_token,
        endpoint_url=options.os_url,
        auth_url=options.os_auth_url,
        tenant_name=options.os_tenant_name,
        tenant_id=options.os_tenant_id,
        username=options.os_username,
        user_id=options.os_user_id,
        password=options.os_password,
        region_name=options.os_region_name,
        auth_strategy=options.os_auth_strategy,
        service_type=options.os_service_type,
        endpoint_type=options.os_endpoint_type,
        insecure=options.insecure,
        ca_cert=options.os_cacert,
        timeout=options.http_timeout,
        retries=options.retries,
        raise_errors=False,
        log_credentials=True)
    return client


def create_keystone_client(options=None):
    if not options:
        parser = build_parser()
        options = parser.parse_args()
    client = keystoneclient.v2_0.client.Client(
        token=options.os_token,
        endpoint_url=options.os_url,
        auth_url=options.os_auth_url,
        tenant_name=options.os_tenant_name,
        tenant_id=options.os_tenant_id,
        username=options.os_username,
        user_id=options.os_user_id,
        password=options.os_password,
        region_name=options.os_region_name,
        auth_strategy=options.os_auth_strategy,
        service_type=options.os_service_type,
        endpoint_type=options.os_endpoint_type,
        insecure=options.insecure,
        ca_cert=options.os_cacert,
        timeout=options.http_timeout,
        retries=options.retries,
        raise_errors=False,
        log_credentials=True)
    return client
