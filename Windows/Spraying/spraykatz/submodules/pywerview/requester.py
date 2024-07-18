# -*- coding: utf8 -*-
# coding: utf-8
#
# This file comes from Pywerview project by Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2016
# Slightly modified for Spraykatz.

# Imports
import socket
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr, drsuapi, epm

class LDAPRequester():
    def __init__(self, domain_controller, domain=str(), user=(), password=str(), lmhash=str(), nthash=str()):
        self._domain_controller = domain_controller
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._queried_domain = None
        self._ads_path = None
        self._ads_prefix = None
        self._ldap_connection = None

    def _get_netfqdn(self):
        try:
            smb = SMBConnection(self._domain_controller, self._domain_controller)
        except socket.error:
            return str()

        smb.login(self._user, self._password, domain=self._domain,
                lmhash=self._lmhash, nthash=self._nthash)
        fqdn = smb.getServerDNSDomainName()
        smb.logoff()

        return fqdn

    def _create_ldap_connection(self, queried_domain=str(), ads_path=str(), ads_prefix=str()):
        if not self._domain:
            self._domain = self._get_netfqdn()

        if not queried_domain:
            queried_domain = self._get_netfqdn()
        self._queried_domain = queried_domain

        base_dn = str()

        if ads_prefix:
            self._ads_prefix = ads_prefix
            base_dn = '{},'.format(self._ads_prefix)

        if ads_path:
            # TODO: manage ADS path starting with 'GC://'
            if ads_path.upper().startswith('LDAP://'):
                ads_path = ads_path[7:]
            self._ads_path = ads_path
            base_dn += self._ads_path
        else:
            base_dn += ','.join('dc={}'.format(x) for x in self._queried_domain.split('.'))

        try:
            ldap_connection = ldap.LDAPConnection('ldap://{}'.format(self._domain_controller),
                                                  base_dn, self._domain_controller)
            ldap_connection.login(self._user, self._password, self._domain,
                                  self._lmhash, self._nthash)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldap_connection = ldap.LDAPConnection('ldaps://{}'.format(self._domain_controller),
                                                      base_dn, self._domain_controller)
                ldap_connection.login(self._user, self._password, self._domain,
                                      self._lmhash, self._nthash)
            else:
                raise e
        except socket.error as e:
            return

        self._ldap_connection = ldap_connection

    def _ldap_search(self, search_filter, class_result, attributes=list()):
        results = list()
        paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True,
                                                                   size=1000)
        try:
            search_results = self._ldap_connection.search(searchFilter=search_filter,
                                                          searchControls=[paged_search_control],
                                                          attributes=attributes)
        except ldap.LDAPSearchError as e:
            # If we got a "size exceeded" error, we get the partial results
            if e.error == 4:
                search_results = e.answers
            else:
                raise e
        # TODO: Filter parenthesis in LDAP filter
        except ldap.LDAPFilterSyntaxError as e:
            return list()

        for result in search_results:
            if not isinstance(result, ldapasn1.SearchResultEntry):
                continue

            results.append(class_result(result['attributes']))

        return results

    @staticmethod
    def _ldap_connection_init(f):
        def wrapper(*args, **kwargs):
            instance = args[0]
            queried_domain = kwargs.get('queried_domain', None)
            ads_path = kwargs.get('ads_path', None)
            ads_prefix = kwargs.get('ads_prefix', None)
            if (not instance._ldap_connection) or \
               (queried_domain != instance._queried_domain) or \
               (ads_path != instance._ads_path) or \
               (ads_prefix != instance._ads_prefix):
                if instance._ldap_connection:
                    instance._ldap_connection.close()
                instance._create_ldap_connection(queried_domain=queried_domain,
                                                 ads_path=ads_path, ads_prefix=ads_prefix)
            return f(*args, **kwargs)
        return wrapper

    def __enter__(self):
        self._create_ldap_connection()
        return self

    def __exit__(self, type, value, traceback):
        try:
            self._ldap_connection.close()
        except AttributeError:
            pass
        self._ldap_connection = None

class RPCRequester():
    def __init__(self, target_computer, domain=str(), user=(), password=str(), lmhash=str(), nthash=str()):
        self._target_computer = target_computer
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._pipe = None
        self._rpc_connection = None
        self._dcom = None
        self._wmi_connection = None

    def _create_rpc_connection(self, pipe):
        # Here we build the DCE/RPC connection
        self._pipe = pipe

        binding_strings = dict()
        binding_strings['srvsvc'] = srvs.MSRPC_UUID_SRVS
        binding_strings['wkssvc'] = wkst.MSRPC_UUID_WKST
        binding_strings['samr'] = samr.MSRPC_UUID_SAMR
        binding_strings['svcctl'] = scmr.MSRPC_UUID_SCMR
        binding_strings['drsuapi'] = drsuapi.MSRPC_UUID_DRSUAPI

        # TODO: try to fallback to TCP/139 if tcp/445 is closed
        if self._pipe == r'\drsuapi':
            string_binding = epm.hept_map(self._target_computer, drsuapi.MSRPC_UUID_DRSUAPI,
                                          protocol='ncacn_ip_tcp')
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(username=self._user, password=self._password,
                                         domain=self._domain, lmhash=self._lmhash,
                                         nthash=self._nthash)
        else:
            rpctransport = transport.SMBTransport(self._target_computer, 445, self._pipe,
                                                  username=self._user, password=self._password,
                                                  domain=self._domain, lmhash=self._lmhash,
                                                  nthash=self._nthash)

        rpctransport.set_connect_timeout(10)
        dce = rpctransport.get_dce_rpc()

        if self._pipe == r'\drsuapi':
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        try:
            dce.connect()
        except socket.error:
            self._rpc_connection = None
        else:
            dce.bind(binding_strings[self._pipe[1:]])
            self._rpc_connection = dce

 
    @staticmethod
    def _rpc_connection_init(pipe=r'\srvsvc'):
        def decorator(f):
            def wrapper(*args, **kwargs):
                instance = args[0]
                if (not instance._rpc_connection) or (pipe != instance._pipe):
                    if instance._rpc_connection:
                        instance._rpc_connection.disconnect()
                    instance._create_rpc_connection(pipe=pipe)
                if instance._rpc_connection is None:
                    return None
                return f(*args, **kwargs)
            return wrapper
        return decorator


class LDAPRPCRequester(LDAPRequester, RPCRequester):
    def __init__(self, target_computer, domain=str(), user=(), password=str(), lmhash=str(), nthash=str(), domain_controller=str()):
        # If no domain controller was given, we assume that the user wants to
        # target a domain controller to perform LDAP requests against
        if not domain_controller:
            domain_controller = target_computer
        LDAPRequester.__init__(self, domain_controller, domain, user, password,
                               lmhash, nthash)
        RPCRequester.__init__(self, target_computer, domain, user, password,
                               lmhash, nthash)
    def __enter__(self):
        try:
            LDAPRequester.__enter__(self)
        except (socket.error, IndexError):
            pass
        # This should work every time
        #RPCRequester.__enter__(self)

        return self

    def __exit__(self, type, value, traceback):
        LDAPRequester.__exit__(self, type, value, traceback)
        #RPCRequester.__exit__(self, type, value, traceback)
