from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch
from subprocess import TimeoutExpired

from xray_fluent.platform.windows.dns_cache import cached_addresses, read_dns_cache
from xray_fluent.network.country_resolver import CountryResolver
from xray_fluent.network.ping_worker import _tcp_observation
from xray_fluent.profiles.geoip import CountryDatabase


def record(name, value, kind='A', **extra):
    return dict(Entry=name, Data=value, RecordType=kind, Status=0, TimeToLive=60, **extra)


class CachedCountryTests(TestCase):
    def test_aliases_ipv6_expiry_negative_and_cycles(self):
        records = [record('VPN.EXAMPLE.', 'target.example.', 'CNAME'),
                   record('target.example', '8.8.8.8'),
                   record('v6.example', '2606:4700:4700::1111', 'AAAA'),
                   record('cycle-a', 'cycle-b', 'CNAME'), record('cycle-b', 'cycle-a', 'CNAME'),
                   record('local', '127.0.0.1')]
        records += [dict(record('expired', '1.1.1.1'), TimeToLive=0),
                    dict(record('negative', '1.1.1.1'), Status=9003)]
        result = cached_addresses(records)
        self.assertEqual(result['vpn.example'], ('8.8.8.8',))
        self.assertEqual(result['v6.example'], ('2606:4700:4700::1111',))
        self.assertFalse(result['cycle-a'])
        for name in ('expired', 'negative', 'local'):
            self.assertNotIn(name, result)

    def test_cache_timeout_is_a_local_miss(self):
        with patch('xray_fluent.platform.windows.dns_cache.sys.platform', 'win32'), patch(
                'xray_fluent.platform.windows.dns_cache.run_text', side_effect=TimeoutExpired('powershell', 5)):
            self.assertEqual(read_dns_cache(), {})

    def test_domain_country_uses_only_cache_and_mmdb(self):
        database = CountryDatabase()
        database._reader = Mock()
        database._reader.get.return_value = {'country': {'iso_code': 'US'}}
        factory = MagicMock()
        factory.return_value.__enter__.return_value = database
        cache = Mock(return_value={'vpn.example': ('8.8.8.8',)})
        worker = CountryResolver([('node', ('vpn.example',), ('vpn.example',))],
                                 database_factory=factory, cache_provider=cache)
        observed = []
        worker.resolved.connect(observed.append)
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')), patch(
                'socket.socket', side_effect=AssertionError('network forbidden')):
            worker.run()
        self.assertEqual(observed, [{'node': (('vpn.example',), 'US')}])
        cache.assert_called_once()
        database.country.cache_clear()

    def test_ping_reuses_peer_of_its_single_existing_connection(self):
        connection = MagicMock()
        connection.__enter__.return_value.getpeername.return_value = ('8.8.8.8', 443)
        with patch('socket.create_connection', return_value=connection) as connect, patch(
                'socket.getaddrinfo', side_effect=AssertionError('extra DNS forbidden')):
            ms, addresses = _tcp_observation('vpn.example', 443)
        connect.assert_called_once_with(('vpn.example', 443), timeout=2.0)
        self.assertGreaterEqual(ms, 0)
        self.assertEqual(addresses, ('8.8.8.8',))
