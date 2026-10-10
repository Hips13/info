from pathlib import Path
module_source = Path(__file__).with_name('dns_proxy.py').read_text(encoding='utf-8')
exec(compile("__name__ = 'patch_tests'\n" + module_source, 'dns_proxy.py', 'exec'), globals())
# Appended to the production module and executed via stdin. No filesystem writes.
from unittest import TestCase, main as test_main
from unittest.mock import patch as mock_patch
import types

class MemoryChecks(TestCase):
    def setUp(self):
        self.c = sqlite3.connect(':memory:'); self.c.row_factory = sqlite3.Row
        self.c.executescript('CREATE TABLE settings(id INTEGER PRIMARY KEY,key TEXT,value TEXT); CREATE TABLE inbounds(id INTEGER PRIMARY KEY,enable INTEGER,protocol TEXT,tag TEXT,port INTEGER,node_id INTEGER,sniffing TEXT,stream_settings TEXT,settings TEXT);')
        self.cfg = dict(dns_url='https://geohide.ru/dns-query', geosite='google-gemini', direct_tag='direct', regular_dns=['1.1.1.1','8.8.8.8'], timeout_ms=4000)
        self.template = dict(dns={'servers':['1.1.1.1','8.8.8.8']},routing={'domainStrategy':'IPIfNonMatch','rules':[{'domain':['geosite:category-ru',r'regexp:.*\.ru$'],'outboundTag':'warp'}]},outbounds=[{'tag':'direct','protocol':'freedom','settings':{'noises':[]}}, {'tag':'warp','protocol':'socks','settings':{'password':'SECRET'}}])
        self.c.execute('INSERT INTO settings VALUES(1,?,?)',('xrayTemplateConfig',encode(self.template)))
        for i,proto,net in [(9,'vless','ws'),(19,'trojan','grpc'),(29,'vmess','httpupgrade'),(39,'vless','xhttp')]:
            self.c.execute('INSERT INTO inbounds VALUES(?,?,?,?,?,?,?,?,?)',(i,1,proto,'custom-'+str(i),i+1000,0,'{"enabled":false,"destOverride":["quic"],"routeOnly":true}',encode({'network':net,'privateKey':'SECRET'}),'USER_UUID'))
        self.c.commit(); self.args=types.SimpleNamespace(db='/etc/x-ui/in-memory-test.db',state='memory',ids=None,tags=None,accept_warnings=True,service='x-ui')
        self.state=None
    def tearDown(self): self.c.close()
    def snap(self): return [tuple(r) for r in self.c.execute('SELECT * FROM inbounds')]
    def commit_plan(self,p):
        def save(path,s):self.state=s
        with mock_patch.dict(globals(),{'write_state':save}):apply(self.c,self.cfg,self.args,p)
    def undo(self):
        with mock_patch.object(Path,'read_text',return_value=encode(self.state)):rollback(self.c,self.args)
    def hy2(self):
        self.c.execute('INSERT INTO inbounds VALUES(6,1,?,?,?,?,?,?,?)',('hysteria','hy2',443,0,'{"enabled":false}','{"network":"hysteria"}','HY2_SECRET'));self.c.commit()
    def test_roundtrip_and_idempotence(self):
        before=self.snap();p=make_plan(self.c,self.cfg);self.assertEqual(len(p['targets']),4);self.commit_plan(p)
        after=self.snap()
        for a,b in zip(before,after):self.assertEqual(a[:6],b[:6]);self.assertEqual(a[7:],b[7:])
        self.assertNotIn('SECRET',encode(self.state));self.assertNotIn('USER_UUID',encode(self.state))
        p=make_plan(self.c,self.cfg);self.assertFalse(p['sniffing']);self.assertFalse(p['template']);self.commit_plan(p);self.assertEqual(after,self.snap())
        self.undo();self.assertEqual(before,self.snap());self.assertEqual(self.template,json.loads(self.c.execute('SELECT value FROM settings').fetchone()[0]))
    def test_hy2_allows_global_change_but_row_is_preserved(self):
        self.hy2();before=tuple(self.c.execute('SELECT * FROM inbounds WHERE id=6').fetchone())
        p=make_plan(self.c,self.cfg);self.assertTrue(p['template']);self.assertNotIn(6,[r['id'] for r in p['targets']])
        self.commit_plan(p)
        self.assertEqual(before,tuple(self.c.execute('SELECT * FROM inbounds WHERE id=6').fetchone()))
        self.undo()
        self.assertEqual(before,tuple(self.c.execute('SELECT * FROM inbounds WHERE id=6').fetchone()))
    def test_hy2_sniff_only(self):
        self.commit_plan(make_plan(self.c,self.cfg));self.c.execute("UPDATE inbounds SET sniffing='{}' WHERE id=9");self.c.commit();self.hy2()
        before=tuple(self.c.execute('SELECT * FROM inbounds WHERE id=6').fetchone());p=make_plan(self.c,self.cfg);self.assertFalse(p['template']);self.commit_plan(p)
        self.assertEqual(before,tuple(self.c.execute('SELECT * FROM inbounds WHERE id=6').fetchone()))
    def test_manual_selection_and_remote_disabled(self):
        self.assertEqual([r['id'] for r in make_plan(self.c,self.cfg,{19})['targets']],[19])
        self.c.execute('UPDATE inbounds SET node_id=7 WHERE id=29');self.c.execute('UPDATE inbounds SET enable=0 WHERE id=39');self.c.commit()
        self.assertEqual(len(make_plan(self.c,self.cfg)['targets']),2)
        for ids in [{29},{39},{999}]:
            with self.assertRaises(Refuse):make_plan(self.c,self.cfg,ids)
    def test_conflicting_routes(self):
        self.template['routing']['rules'].append({'domain':['geosite:google'],'outboundTag':'another-proxy'})
        self.c.execute('UPDATE settings SET value=?',(encode(self.template),));self.c.commit()
        p=make_plan(self.c,self.cfg);self.assertTrue(p['warnings'])
        self.args.accept_warnings=False
        before=self.snap()
        with self.assertRaises(Refuse):self.commit_plan(p)
        self.assertEqual(before,self.snap())
        self.args.accept_warnings=True;self.commit_plan(p)
        self.assertEqual(self.template['routing']['rules'],json.loads(self.c.execute('SELECT value FROM settings').fetchone()[0])['routing']['rules'])
    def test_gemini_warp_is_not_managed_or_a_blocker(self):
        for enabled in [False,True]:
            t=copy.deepcopy(self.template);t['routing']['rules'].append({'domain':['geosite:google-gemini'],'outboundTag':'warp','enabled':enabled})
            self.c.execute('UPDATE settings SET value=?',(encode(t),));self.c.commit()
            p=make_plan(self.c,self.cfg);self.commit_plan(p)
            saved=json.loads(self.c.execute('SELECT value FROM settings').fetchone()[0])
            self.assertEqual(t['routing']['rules'],saved['routing']['rules'])
            self.undo()
    def test_concurrent_edit(self):
        p=make_plan(self.c,self.cfg);self.c.execute("UPDATE inbounds SET sniffing='{}' WHERE id=9");self.c.commit();before=self.snap()
        with self.assertRaises(Refuse):self.commit_plan(p)
        self.assertEqual(before,self.snap())
    def test_late_edit_blocks_undo(self):
        self.commit_plan(make_plan(self.c,self.cfg));self.c.execute("UPDATE inbounds SET sniffing='{}' WHERE id=9");self.c.commit();before=self.snap()
        with self.assertRaises(Refuse):self.undo()
        self.assertEqual(before,self.snap())
    def test_duplicate_dns_and_shared_rule(self):
        for extra in [[{'domains':['geosite:google-gemini','geosite:google']}],[{'domains':['geosite:google-gemini']},{'domains':['geosite:google-gemini']}]]:
            t=copy.deepcopy(self.template);t['dns']['servers'].extend(extra);self.c.execute('UPDATE settings SET value=?',(encode(t),));self.c.commit()
            p=make_plan(self.c,self.cfg);self.assertTrue(p['warnings']);self.commit_plan(p)
            dns=json.loads(self.c.execute('SELECT value FROM settings').fetchone()[0])['dns']
            matches=[s for s in dns['servers'] if isinstance(s,dict) and 'geosite:google-gemini' in s.get('domains',[])]
            self.assertEqual(len(matches),1);self.assertEqual(matches[0]['domains'],['geosite:google-gemini'])
            if len(extra)==1:
                self.assertTrue(any(isinstance(s,dict) and s.get('domains')==['geosite:google'] for s in dns['servers']))
            self.assertFalse(make_plan(self.c,self.cfg)['template']);self.undo()
    def test_provider_change(self):
        self.commit_plan(make_plan(self.c,self.cfg));self.cfg['dns_url']='https://other.example/dns-query';self.commit_plan(make_plan(self.c,self.cfg))
        d=json.loads(self.c.execute('SELECT value FROM settings').fetchone()[0])['dns']['servers'];self.assertEqual(len(d),3);self.assertEqual(d[-1]['address'],self.cfg['dns_url'])
    def test_address_validation(self):
        for address in ['https://geohide.ru/dns-query','https://dns.bezmezhau.com/dns-query','143.20.64.55','91.108.243.78']:
            self.assertEqual(validate_address(address),address)
        for address in ['143.20.64.55,91.108.243.78','dns.bezmezhau.com','https://geohide.ru','https://geohide.ru/','https://user:password@example.com/dns-query','2a01:4f9::1','143.20.64.55:53',' https://example.com/dns-query']:
            with self.assertRaises(Refuse):validate_address(address)
    def test_differently_named_freedom_and_default_order(self):
        t=copy.deepcopy(self.template);t['outbounds'][0]['tag']='my-direct';t['outbounds'].reverse()
        self.c.execute('UPDATE settings SET value=?',(encode(t),));self.c.commit();p=make_plan(self.c,self.cfg)
        self.assertGreaterEqual(len(p['warnings']),2);self.commit_plan(p)
        saved=json.loads(self.c.execute('SELECT value FROM settings').fetchone()[0]);self.assertEqual([o['tag'] for o in saved['outbounds']],['warp','my-direct'])
        self.assertEqual(saved['outbounds'][1]['settings']['domainStrategy'],'UseIPv4');self.undo()
    def test_interactive_cancellation_no_writes(self):
        before=self.snap()
        with mock_patch.dict(globals(),{'service_active':lambda s:True,'ask':lambda *a:'2'}):
            install(self.c,self.cfg,self.args)
        self.assertEqual(before,self.snap());self.assertIsNone(self.state)
    def test_interactive_success_and_user_rollback(self):
        for choice in ['1','2','3']:
            before=self.snap();answers=iter(['1',choice]);restarts=[]
            def save(path,s):self.state=s
            with mock_patch.dict(globals(),{'service_active':lambda s:True,'restart_service':lambda s:restarts.append(s),'ask':lambda *a:next(answers),'write_state':save}),mock_patch.object(Path,'read_text',side_effect=lambda *a,**k:encode(self.state)):
                install(self.c,self.cfg,self.args)
            self.assertEqual(len(restarts),2 if choice=='2' else 1)
            if choice=='2':self.assertEqual(before,self.snap())
            else:self.undo()
    def test_activation_failure_auto_rollback(self):
        before=self.snap();calls=[]
        def restart(s):
            calls.append(s)
            if len(calls)==1:raise Refuse('simulated activation failure')
        def save(path,s):self.state=s
        with mock_patch.dict(globals(),{'service_active':lambda s:True,'restart_service':restart,'ask':lambda *a:'1','write_state':save}),mock_patch.object(Path,'read_text',side_effect=lambda *a,**k:encode(self.state)):
            with self.assertRaises(Refuse):install(self.c,self.cfg,self.args)
        self.assertEqual(before,self.snap());self.assertEqual(len(calls),2)
    def test_provider_menu_presets_custom_and_bad_input(self):
        catalog={'providers':[{'name':'Example','doh':'https://example.org/dns-query','primary_ipv4':'143.20.64.55','secondary_ipv4':'91.108.243.78','note':'sample','source':'https://example.org/'},{'name':'Other','doh':'https://other.example/dns-query','note':'sample','source':'https://other.example/'}]}
        for inputs,expected in [(['1','1'],'https://example.org/dns-query'),(['1','2'],'143.20.64.55'),(['3','1','dns.example','https://dns.bezmezhau.com/dns-query'],'https://dns.bezmezhau.com/dns-query'),(['3','2','143.20.64.55,91.108.243.78','143.20.64.55'],'143.20.64.55')]:
            answers=iter(inputs)
            with mock_patch.dict(globals(),{'ask':lambda *a:next(answers)}),mock_patch.object(Path,'read_text',return_value=encode(catalog)):
                chosen=choose_provider(self.cfg,'memory-providers')
            self.assertEqual(chosen['dns_url'],expected)
            self.assertEqual(self.cfg['dns_url'],'https://geohide.ru/dns-query')

    def test_delayed_xray_start_and_timeout(self):
        def run_case(ready_after):
            clock = [0]
            def read(path, *args, **kwargs):
                if str(path).endswith('/children'):
                    return '456' if clock[0] >= ready_after else ''
                return 'xray-linux-amd64'
            with mock_patch.dict(globals(), {'service_active': lambda s: True}), mock_patch.object(subprocess, 'run', return_value=types.SimpleNamespace(stdout='123')), mock_patch.object(time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), mock_patch.object(Path, 'read_text', read):
                restart_service('x-ui')
            return clock[0]
        self.assertEqual(run_case(12), 12)
        self.assertEqual(run_case(29), 29)
        with self.assertRaises(Refuse):
            run_case(31)
test_main(argv=['memory_checks'],verbosity=2)

