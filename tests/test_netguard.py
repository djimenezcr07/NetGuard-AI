import csv,io,sqlite3
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from netguard.importer import parse
from netguard.analysis import analyze
from netguard import db
from netguard.app import app
ROOT=Path(__file__).resolve().parents[1]
SAMPLE=(ROOT/'examples/actividad_sintetica.csv').read_bytes()
MIXED=(ROOT/'examples/validacion_mixta.csv').read_bytes()

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setenv('NETGUARD_DB',str(tmp_path/'test.db'))
    with TestClient(app) as c:yield c

def upload(client,data=SAMPLE,name='actividad.csv',preview=False):
    return client.post('/api/imports/preview' if preview else '/api/imports',files={'file':(name,data,'text/csv')})

def test_preview_mixed_and_deduplicate(client):
    r=upload(client,MIXED,preview=True);assert r.status_code==200
    data=r.json();assert data['accepted']==1 and data['rejected']==4
    assert any('duplicado' in x['reason'] for x in data['rejections'])
    assert any('zona horaria' in x['reason'] for x in data['rejections'])
    assert client.get('/api/imports').json()==[]
    saved=upload(client,MIXED).json();assert saved['accepted']==1 and saved['rejected']==4
    assert len(client.get(f"/api/imports/{saved['id']}/rejections").json())==4

@pytest.mark.parametrize('data,name',[(b'','x.csv'),(b'a,b\n1,2','x.csv'),(b'\xff\xfe','x.csv'),(b'x','x.exe'),(b'timestamp,source_ip,destination_ip,destination_port,protocol\n"bad','x.csv')])
def test_invalid_files(client,data,name):
    assert upload(client,data,name,True).status_code==400
    assert client.get('/api/imports').json()==[]

def test_ip_ports_and_timezones():
    data=parse(MIXED,'validacion.csv',10**6)
    assert len(data['valid'])==1 and len(data['rejected'])==4
    assert data['valid'][0]['timestamp'].endswith('Z')
    raw=b'timestamp,source_ip,destination_ip,destination_port,protocol\n2025-01-01T03:00:00+03:00,192.0.2.1,198.51.100.1,443,TCP\n'
    assert parse(raw,'x.csv',1000)['valid'][0]['timestamp'].startswith('2025-01-01T00:00:00')

def test_rules_and_reproducible_model(client):
    iid=upload(client).json()['id'];r=client.post(f'/api/imports/{iid}/analyze',json={});assert r.status_code==200
    result=client.get(f'/api/imports/{iid}/findings').json();names={x['title'] for x in result['items']}
    assert 'Intentos fallidos frecuentes' in names and 'Conexiones a múltiples puertos' in names and 'Ventana estadísticamente inusual' in names
    first=result['items'][0];detail=client.get(f"/api/findings/{first['id']}").json();assert detail['events'] and detail['total_events']==first['event_count']
    first_model=[(x['source_ip'],x['metrics']) for x in result['items'] if x['method']=='modelo']
    client.post(f'/api/imports/{iid}/analyze',json={});again=client.get(f'/api/imports/{iid}/findings').json()
    assert first_model==[(x['source_ip'],x['metrics']) for x in again['items'] if x['method']=='modelo']
    assert client.post(f'/api/imports/{iid}/analyze',json={'contamination':0.8}).status_code==422

def test_rule_time_boundary_and_missing_fields():
    def e(i,t,port=22,action='failure'):return {'id':i,'timestamp':t,'source_ip':'192.0.2.1','destination_ip':'198.51.100.1','destination_port':port,'action':action,'bytes':None}
    ev=[e(1,'2025-01-01T00:04:59Z'),e(2,'2025-01-01T00:05:00Z')]
    params={'failure_threshold':2,'port_threshold':2,'window_minutes':5,'contamination':.05}
    findings,steps=analyze(ev,['timestamp','source_ip','destination_ip','destination_port','protocol','action'],params)
    assert findings==[] and steps[-1]['status']=='omitido'
    findings,steps=analyze(ev,['timestamp','source_ip','destination_ip','destination_port','protocol'],params)
    assert steps[0]['status']=='omitido'
    ev[1]['timestamp']='2025-01-01T00:04:58Z';findings,_=analyze(ev,['timestamp','source_ip','destination_ip','destination_port','protocol','action'],params)
    assert len(findings)==1 and set(findings[0]['event_ids'])=={1,2}

def test_events_filter_order_pagination_and_export(client):
    iid=upload(client).json()['id']
    r=client.get(f'/api/imports/{iid}/events',params={'source':'192.0.2.90','page_size':5,'sort':'timestamp','direction':'asc'});data=r.json()
    assert data['total']==12 and len(data['items'])==5 and all(x['source_ip']=='192.0.2.90' for x in data['items'])
    assert data['items'][0]['timestamp']<=data['items'][1]['timestamp']
    assert client.get(f'/api/imports/{iid}/events',params={'sort':'id; DROP TABLE events'}).status_code==400
    assert client.get(f'/api/imports/{iid}/events',params={'start':'2025-01-01T00:00:00'}).status_code==400
    assert client.get(f'/api/imports/{iid}/report').status_code==400
    client.post(f'/api/imports/{iid}/analyze',json={});report=client.get(f'/api/imports/{iid}/report')
    assert report.status_code==200 and 'no confirman ataques' in report.text and 'attachment' in report.headers['content-disposition']

def test_delete_cascades(client):
    iid=upload(client).json()['id'];client.post(f'/api/imports/{iid}/analyze',json={});fid=client.get(f'/api/imports/{iid}/findings').json()['items'][0]['id']
    assert client.delete(f'/api/imports/{iid}').status_code==204
    assert client.get(f'/api/findings/{fid}').status_code==404
    with db.connect() as conn:
        for table in ('events','runs','findings','finding_events','rejected_rows'):
            assert conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]==0

def test_atomic_rollback(client):
    with db.connect() as conn:
        conn.execute("CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'test'); END;")
    r=upload(client);assert r.status_code==500
    assert client.get('/api/imports').json()==[]

def test_no_action_column_is_skipped(client):
    data=b'timestamp,source_ip,destination_ip,destination_port,protocol\n2025-01-01T00:00:00Z,192.0.2.1,198.51.100.1,80,TCP\n'
    iid=upload(client,data).json()['id'];result=client.post(f'/api/imports/{iid}/analyze',json={}).json()
    assert result['steps'][0]['status']=='omitido' and result['steps'][-1]['status']=='omitido'
