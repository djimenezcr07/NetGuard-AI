import csv,html,io,json,os,sqlite3
from collections import Counter
from contextlib import asynccontextmanager,closing
from datetime import datetime,timezone
from pathlib import Path
from fastapi import FastAPI,File,HTTPException,Query,UploadFile
from fastapi.responses import FileResponse,HTMLResponse,Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from . import db
from .analysis import analyze,VERSION
from .importer import parse

ROOT=Path(__file__).resolve().parents[1]
MAX_MB=int(os.environ.get('NETGUARD_MAX_MB','5'))
if not 1<=MAX_MB<=50:raise RuntimeError('NETGUARD_MAX_MB debe estar entre 1 y 50.')
@asynccontextmanager
async def lifespan(_):db.initialize();yield
app=FastAPI(title='NetGuard AI',lifespan=lifespan)
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')

def now():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def fail_missing(row):
    if row is None:raise HTTPException(404,'ImportaciÃ³n no encontrada.')
    return row

def load_import(con,id):return fail_missing(con.execute('SELECT * FROM imports WHERE id=?',(id,)).fetchone())
def validate_timestamp(value):
    if not value:return None
    try:
        d=datetime.fromisoformat(value.replace('Z','+00:00'))
        if d.tzinfo is None or d.utcoffset() is None:raise ValueError()
        return d.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    except ValueError:raise HTTPException(400,'Las fechas deben estar en ISO 8601 con zona horaria.')

def summary(parsed):return {'total':parsed['total'],'accepted':len(parsed['valid']),'rejected':len(parsed['rejected']),'rejections':parsed['rejected'],'columns':parsed['columns']}
async def read_upload(file):
    content=await file.read(MAX_MB*1024*1024+1)
    try:return content,parse(content,file.filename or '',MAX_MB*1024*1024)
    except ValueError as exc:raise HTTPException(400,str(exc)) from exc

def save_import(content,parsed,filename):
    if not parsed['valid']:raise HTTPException(400,'No hay filas vÃ¡lidas para guardar.')
    name=Path((filename or 'datos.csv').replace('\\','/')).name[:200]
    example=ROOT/'examples'/'actividad_sintetica.csv'
    source='sintÃ©tico incluido' if example.exists() and content==example.read_bytes() else 'archivo local'
    with closing(db.connect()) as con:
        try:
            with con:
                cursor=con.execute('INSERT INTO imports(name,created_at,accepted,rejected,source,columns_json) VALUES(?,?,?,?,?,?)',(name,now(),len(parsed['valid']),len(parsed['rejected']),source,json.dumps(parsed['columns'])))
                id=cursor.lastrowid
                for e in parsed['valid']:
                    con.execute('INSERT INTO events(import_id,line,timestamp,source_ip,destination_ip,source_port,destination_port,protocol,action,bytes,fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(id,e['line'],e['timestamp'],e['source_ip'],e['destination_ip'],e['source_port'],e['destination_port'],e['protocol'],e['action'],e['bytes'],e['fingerprint']))
                con.executemany('INSERT INTO rejected_rows(import_id,line,reason) VALUES(?,?,?)',[(id,x['line'],x['reason']) for x in parsed['rejected']])
            return id
        except sqlite3.Error as exc:raise HTTPException(500,'No se pudo guardar la importaciÃ³n; no se conservaron cambios parciales.') from exc

@app.get('/')
def index():return FileResponse(ROOT/'static'/'index.html')
@app.get('/api/health')
def health():
    try:
        with closing(db.connect()) as con:con.execute('SELECT 1').fetchone()
        return {'status':'disponible','version':VERSION,'storage':'SQLite local'}
    except sqlite3.Error:raise HTTPException(503,'La base de datos local no estÃ¡ disponible.')
@app.get('/api/examples/actividad')
def example():return FileResponse(ROOT/'examples'/'actividad_sintetica.csv',media_type='text/csv',filename='actividad_sintetica.csv')
@app.post('/api/imports/preview')
async def preview(file:UploadFile=File(...)):
    _,parsed=await read_upload(file);return summary(parsed)
@app.post('/api/imports')
async def create_import(file:UploadFile=File(...)):
    content,parsed=await read_upload(file);id=save_import(content,parsed,file.filename);return {'id':id,**summary(parsed)}
@app.get('/api/imports')
def imports():
    with closing(db.connect()) as con:
        rows=con.execute('SELECT i.*,MIN(e.timestamp) start_time,MAX(e.timestamp) end_time FROM imports i LEFT JOIN events e ON e.import_id=i.id GROUP BY i.id ORDER BY i.id DESC').fetchall()
        return [dict(x) for x in rows]
@app.delete('/api/imports/{id}')
def delete_import(id:int):
    with closing(db.connect()) as con:
        with con:cur=con.execute('DELETE FROM imports WHERE id=?',(id,))
        if not cur.rowcount:raise HTTPException(404,'ImportaciÃ³n no encontrada.')
    return Response(status_code=204)
@app.get('/api/imports/{id}/rejections')
def rejections(id:int):
    with closing(db.connect()) as con:
        load_import(con,id);return [dict(x) for x in con.execute('SELECT line,reason FROM rejected_rows WHERE import_id=? ORDER BY line',(id,))]
@app.get('/api/imports/{id}/overview')
def overview(id:int):
    with closing(db.connect()) as con:
        imp=dict(load_import(con,id));base=(id,)
        time=con.execute('SELECT MIN(timestamp),MAX(timestamp) FROM events WHERE import_id=?',base).fetchone();imp['start_time']=time[0];imp['end_time']=time[1]
        protocol=[dict(r) for r in con.execute('SELECT protocol,COUNT(*) count FROM events WHERE import_id=? GROUP BY protocol ORDER BY count DESC',base)]
        ports=[dict(r) for r in con.execute('SELECT destination_port port,COUNT(*) count FROM events WHERE import_id=? GROUP BY destination_port ORDER BY count DESC,destination_port LIMIT 6',base)]
        timeline=[dict(r) for r in con.execute("SELECT substr(timestamp,1,13)||':00Z' hour,COUNT(*) count FROM events WHERE import_id=? GROUP BY substr(timestamp,1,13) ORDER BY hour LIMIT 1000",base)]
        last=con.execute('SELECT id,created_at,steps_json FROM runs WHERE import_id=? ORDER BY id DESC LIMIT 1',base).fetchone()
        if last:
            count=con.execute('SELECT COUNT(*) FROM findings WHERE run_id=?',(last['id'],)).fetchone()[0];run={'id':last['id'],'created_at':last['created_at'],'steps':json.loads(last['steps_json']),'findings':count}
        else:run=None
        return {'import':imp,'protocols':protocol,'ports':ports,'timeline':timeline,'run':run}
@app.get('/api/imports/{id}/events')
def events(id:int,source:str='',destination:str='',port:int|None=Query(None,ge=0,le=65535),protocol:str='',start:str='',end:str='',sort:str='timestamp',direction:str='desc',page:int=Query(1,ge=1),page_size:int=Query(20,ge=1,le=100)):
    allowed={'timestamp','source_ip','destination_ip','destination_port','protocol','bytes'}
    if sort not in allowed or direction not in {'asc','desc'}:raise HTTPException(400,'Ordenamiento no permitido.')
    if protocol and protocol.upper() not in {'TCP','UDP','ICMP'}:raise HTTPException(400,'Protocolo no admitido.')
    begin=validate_timestamp(start);finish=validate_timestamp(end)
    if begin and finish and begin>finish:raise HTTPException(400,'La fecha inicial debe ser anterior a la final.')
    where=['import_id=?'];values=[id]
    for field,value in [('source_ip',source),('destination_ip',destination),('destination_port',port),('protocol',protocol.upper())]:
        if value is not None and value!='': where.append(f'{field}=?');values.append(value)
    if begin:where.append('timestamp>=?');values.append(begin)
    if finish:where.append('timestamp<=?');values.append(finish)
    clause=' AND '.join(where)
    with closing(db.connect()) as con:
        load_import(con,id);total=con.execute(f'SELECT COUNT(*) FROM events WHERE {clause}',values).fetchone()[0]
        rows=con.execute(f'SELECT id,line,timestamp,source_ip,destination_ip,source_port,destination_port,protocol,action,bytes FROM events WHERE {clause} ORDER BY {sort} {direction.upper()},id {direction.upper()} LIMIT ? OFFSET ?',values+[page_size,(page-1)*page_size]).fetchall()
        return {'items':[dict(x) for x in rows],'total':total,'page':page,'page_size':page_size}
@app.get('/api/events/{id}')
def event_detail(id:int):
    with closing(db.connect()) as con:
        row=con.execute('SELECT id,line,import_id,timestamp,source_ip,destination_ip,source_port,destination_port,protocol,action,bytes FROM events WHERE id=?',(id,)).fetchone()
        if not row:raise HTTPException(404,'Evento no encontrado.')
        return dict(row)

class AnalysisRequest(BaseModel):
    failure_threshold:int=Field(default=8,ge=2,le=10000)
    port_threshold:int=Field(default=8,ge=2,le=65536)
    window_minutes:int=Field(default=5,ge=1,le=1440)
    contamination:float=Field(default=0.05,ge=.01,le=.3)
@app.post('/api/imports/{id}/analyze')
def run_analysis(id:int,request:AnalysisRequest):
    with closing(db.connect()) as con:
        imp=load_import(con,id);events=[dict(x) for x in con.execute('SELECT * FROM events WHERE import_id=? ORDER BY timestamp,id',(id,))]
        if not events:raise HTTPException(400,'La importaciÃ³n no contiene eventos vÃ¡lidos.')
        params=request.model_dump();findings,steps=analyze(events,json.loads(imp['columns_json']),params)
        try:
            with con:
                cur=con.execute('INSERT INTO runs(import_id,created_at,params_json,steps_json,version) VALUES(?,?,?,?,?)',(id,now(),json.dumps(params),json.dumps(steps,ensure_ascii=False),VERSION));run_id=cur.lastrowid
                for f in findings:
                    cur=con.execute('INSERT INTO findings(run_id,method,title,source_ip,destination_ip,start_time,end_time,metrics_json,details_json) VALUES(?,?,?,?,?,?,?,?,?)',(run_id,f['method'],f['title'],f['source_ip'],f['destination_ip'],f['start_time'],f['end_time'],json.dumps(f['metrics'],ensure_ascii=False),json.dumps(f['details'],ensure_ascii=False)))
                    con.executemany('INSERT INTO finding_events(finding_id,event_id) VALUES(?,?)',[(cur.lastrowid,eid) for eid in f['event_ids']])
            return {'run_id':run_id,'findings':len(findings),'steps':steps,'params':params}
        except sqlite3.Error as exc:raise HTTPException(500,'No se pudo guardar el anÃ¡lisis; no se conservaron cambios parciales.') from exc
@app.get('/api/imports/{id}/findings')
def findings(id:int):
    with closing(db.connect()) as con:
        load_import(con,id);run=con.execute('SELECT * FROM runs WHERE import_id=? ORDER BY id DESC LIMIT 1',(id,)).fetchone()
        if not run:return {'run':None,'items':[]}
        items=[]
        for r in con.execute('SELECT f.*,COUNT(fe.event_id) event_count FROM findings f LEFT JOIN finding_events fe ON fe.finding_id=f.id WHERE f.run_id=? GROUP BY f.id ORDER BY f.id',(run['id'],)):
            item=dict(r);item['metrics']=json.loads(item.pop('metrics_json'));item['details']=json.loads(item.pop('details_json'));items.append(item)
        return {'run':{'id':run['id'],'created_at':run['created_at'],'params':json.loads(run['params_json']),'steps':json.loads(run['steps_json']),'version':run['version']},'items':items}
@app.get('/api/imports/{id}/findings.json')
def findings_download(id:int):
    payload=findings(id)
    if not payload['run']:raise HTTPException(400,'Primero ejecutá un análisis.')
    return Response(json.dumps(payload,ensure_ascii=False,indent=2),media_type='application/json',headers={'Content-Disposition':'attachment; filename="hallazgos-netguard.json"'})
@app.get('/api/findings/{id}')
def finding_detail(id:int):
    with closing(db.connect()) as con:
        row=con.execute('SELECT * FROM findings WHERE id=?',(id,)).fetchone()
        if not row:raise HTTPException(404,'Hallazgo no encontrado.')
        item=dict(row);item['metrics']=json.loads(item.pop('metrics_json'));item['details']=json.loads(item.pop('details_json'))
        total=con.execute('SELECT COUNT(*) FROM finding_events WHERE finding_id=?',(id,)).fetchone()[0]
        events=con.execute('SELECT e.id,e.line,e.timestamp,e.source_ip,e.destination_ip,e.source_port,e.destination_port,e.protocol,e.action,e.bytes FROM events e JOIN finding_events fe ON fe.event_id=e.id WHERE fe.finding_id=? ORDER BY e.timestamp,e.id LIMIT 200',(id,)).fetchall()
        return {'finding':item,'events':[dict(x) for x in events],'total_events':total,'limit':200}
@app.get('/api/imports/{id}/report')
def report(id:int):
    with closing(db.connect()) as con:
        imp=load_import(con,id);run=con.execute('SELECT * FROM runs WHERE import_id=? ORDER BY id DESC LIMIT 1',(id,)).fetchone()
        if not run:raise HTTPException(400,'Primero ejecutÃ¡ un anÃ¡lisis.')
        dates=con.execute('SELECT MIN(timestamp),MAX(timestamp) FROM events WHERE import_id=?',(id,)).fetchone()
        items=con.execute('SELECT f.*,COUNT(fe.event_id) event_count FROM findings f LEFT JOIN finding_events fe ON fe.finding_id=f.id WHERE f.run_id=? GROUP BY f.id ORDER BY f.id',(run['id'],)).fetchall()
        esc=lambda s:html.escape(str(s))
        sections=''.join(f'<li><b>{esc(x["title"])}</b> Â· {esc(x["method"])} Â· {esc(x["source_ip"])} Â· {esc(x["start_time"])} a {esc(x["end_time"])} Â· {x["event_count"]} eventos Â· mÃ©tricas: {esc(x["metrics_json"])} Â· detalles: {esc(x["details_json"])} Â· ID de hallazgo {x["id"]}</li>' for x in items) or '<li>Sin hallazgos.</li>'
        steps=''.join(f'<li>{esc(x["name"])}: {esc(x["status"])} â€” {esc(x.get("reason",str(x.get("hallazgos",0))+" hallazgos"))}</li>' for x in json.loads(run['steps_json']))
        content=f"""<!doctype html><html lang='es'><meta charset='utf-8'><title>Informe NetGuard</title><style>body{{font:16px/1.6 sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#26322e}}li{{margin:10px 0}}code{{word-break:break-word}}</style><h1>Informe NetGuard AI</h1><p>Herramienta de anÃ¡lisis defensivo histÃ³rico. Los resultados requieren investigaciÃ³n y no confirman ataques.</p><h2>Fuente y cobertura</h2><p>{esc(imp['name'])} Â· {esc(imp['source'])} Â· anÃ¡lisis {esc(run['created_at'])} Â· motor {esc(run['version'])}<br>PerÃ­odo UTC: {esc(dates[0])} â€” {esc(dates[1])}<br>Aceptados: {imp['accepted']} Â· Rechazados: {imp['rejected']}</p><h2>ParÃ¡metros</h2><code>{esc(run['params_json'])}</code><h2>Pasos ejecutados u omitidos</h2><ul>{steps}</ul><h2>Hallazgos y evidencia</h2><p>Los identificadores permiten abrir la evidencia en la aplicaciÃ³n. El informe no incluye el contenido completo de los registros.</p><ul>{sections}</ul><h2>Limitaciones</h2><p>Ventanas fijas en UTC; Isolation Forest se ajusta a la importaciÃ³n y puede seÃ±alar actividad legÃ­tima. No hay evaluaciÃ³n con etiquetas ni precisiÃ³n industrial.</p></html>"""
        return HTMLResponse(content,headers={'Content-Disposition':'attachment; filename="informe-netguard.html"'})
