"""Reglas deterministas y anomalías por grupos de origen y hora UTC."""
from collections import defaultdict
from datetime import datetime,timezone
import math
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

VERSION='1.0.0'
def _bucket(timestamp,minutes):
    dt=datetime.fromisoformat(timestamp.replace('Z','+00:00'))
    return int(dt.timestamp())//(minutes*60)*(minutes*60)
def _time(seconds):return datetime.fromtimestamp(seconds,timezone.utc).isoformat().replace('+00:00','Z')
def _finding(method,title,source,dest,start,minutes,metrics,params,events):
    return {'method':method,'title':title,'source_ip':source,'destination_ip':dest,'start_time':_time(start),'end_time':_time(start+minutes*60),'metrics':metrics,'details':{'parametros':params,'limites':'Patrón estadístico o por reglas; requiere investigación y no confirma un ataque.'},'event_ids':[int(x['id']) for x in events]}

def analyze(events,columns,params):
    failures=params['failure_threshold'];ports=params['port_threshold'];window=params['window_minutes'];contamination=params['contamination']
    if not 2<=failures<=10000 or not 2<=ports<=65536 or not 1<=window<=1440 or not .01<=contamination<=.3:raise ValueError('Parámetros de análisis fuera de rango.')
    findings=[];steps=[]
    if 'action' not in columns:
        steps.append({'name':'Intentos fallidos','status':'omitido','reason':'La columna action no está presente.'})
    elif not any(e['action']!='unknown' for e in events):
        steps.append({'name':'Intentos fallidos','status':'omitido','reason':'No hay acciones conocidas en los datos.'})
    else:
        groups=defaultdict(list)
        for e in events:
            if e['action'] in ('failure','deny'):groups[(e['source_ip'],_bucket(e['timestamp'],window))].append(e)
        before=len(findings)
        for (src,t),items in groups.items():
            if len(items)>=failures:findings.append(_finding('regla','Intentos fallidos frecuentes',src,None,t,window,{'eventos_fallidos':len(items)}, {'umbral':failures,'ventana_minutos':window},items))
        steps.append({'name':'Intentos fallidos','status':'ejecutado','hallazgos':len(findings)-before})
    if not all(k in columns for k in ('source_ip','destination_ip','destination_port','timestamp')):
        steps.append({'name':'Múltiples puertos','status':'omitido','reason':'Faltan campos requeridos.'})
    else:
        groups=defaultdict(list)
        for e in events:groups[(e['source_ip'],e['destination_ip'],_bucket(e['timestamp'],window))].append(e)
        before=len(findings)
        for (src,dst,t),items in groups.items():
            count=len({e['destination_port'] for e in items})
            if count>=ports:findings.append(_finding('regla','Conexiones a múltiples puertos',src,dst,t,window,{'puertos_distintos':count,'eventos':len(items)}, {'umbral':ports,'ventana_minutos':window},items))
        steps.append({'name':'Múltiples puertos','status':'ejecutado','hallazgos':len(findings)-before})
    groups=defaultdict(list)
    for e in events:groups[(e['source_ip'],_bucket(e['timestamp'],60))].append(e)
    records=[];features=['eventos','destinos_distintos','puertos_distintos']
    use_action='action' in columns and any(e['action']!='unknown' for e in events)
    use_bytes='bytes' in columns and any(e['bytes'] is not None for e in events)
    if use_action:features.append('proporcion_fallidos')
    if use_bytes:features.append('bytes_totales')
    for (src,t),items in sorted(groups.items()):
        vals={'eventos':len(items),'destinos_distintos':len({e['destination_ip'] for e in items}),'puertos_distintos':len({e['destination_port'] for e in items})}
        if use_action:vals['proporcion_fallidos']=round(sum(e['action'] in ('failure','deny') for e in items)/len(items),4)
        if use_bytes:vals['bytes_totales']=sum(e['bytes'] or 0 for e in items)
        records.append((src,t,items,vals))
    if len(records)<20:
        steps.append({'name':'Isolation Forest','status':'omitido','reason':f'Datos insuficientes: {len(records)} grupos; se requieren al menos 20.'})
    else:
        matrix=np.array([[r[3][f] for f in features] for r in records],dtype=float)
        if sum(np.ptp(matrix[:,i])>0 for i in range(matrix.shape[1]))<2:
            steps.append({'name':'Isolation Forest','status':'omitido','reason':'Variación insuficiente en las características.'})
        else:
            try:
                model=IsolationForest(n_estimators=100,contamination=contamination,random_state=42,n_jobs=1)
                labels=model.fit_predict(matrix);scores=model.decision_function(matrix);count=0
                for (src,t,items,vals),label,score in zip(records,labels,scores):
                    if label==-1:
                        count+=1;metrics={**vals,'puntuacion':round(float(score),6)}
                        findings.append(_finding('modelo','Ventana estadísticamente inusual',src,None,t,60,metrics,{'modelo':'IsolationForest','semilla':42,'contaminacion':contamination,'caracteristicas':features,'sklearn':sklearn.__version__},items))
                steps.append({'name':'Isolation Forest','status':'ejecutado','hallazgos':count,'grupos':len(records),'caracteristicas':features,'bytes_faltantes':'Se imputan como cero' if use_bytes else 'Característica omitida','acciones_faltantes':'Se contabilizan como no fallidas' if use_action else 'Característica omitida'})
            except (ValueError, FloatingPointError):
                steps.append({'name':'Isolation Forest','status':'fallido','reason':'No se pudo ajustar el modelo con estos datos.'})
    return findings,steps
