"""Validación reproducible, sin escribir en la base durante la vista previa."""
import csv,hashlib,io,ipaddress,json
from datetime import datetime,timezone
from pathlib import Path

REQUIRED=('timestamp','source_ip','destination_ip','destination_port','protocol')
ACTIONS={'allow','deny','success','failure','unknown'}
PROTOCOLS={'TCP','UDP','ICMP'}

def parse(data:bytes,filename:str,max_bytes:int):
    if Path(filename).suffix.lower()!='.csv': raise ValueError('Solo se admiten archivos CSV.')
    if not data: raise ValueError('El archivo está vacío.')
    if len(data)>max_bytes: raise ValueError('El archivo supera el límite configurado.')
    try: text=data.decode('utf-8-sig')
    except UnicodeDecodeError as exc: raise ValueError('El archivo debe estar codificado en UTF-8.') from exc
    try:
        reader=csv.DictReader(io.StringIO(text,newline=''),strict=True)
        if not reader.fieldnames: raise ValueError('El CSV no tiene encabezados.')
        names=[x.strip() for x in reader.fieldnames]
        if len(names)!=len(set(names)) or any(not n for n in names): raise ValueError('Los nombres de columnas deben ser únicos y no vacíos.')
        reader.fieldnames=names
        missing=[x for x in REQUIRED if x not in names]
        if missing: raise ValueError('Faltan columnas obligatorias: '+', '.join(missing))
        valid=[];rejected=[];seen=set();rows=0
        for row in reader:
            rows+=1;line=reader.line_num
            if rows>25000: raise ValueError('La importación supera el límite de 25 000 filas.')
            try:
                if None in row: raise ValueError('La fila tiene más columnas que el encabezado.')
                def val(key): return (row.get(key) or '').strip()
                dt=datetime.fromisoformat(val('timestamp').replace('Z','+00:00'))
                if dt.tzinfo is None or dt.utcoffset() is None: raise ValueError('La fecha debe incluir zona horaria.')
                stamp=dt.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
                src=str(ipaddress.ip_address(val('source_ip')));dst=str(ipaddress.ip_address(val('destination_ip')))
                def port(name,required=False):
                    s=val(name)
                    if not s and not required:return None
                    n=int(s)
                    if not 0<=n<=65535:raise ValueError(f'{name} fuera de 0–65535.')
                    return n
                sport=port('source_port');dport=port('destination_port',True)
                protocol=val('protocol').upper()
                if protocol not in PROTOCOLS:raise ValueError('Protocolo admitido: TCP, UDP o ICMP.')
                action=val('action').lower() or 'unknown'
                if action not in ACTIONS:raise ValueError('Acción no admitida.')
                rawbytes=val('bytes');amount=int(rawbytes) if rawbytes else None
                if amount is not None and not 0<=amount<=2**63-1:raise ValueError('Bytes fuera del rango permitido.')
                event={'timestamp':stamp,'source_ip':src,'destination_ip':dst,'source_port':sport,'destination_port':dport,'protocol':protocol,'action':action,'bytes':amount}
                fingerprint=hashlib.sha256(json.dumps(event,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                if fingerprint in seen:raise ValueError('Registro duplicado dentro del archivo.')
                seen.add(fingerprint);event['fingerprint']=fingerprint;event['line']=line;valid.append(event)
            except (ValueError,TypeError,OverflowError) as exc:rejected.append({'line':line,'reason':str(exc) or 'Valor inválido.'})
        if rows==0:raise ValueError('El archivo no contiene filas de datos.')
        return {'valid':valid,'rejected':rejected,'total':rows,'columns':names}
    except csv.Error as exc:raise ValueError('CSV dañado o con comillas inválidas.') from exc
