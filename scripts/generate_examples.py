import csv,random
from datetime import datetime,timedelta,timezone
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'examples';p.mkdir(exist_ok=True)
fields=['timestamp','source_ip','destination_ip','source_port','destination_port','protocol','action','bytes']
r=random.Random(73);start=datetime(2025,6,1,tzinfo=timezone.utc);rows=[]
for hour in range(36):
 for j in range(4+(hour%4)):
  rows.append([(start+timedelta(hours=hour,minutes=10+j*4)).isoformat(),f'192.0.2.{1+hour%8}',f'198.51.100.{1+(hour+j)%6}',str(40000+hour*10+j),str([443,80,53][j%3]),['TCP','TCP','UDP'][j%3],'allow',str(r.randint(250,12000))])
for j in range(12):rows.append([(start+timedelta(hours=12,minutes=1,seconds=j*5)).isoformat(),'192.0.2.90','198.51.100.40',str(49000+j),'22','TCP','failure',str(100+j)])
for j in range(12):rows.append([(start+timedelta(hours=20,minutes=21,seconds=j*4)).isoformat(),'192.0.2.91','203.0.113.44',str(50000+j),str(8000+j),'TCP','allow',str(200+j)])
for j in range(5):rows.append([(start+timedelta(hours=27,minutes=10+j)).isoformat(),'192.0.2.92','198.51.100.41',str(51000+j),'443','TCP','allow',str(150000000+j)])
rows.sort(key=lambda x:x[0])
with (p/'actividad_sintetica.csv').open('w',newline='',encoding='utf-8') as f:w=csv.writer(f);w.writerow(fields);w.writerows(rows)
invalid=[rows[0],rows[0],['2025-06-01T10:00:00','192.0.2.5','198.51.100.1','1234','443','TCP','allow','20'],['2025-06-01T10:00:00Z','999.0.0.1','198.51.100.1','1234','443','TCP','allow','20'],['2025-06-01T10:00:00Z','192.0.2.1','198.51.100.1','1234','70000','TCP','allow','20']]
with (p/'validacion_mixta.csv').open('w',newline='',encoding='utf-8') as f:w=csv.writer(f);w.writerow(fields);w.writerows(invalid)
print(f'{len(rows)} eventos sintéticos y 5 filas mixtas generados.')
