FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY netguard ./netguard
COPY static ./static
COPY examples ./examples
ENV NETGUARD_DB=/data/netguard.db
EXPOSE 8080
CMD ["uvicorn", "netguard.app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
