FROM python:3.11-slim
WORKDIR /srv/vulnscope
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY dataset/ ./dataset/
COPY scripts/ ./scripts/
RUN useradd -m runner && mkdir -p /srv/vulnscope/runtime /srv/vulnscope/result && chown -R runner:runner /srv/vulnscope/runtime /srv/vulnscope/result
USER runner
ENV VULNSCOPE_DATA_DIR=/srv/vulnscope/runtime
EXPOSE 8000
CMD ["uvicorn", "app.web:app", "--host", "0.0.0.0", "--port", "8000"]
