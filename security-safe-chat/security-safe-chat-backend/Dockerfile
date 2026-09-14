# ─────────────────────────────────────────────────────────────────────────────
# AWS Lambda Container Image — Unified SAFE Backend
# Base: AWS Lambda Python 3.11 Official Base Image
# ─────────────────────────────────────────────────────────────────────────────
FROM public.ecr.aws/lambda/python:3.11

# Set working directory to Lambda task root
WORKDIR ${LAMBDA_TASK_ROOT}

# Install dependencies into LAMBDA_TASK_ROOT
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt --target "${LAMBDA_TASK_ROOT}"

# Copy application source code and seed files
COPY main.py ${LAMBDA_TASK_ROOT}/
COPY blogs_store.json ${LAMBDA_TASK_ROOT}/
COPY app/ ${LAMBDA_TASK_ROOT}/app/
COPY routes/ ${LAMBDA_TASK_ROOT}/routes/
COPY utils/ ${LAMBDA_TASK_ROOT}/utils/
COPY data/ ${LAMBDA_TASK_ROOT}/data/

# Lambda Function Handler (Mangum ASGI Adapter in main.py)
CMD [ "main.handler" ]
