# Cloud Security Scanner Demo

This project is a local cloud security demo that scans Terraform infrastructure as code for common AWS security issues.

## What it does

- Parses Terraform HCL from `terraform/main.tf`
- Detects insecure patterns like:
  - public S3 bucket ACLs
  - overly broad IAM permissions
  - security groups allowing `0.0.0.0/0`
- Assigns a risk score to each finding
- Prints remediation guidance for fixed issues
- Can optionally compare against simulated deployed state in `data/deployed_state.json`

## Files

- `terraform/main.tf` — sample Terraform resources with insecure settings
- `scanner.py` — analyzer script for IaC security issues
- `data/deployed_state.json` — sample deployed state for drift detection
- `requirements.txt` — required Python dependency

## Setup

1. Activate the project virtual environment or use its Python interpreter:

```bash
source venv/bin/activate
# or use the interpreter directly:
# ./venv/bin/python
```

2. Install Python dependencies:

```bash
./venv/bin/python -m pip install -r requirements.txt
```

3. Run the scanner:

```bash
./venv/bin/python scanner.py --scan terraform/main.tf
```

4. To compare against simulated deployed state:

```bash
./venv/bin/python scanner.py --scan terraform/main.tf --deployed-state data/deployed_state.json
```

## Resume-ready summary

- Built a local cloud security posture project using Terraform IaC scanning.
- Developed custom detection rules for insecure AWS configuration patterns.
- Included risk scoring, remediation guidance, and drift comparison logic.

## Optional local testing

If you want to explore actual runtime emulation later, install LocalStack:

```bash
python3 -m pip install localstack
```

Then you can use this repo as a sandbox for AWS-style IaC security validation without a real cloud account.
