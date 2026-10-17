\# CloudGuard — AWS Website Monitoring \& Incident Alerting



CloudGuard is an AWS-based website monitoring project that checks website availability, tracks response times, detects failures and recoveries, and sends email notifications for incident transitions.



\## Features



\- Automated health checks for Store, Restaurant, and Clinic endpoints

\- Consecutive-failure and recovery thresholds

\- Response-time and availability metrics in Amazon CloudWatch

\- CloudWatch alarms for website downtime and slow responses

\- Amazon SNS email notifications

\- Amazon DynamoDB incident storage

\- Interactive Streamlit dashboard with Overview, Analytics, Incident Explorer, and AWS Alarms pages

\- CSV-based local health and incident history



\## Architecture



1\. A Python monitoring script checks configured website endpoints.

2\. A systemd timer runs the health checks periodically.

3\. Failure and recovery thresholds identify incident transitions.

4\. Amazon CloudWatch receives availability and response-time metrics.

5\. Amazon SNS sends incident notification emails.

6\. Amazon DynamoDB stores incident records.

7\. A Streamlit dashboard visualizes monitoring history and AWS alarm states.



\## Technology Stack



\- Python

\- Flask

\- Streamlit

\- Plotly and pandas

\- AWS EC2

\- Amazon CloudWatch

\- Amazon SNS

\- Amazon DynamoDB

\- Nginx

\- Linux systemd



\## Project Structure



```text

cloudguard/

├── app.py

├── monitor.py

├── dashboard.py

├── requirements.txt

├── .gitignore

└── README.md

```



Runtime reports, environment secrets, and Python virtual environments are excluded from version control.



\## Local Setup



Create and activate a Python virtual environment, then install dependencies:



```bash

python -m venv .venv

```



Windows:



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



Linux/macOS:



```bash

source .venv/bin/activate

```



Install packages:



```bash

pip install -r requirements.txt

```



\## AWS Configuration



The application uses AWS SDK credentials and permissions supplied by the execution environment. On EC2, an IAM role should grant only the permissions needed for CloudWatch metrics and alarms, SNS publishing, and DynamoDB incident access.



Do not commit AWS access keys, private keys, admin tokens, environment files, or other credentials.



Configure the monitoring endpoints and AWS region for your environment before running the application.



\## Running the Applications



Start the Flask application using your configured Flask service or development command.



Run the monitoring script:



```bash

python monitor.py

```



Run the Streamlit dashboard:



```bash

streamlit run dashboard.py

```



The dashboard needs access to the configured AWS resources and local health-history CSV when displaying those data sources.



\## Security Notes



\- Keep credentials outside the repository.

\- Use least-privilege IAM policies.

\- Restrict access to the dashboard.

\- Do not expose development servers directly to the public internet.

\- Review logs and incident records before sharing them.



\## Current Limitations



\- Availability calculations are based on observed health checks.

\- Monitoring and dashboard availability depend on the EC2 instance and its configuration.

\- CloudWatch alarms need sufficient datapoints before their states can be evaluated.

\- Production deployment should use appropriate process management, access controls, and application-server configuration.



\## Future Improvements



\- Automated deployment and configuration

\- Authentication and role-based dashboard access

\- Improved incident analytics and recovery-time reporting

\- Automated tests and CI checks

\- Production-grade application serving and centralized logging



\## Disclaimer



This project is intended as a cloud-monitoring learning project. Test all configuration changes in a controlled environment before using the system for production-critical monitoring.



