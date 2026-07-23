# 🛡️ AI-NGFW Gateways Latency Test Tool
### *Palo Alto Networks AI-NGFW / AI-Gateway Latency Analyzer*

Application for simulating prompts to capture the latency on AI NGFWs and AI Gateways.

A specialized, Streamlit-based testing suite designed to empirically measure packet processing latency, cryptographic decryption overhead, and inline AI security inspection metrics of Palo Alto Networks Next-Generation Firewalls (NGFW) when securing Generative AI traffic. You can also repurpose this framework to test any inline gateway or AI-NGFW to capture latency footprints.

This application acts as a client generating API requests to AWS Bedrock (e.g., Anthropic Claude 3), forcing the traffic through a centralized NGFW inspection VPC. By running isolated scenarios and filtering out public internet anomalies, the tool calculates the exact hardware processing footprint of the firewall down to the millisecond.

---

## ✨ Key Features

*   **Four-Stage Empirical Testing (UC1 - UC4):** Run isolated baseline, decryption, active AI inspection, and inline threat-blocking scenarios to calculate exact latency deltas.
*   **Statistical Anomaly Filtering:** Automatically strips out the top 5% of latency spikes (P95) caused by public internet routing and AWS Bedrock generation variance, ensuring your hardware metrics are highly accurate.
*   **Dynamic Prompt Injection:** Easily swap between benign testing prompts and adversarial "Jailbreak" payloads via the UI to test inline blocking mechanisms.
*   **Warm vs. Cold Connection Profiling:** Toggle between pooled connections (to isolate Layer 7 AI inspection) and forced fresh handshakes (to measure SSL Forward Proxy certificate generation overhead).
*   **Automated Executive Reporting:** One-click generation of a minimalist PDF report detailing raw stats, cleaned averages, and isolated processing overhead variances.
*   **Raw Data Export:** Download complete unified logs (CSV) including the full model responses, exact prompts sent, and specific error termination reasons.
*   **CSV Upload option:** Upload prompts as a CSV to do tests with randomized prompts. If the CSV contains 5 prompts and if you select to run 100, it will randomly repeat the prompts. 
---

## 📁 Repository Structure & Application Versions

Depending on your testing environment and the complexity of your evaluation, this repository offers three different versions of the Latency Test Tool. 

### 1. `app.py` (Standard Version)
The baseline empirical latency tester. This version is ideal for standard Generative AI traffic testing (UC1 to UC4) using standard AWS Bedrock models (like Claude 3 Haiku). It includes the core analytics dashboard, warm/cold connection profiling, and PDF report generation.

### 2. `app-thinking.py` (Advanced Models & Prisma AIRS)
This version introduces advanced payload handling and API integrations, designed for testing the absolute limits of Layer 7 firewall inspection.
* **Extended Thinking Support:** Includes dynamic token math and API formatting to support "thinking" models (e.g., Claude 3.7 Sonnet). This forces the firewall to hold TCP connections open and inspect massive, hidden token streams before a final response is generated.
* **Prisma AIRS API Integration (UC5):** Adds a 5th Use Case to test direct REST API intercepts using the Prisma AIRS API (`/v1/scan/sync/request`). 
* **Sequential CSV Prompting:** Allows bulk uploading of Benign and Jailbreak prompts to simulate varied, real-world user traffic sequentially.
* **Selective Database Management:** Allows clearing specific Use Case data from the database directly from the UI without wiping the entire log file.

### 3. `appv3_multi-eni.py` (Automated "Zero-Commit" Architecture)
The ultimate "Set-and-Forget" version. This script includes everything from `app-thinking.py`, but adds low-level socket binding to automate firewall routing. It eliminates the need to manually commit PAN-OS firewall rules between scenario runs.
* **Dynamic Source IP Binding:** Maps specific Use Cases directly to specific secondary IPs (ENIs) on your Ubuntu server.
* **Custom Socket Routing:** Uses custom `urllib3` connection patching for AWS `boto3` and custom `HTTPAdapters` for Prisma AIRS `requests` to force traffic out of the designated local interface.
* **Zero-Touch Firewalling:** By pre-configuring your PAN-OS policies based on three distinct source IPs, you can run UC1 through UC5 back-to-back in seconds under identical network conditions without waiting for firewall commits.


## 🏗️ Architecture Overview

This application is designed to be deployed on an AWS EC2 instance (Ubuntu) functioning as the Client App Server. 

1.  **Client VPC (App Server):** Generates and transmits the Bedrock API prompt requests.
2.  **Transit Gateway:** Routes outbound traffic from the client environment into the security boundary.
3.  **Security VPC (Network Firewall):** The Palo Alto Networks NGFW intercepts the traffic to perform inline SSL decryption and AI security profile inspection.
4.  **Internet Gateway:** Egresses the permitted traffic to the public internet.
5.  **Destination (AWS Bedrock):** The generative AI model processes the prompt and returns the response via the established path.

---

## 📋 Prerequisites

To run this application, your AWS environment must be configured with the following:

1.  **Python 3.8+** installed on your client EC2 instance.
2.  **IAM Permissions:** The EC2 instance running this app must have an IAM Role attached with permissions to invoke AWS Bedrock models (e.g., `bedrock:InvokeModel`).
3.  **Firewall Access:** You must have administrative access to the Palo Alto Networks NGFW (via PAN-OS or Strata Cloud Manager) to manually toggle SSL Decryption and AI Security Profiles between test runs.

---

## 🚀 Installation

1.  **Clone this repository to your App Server:**
    ```bash
    git clone [https://github.com/your-username/AI-NGFW-Gateways-Latency-Testing.git](https://github.com/chinthakaek/AI-NGFW-Gateways-Latency-Testing.git)
    cd AI-NGFW-Gateways-Latency-Testing
    ```

2.  **Install the required Python dependencies:**
    Make sure you have a `requirements.txt` containing `streamlit`, `pandas`, `boto3`, and `fpdf`. Then run:
    ```bash
    pip3 install -r requirements.txt
    ```

3.  **Run the application manually for testing:**
    ```bash
    streamlit run app.py
    ```
    *(Note: If you have configured this as a `systemd` service, you can manage it via `sudo systemctl start ngfw-tester`)*

---
<img width="1836" height="1011" alt="image" src="https://github.com/user-attachments/assets/6bdb75f6-75e9-4754-8276-ae903295a289" />

## 🎮 How to Use

Access the Streamlit dashboard via your browser at `http://<YOUR_EC2_IP>:8501`.

### 1. Configure Your Test Run
Using the left sidebar, configure your **AWS Region**, target **Bedrock Model ID**, and the **Number of Requests** per iteration. You can also adjust the **Max Generation Tokens** slider limit (keeping it intentionally low helps isolate infrastructure latency from model execution delays).

### 2. Run the Scenarios Sequentially
Navigate to the **Run Scenarios** tab. You must run the tests in order, manually updating your NGFW policies between each run to calculate the exact latency deltas:
*   **UC1 (Baseline):** Disable SSL Decryption and AI Profiles on the firewall. Run the test to establish your baseline network Round Trip Time (RTT).
*   **UC2 (Decryption Overhead):** Enable SSL Decryption (Forward Proxy) on the firewall, but leave AI Profiles disabled. Run the test to measure the hardware cryptographic penalty.
*   **UC3 (AI Inspection):** Keep Decryption enabled, and attach the active AI Security Profile. Run the test to measure the inline Machine Learning inspection overhead.
*   **UC4 (Inline Block):** Leave settings identical to UC3. Select UC4 to send the Jailbreak payload. The firewall should instantly sever the connection, demonstrating the speed of proactive threat mitigation.

### 3. Analyze and Export
Navigate to the **Analytics Dashboard** tab. The application will automatically display both the raw stats and the cleaned metrics (top 5% anomalies removed), calculate isolated latency deltas, and provide options to export raw CSV logs or download the minimalist PDF layout.

<img width="1812" height="857" alt="image" src="https://github.com/user-attachments/assets/d3e9fb0e-9ff0-4664-9049-2a294929fd08" />

---

## ⚠️ Important Configuration Notes

Before running the tests, the certificates required for the firewall's SSL Forward Proxy must be added to the application server. If the client virtual machine does not trust the firewall's certificate, the Bedrock API requests will fail during the decryption scenarios.

```bash
Export and import the required certificate. (You can leverage SCP). Post that you can update the certificate store with the decryption certificate. 

#copy the certificate to ubuntu cert store
sudo cp sslcert.crt /usr/local/share/ca-certificates

#Install the certificate
sudo update-ca-certificates
```


Current readtime out is set to 30 seconds for Cold requests and 60 seconds for warm requests. Depending on the Token size you may need to increase the timeout otherwise, AWS Bedrock will exceed the local application timeout while generating the massive text payload, resulting in false failures.

```bash
def get_bedrock_client(cold_conn):
    if cold_conn:
        config = Config(
            region_name=aws_region, 
            connect_timeout=3, 
            read_timeout=30,        # <--- Update this for cold connections
            max_pool_connections=1, 
            retries={'max_attempts': 0}
        )
    else:
        config = Config(
            region_name=aws_region, 
            connect_timeout=3, 
            read_timeout=60,        # <--- Update this for warm connections
            max_pool_connections=10, 
            retries={'max_attempts': 3}
        )
    return boto3.client(service_name="bedrock-runtime", config=config)
```

Updating Max Tokens

Streamlit enforces a strict rule: the default value must exactly align with the min_value plus a multiple of the step. Hence ensure to align the numbers when updating

```bash
max_tokens_val = st.sidebar.slider(
    "Max Generation Tokens", 
    min_value=20,          # <--- Aligned with the step and value
    max_value=2048, 
    value=20, 
    step=20,
    help="Higher values isolate application processing, while lower values isolate firewall infrastructure overhead."
)
```
