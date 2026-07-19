# AI-NGFW-Gateways-Latency-Testing
Application for simulating prompts to capture the latency on AI NGFWs/AI Gateways

🛡️ AI-NGFW/ AI-Gateway Latency Analyzer

A specialized, Streamlit-based testing suite designed to empirically measure the packet processing latency, cryptographic decryption overhead, and inline AI security inspection metrics of Palo Alto Networks Next-Generation Firewalls (NGFW) when securing Generative AI traffic. You can repurpose to test any inline gateway/AI-NGFW to capture latency

This application acts as a client generating API requests to AWS Bedrock (e.g., Anthropic Claude 3), forcing the traffic through a centralized NGFW inspection VPC. By running isolated scenarios and filtering out public internet anomalies, the tool calculates the exact hardware processing footprint of the firewall down to the millisecond.

✨ Key Features
Four-Stage Empirical Testing (UC1 - UC4): Run isolated baseline, decryption, active AI inspection, and inline threat-blocking scenarios to calculate exact latency deltas.

Statistical Anomaly Filtering: Automatically strips out the top 5% of latency spikes (P95) caused by public internet routing and AWS Bedrock generation variance, ensuring your hardware metrics are highly accurate.

Dynamic Prompt Injection: Easily swap between benign testing prompts and adversarial "Jailbreak" payloads via the UI to test inline blocking mechanisms.

Warm vs. Cold Connection Profiling: Toggle between pooled connections (to isolate Layer 7 AI inspection) and forced fresh handshakes (to measure SSL Forward Proxy certificate generation overhead).

Automated Executive Reporting: One-click generation of a minimalist PDF report detailing raw stats, cleaned averages, and isolated processing overhead variances.

Raw Data Export: Download complete unified logs (CSV) including the full model responses, exact prompts sent, and specific error termination reasons.

🏗️ Architecture Overview
This application is designed to be deployed on an AWS EC2 instance (Ubuntu) functioning as the Client App Server.

Client VPC (App Server): Generates and transmits the Bedrock API prompt requests.

Transit Gateway: Routes outbound traffic from the client environment into the security boundary.

Security VPC (Network Firewall): The Palo Alto Networks NGFW intercepts the traffic to perform inline SSL decryption and AI security profile inspection.

Internet Gateway: Egresses the permitted traffic to the public internet.

Destination (AWS Bedrock): The generative AI model processes the prompt and returns the response via the established path.

📋 Prerequisites
To run this application, your AWS environment must be configured with the following:

Python 3.8+ installed on your client EC2 instance.

IAM Permissions: The EC2 instance running this app must have an IAM Role attached with permissions to invoke AWS Bedrock models (e.g., bedrock:InvokeModel).

Firewall Access: You must have administrative access to the Palo Alto Networks NGFW (via PAN-OS or Strata Cloud Manager) to manually toggle SSL Decryption and AI Security Profiles between test runs.

🚀 Installation
Clone this repository to your App Server:

Bash
git clone https://github.com/your-username/ai-ngfw-latency-analyzer.git
cd ai-ngfw-latency-analyzer
Install the required Python dependencies. (Create a requirements.txt containing: streamlit, pandas, boto3, fpdf):

Bash
pip3 install -r requirements.txt
Run the application manually for testing:

Bash
streamlit run appv2.py
(Note: If you have configured this as a systemd service, you can manage it via sudo systemctl start ngfw-tester)

🎮 How to Use
Access the Streamlit dashboard via your browser at http://<YOUR_EC2_IP>:8501.

1. Configure Your Test Run
Using the left sidebar, configure your AWS Region, target Bedrock Model ID, and the Number of Requests per iteration. You can also adjust the Max Generation Tokens limit (Keep this low, e.g., 15-20, to isolate firewall latency and avoid heavy downstream LLM generation delays).

2. Run the Scenarios Sequentially
Navigate to the Run Scenarios tab. You must run the tests in order, manually updating your NGFW policies between each run to calculate the exact latency deltas:

UC1 (Baseline): Disable SSL Decryption and AI Profiles on the firewall. Run the test to establish your baseline network Round Trip Time (RTT).

UC2 (Decryption Overhead): Enable SSL Decryption (Forward Proxy) on the firewall, but leave AI Profiles disabled. Run the test to measure the hardware cryptographic penalty.

UC3 (AI Inspection): Keep Decryption enabled, and attach the active AI Security Profile. Run the test to measure the inline Machine Learning inspection overhead.

UC4 (Inline Block): Leave settings identical to UC3. Select UC4 to send the Jailbreak payload. The firewall should instantly sever the connection, demonstrating the speed of proactive threat mitigation.

3. Analyze and Export
Navigate to the Analytics Dashboard tab. The application will automatically:

Identify valid firewall resets (Connection Severed) vs. standard API failures.

Filter out the top 5% latency anomalies.

Calculate the exact symmetric decryption overhead and inline AI inspection overhead in milliseconds.

Allow you to export the Cleaned Summary CSV, Raw Logs CSV, or generate a Minimalist PDF Summary Report for stakeholders.

⚠️ Important Configuration Notes
If you push the Max Generation Tokens slider to a high value (e.g., 2000+), you must manually edit the appv2.py script to increase the boto3 read_timeout beyond 10 seconds. Otherwise, AWS Bedrock will exceed the local application timeout while generating the massive text payload, resulting in false failures.
