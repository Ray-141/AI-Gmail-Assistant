# AI Gmail Assistant

An AI-powered Gmail add-on that analyzes emails, summarizes their content, classifies potential threats, and assists with phishing reporting.

## Features

- **Email Analysis:** Analyzes email content using a locally hosted AI model.
- **Email Summarization:** Produces concise summaries of messages.
- **Threat Classification:** Categorizes emails as likely legitimate, spam/promotional, suspicious, likely phishing, or uncertain.
- **Recommended Actions:** Provides guidance based on the analysis.
- **Phishing Reporting:** Allows suspicious emails to be reported, including the original email as an attachment.

## Technologies

- Python
- Flask
- Google Gmail API
- Google Workspace Add-ons
- Ollama
- Cloudflare Tunnel

## How It Works

The Gmail add-on sends requests to a Python Flask backend. The backend retrieves the relevant email information through the Gmail API and sends its content to a locally hosted AI model through Ollama.

The model analyzes the message and returns a classification, summary, explanation, and recommended action. For emails classified as suspicious or likely phishing, the add-on can provide a reporting option.

## Requirements

- Python
- Flask and the Python packages listed in `requirements.txt`
- Ollama and a compatible local model
- A Google Cloud project configured for the Gmail API and Google Workspace Add-ons
- Appropriate OAuth configuration and Gmail permissions

## Setup

1. Install Python and Ollama.
2. Install the Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Download and configure a compatible Ollama model.
4. Configure the Google Cloud project and OAuth credentials.
5. Start the Ollama service.
6. Run the Flask application.
7. Configure the Google Workspace add-on deployment to reach the backend.

## Security

Never commit OAuth tokens, client secrets, passwords, or other private credentials to the repository.

## Project Status

Functional prototype developed as an AI and Robotics Engineering project.