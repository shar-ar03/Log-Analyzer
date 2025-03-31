import os
import re
import time
import smtplib
import argparse
import logging
import json
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# Configure logging for the script itself
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='log_analyzer.log'
)
logger = logging.getLogger('LogAnalyzer')

class LogAnalyzer:
    def __init__(self, config_path='config.json'):
        #Initialize the Log Analyzer with configuration settings from the json file as dictionary format to loop through in the script.
        
        self.config = self._load_config(config_path)
        self.log_patterns = self.config['log_patterns']
        self.email_config = self.config['email']
        self.slack_config = self.config['slack']
        self.log_files = self.config['log_files']
        self.alert_thresholds = self.config['alert_thresholds']
        self.stats = defaultdict(Counter)
        self.last_position = {}
        self.alert_history = {}
        
        # Initialize file positions
        for log_file in self.log_files:
            try:
                if os.path.exists(log_file):
                    self.last_position[log_file] = os.path.getsize(log_file)
                else:
                    logger.error(f"Log file not found: {log_file}")
                    self.last_position[log_file] = 0
            except Exception as e:
                logger.error(f"Error initializing log file {log_file}: {e}")
                self.last_position[log_file] = 0
    
    def _load_config(self, config_path):
        #Load configuration from JSON file. In case not found .json hardcode one to avoid script changes.
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            # Return default configuration
            return {
                "log_files": ["/var/log/auth.log", "/var/log/syslog"],
                "log_patterns": {
                    "failed_login": r"Failed password for .* from .* port \d+",
                    "system_error": r"error|failed|failure",
                    "critical_service": r"(nginx|apache|mysql|postgresql) .*(stopped|failed|crashed)"
                },
                "alert_thresholds": {
                    "failed_login": 5,
                    "system_error": 10,
                    "critical_service": 1
                },
                "email": {
                    "enabled": False,
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "username": "alerts@example.com",
                    "password": "your_password",
                    "from_email": "alerts@example.com",
                    "to_email": "admin@example.com"
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
                    "channel": "#alerts"
                },
                "scan_interval": 60
            }
    
    def _parse_log_line(self, line):
        """Parse a log line and check if it matches any patterns."""
        matches = {}
        for pattern_name, pattern in self.log_patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                matches[pattern_name] = line
        return matches
    
    def analyze_logs(self):
        """Analyze log files for patterns and update statistics."""
        for log_file in self.log_files:
            try:
                if not os.path.exists(log_file):
                    logger.warning(f"Log file does not exist: {log_file}")
                    continue
                
                current_size = os.path.getsize(log_file)
                
                # Handle log rotation (if current size is smaller than last position)
                if current_size < self.last_position.get(log_file, 0):
                    logger.info(f"Log rotation detected for {log_file}")
                    self.last_position[log_file] = 0
                
                # Skip if no new content
                if current_size <= self.last_position.get(log_file, 0):
                    continue
                
                with open(log_file, 'r') as f:
                    f.seek(self.last_position.get(log_file, 0))
                    for line in f:
                        matches = self._parse_log_line(line)
                        for pattern_name in matches:
                            self.stats[pattern_name][log_file] += 1
                
                self.last_position[log_file] = current_size
            
            except Exception as e:
                logger.error(f"Error analyzing log file {log_file}: {e}")
    
    def check_alerts(self):
        """Check if any alert thresholds have been reached."""
        alerts = []
        
        for pattern_name, counts in self.stats.items():
            total_count = sum(counts.values())
            threshold = self.alert_thresholds.get(pattern_name, 1000000)  # High default threshold
            
            # Only alert if threshold exceeded and not recently alerted
            last_alert_time = self.alert_history.get(pattern_name, datetime.min)
            time_since_last_alert = datetime.now() - last_alert_time
            
            if total_count >= threshold and time_since_last_alert > timedelta(minutes=30):
                alert_msg = f"ALERT: {pattern_name} threshold exceeded ({total_count}/{threshold})"
                logger.warning(alert_msg)
                
                # Add details
                for log_file, count in counts.items():
                    alert_msg += f"\n - {count} occurrences in {log_file}"
                
                alerts.append(alert_msg)
                self.alert_history[pattern_name] = datetime.now()
        
        # Reset counters after checking alerts
        self.stats = defaultdict(Counter)
        
        return alerts
    
    def send_email_alert(self, alert_msg):
        """Send alert via email."""
        if not self.email_config['enabled']:
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['from_email']
            msg['To'] = self.email_config['to_email']
            msg['Subject'] = "Log Analyzer Alert"
            
            msg.attach(MIMEText(alert_msg, 'plain'))
            
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['username'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
            
            logger.info("Email alert sent successfully")
        
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def send_slack_alert(self, alert_msg):
        """Send alert to Slack."""
        if not self.slack_config['enabled']:
            return
        
        try:
            payload = {
                "channel": self.slack_config['channel'],
                "username": "Log Analyzer",
                "text": f"```{alert_msg}```",
                "icon_emoji": ":warning:"
            }
            
            response = requests.post(
                self.slack_config['webhook_url'],
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to send Slack alert: {response.text}")
            else:
                logger.info("Slack alert sent successfully")
        
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
    
    def process_alerts(self, alerts):
        """Process and send alerts through configured channels."""
        if not alerts:
            return
        
        alert_text = "\n\n".join(alerts)
        
        # Send alerts through configured channels
        if self.email_config['enabled']:
            self.send_email_alert(alert_text)
        
        if self.slack_config['enabled']:
            self.send_slack_alert(alert_text)
    
    def run_once(self):
        """Run a single analysis cycle."""
        logger.info("Starting log analysis cycle")
        self.analyze_logs()
        alerts = self.check_alerts()
        self.process_alerts(alerts)
        logger.info("Completed log analysis cycle")
    
    def run_continuously(self):
        """Run analysis in a continuous loop."""
        try:
            while True:
                self.run_once()
                time.sleep(self.config.get('scan_interval', 60))
        except KeyboardInterrupt:
            logger.info("Log analyzer stopped by user")
        except Exception as e:
            logger.error(f"Error in continuous run: {e}")


def main():
    """Main function to parse arguments and run the log analyzer."""
    parser = argparse.ArgumentParser(description='Log Analyzer & Alert System')
    parser.add_argument('-c', '--config', default='config.json', help='Path to configuration file')
    parser.add_argument('-o', '--once', action='store_true', help='Run analysis once and exit')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    analyzer = LogAnalyzer(args.config)
    
    if args.once:
        analyzer.run_once()
    else:
        print("Starting Log Analyzer in continuous mode. Press Ctrl+C to stop.")
        analyzer.run_continuously()


if __name__ == "__main__":
    main()
