Log Analyzer & Alert System
A powerful Python-based log monitoring tool that analyzes system/application logs in real time, detects anomalies, and sends automated alerts via email/Slack.

Features
1. Real-time log monitoring
2. Anomaly detection using regex & pattern matching
3. Automated alerts via Email/Slack
4. Customizable log filters (error levels, keywords)
5. Supports large log files efficiently

Installation
1. Clone this repository:
   	git clone https://github.com/shar-ar03/Log-Analyzer
   	cd log-analyzer

Usage

Run the log analyzer with a sample log file:
 	python src/log_analyzer.py --logfile logs/sample.log 
	the above command can be used to run a sample log file, you can change the name accordingly in the command.

Configuration
You can edit config.json to customize monitoring settings.

Contributing
Contributions are welcome! Follow these steps:
1. Fork the repository
2. Create a new branch (git checkout -b feature-branch)
3. Commit changes (git commit -m "Added new feature")
4. Push the branch (git push origin feature-branch)
5. Open a Pull Request

Future Improvements
1.Log visualization dashboard (using Flask/React)
2.Machine Learning-based anomaly detection
3.Database integration (store logs in MongoDB/PostgreSQL)


