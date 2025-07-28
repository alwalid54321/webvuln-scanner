#!/usr/bin/env python3
"""
Web Vulnerability Scanner - UI Dashboard Server

This module provides a web-based dashboard for the Web Vulnerability Scanner
using Flask and Flask-SocketIO for real-time updates.
"""

import os
import json
import logging
import threading
import time
from typing import Dict, List, Any, Optional
from dataclasses import asdict

from flask import Flask, send_from_directory, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix

from scanner.reporter import Finding, Severity, Reporter
from scanner.crawler import Crawler
from scanner.http_client import HttpClient
from scanner.safety import get_safety_manager
import plugins  # This triggers plugin registration
from plugins.base import Plugin

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask and SocketIO
app = Flask(__name__, 
            static_folder=os.path.join(os.path.dirname(__file__), 'static'),
            template_folder=os.path.join(os.path.dirname(__file__), 'templates'))
app.config['SECRET_KEY'] = 'webvulnscannerkey'
app.wsgi_app = ProxyFix(app.wsgi_app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
scan_status = {
    "is_running": False,
    "total_urls": 0,
    "scanned_urls": 0,
    "start_time": None,
    "findings_count": 0,
    "findings_by_severity": {sev.name: 0 for sev in Severity},
    "target_url": "",
}

# In-memory storage of findings
findings = []


@app.route('/')
def index():
    """Serve the main dashboard page."""
    return render_template('dashboard.html')


@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files."""
    static_folder = os.path.join(os.path.dirname(__file__), 'static')
    return send_from_directory(static_folder, path)


@app.route('/api/status')
def get_status():
    """Return current scan status."""
    return jsonify(scan_status)


@app.route('/api/findings')
def get_findings():
    """Return all findings."""
    severity_filter = request.args.get('severity', '').upper()
    if severity_filter and hasattr(Severity, severity_filter):
        filtered = [f for f in findings if f.get('severity', '').upper() == severity_filter]
        return jsonify(filtered)
    return jsonify(findings)


@app.route('/api/findings/<int:finding_id>')
def get_finding(finding_id):
    """Return a specific finding by ID."""
    if 0 <= finding_id < len(findings):
        return jsonify(findings[finding_id])
    return jsonify({"error": "Finding not found"}), 404


@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    emit('status_update', scan_status)
    emit('findings_update', findings)


@socketio.on('pause_scan')
def handle_pause():
    """Pause the scan."""
    # Logic to pause the scan would be implemented here
    scan_status["is_running"] = False
    emit('status_update', scan_status, broadcast=True)
    return {"success": True, "message": "Scan paused"}


@socketio.on('resume_scan')
def handle_resume():
    """Resume the scan."""
    # Logic to resume the scan would be implemented here
    scan_status["is_running"] = True
    emit('status_update', scan_status, broadcast=True)
    return {"success": True, "message": "Scan resumed"}


@socketio.on('stop_scan')
def handle_stop():
    """Stop the scan."""
    # Logic to stop the scan would be implemented here
    scan_status["is_running"] = False
    emit('status_update', scan_status, broadcast=True)
    return {"success": True, "message": "Scan stopped"}


@socketio.on('start_scan')
def handle_start(data):
    """Start a new scan."""
    global findings
    findings = []
    
    scan_status["is_running"] = True
    scan_status["total_urls"] = 0
    scan_status["scanned_urls"] = 0
    scan_status["start_time"] = time.time()
    scan_status["findings_count"] = 0
    scan_status["findings_by_severity"] = {sev.name: 0 for sev in Severity}
    scan_status["target_url"] = data.get('target_url', '')
    
    emit('status_update', scan_status, broadcast=True)
    emit('findings_update', findings, broadcast=True)
    
    # Start the actual scanner in a background thread
    scan_thread = threading.Thread(target=run_scan, args=(data,))
    scan_thread.daemon = True
    scan_thread.start()
    
    return {"success": True, "message": "Scan started"}


def run_scan(data):
    """Run the actual vulnerability scan in a background thread."""
    try:
        target_url = data.get('target_url', '')
        selected_plugins = data.get('plugins', ['xss', 'security_headers'])
        max_depth = int(data.get('max_depth', 3))
        delay = float(data.get('delay', 0.5))
        timeout = int(data.get('timeout', 30))
        threads = int(data.get('threads', 1))
        
        logger.info(f"Starting scan of {target_url} with plugins: {selected_plugins}")
        
        # Initialize safety manager
        safety_manager = get_safety_manager()
        
        # Validate target URL for safety
        if not safety_manager.is_url_safe(target_url):
            logger.error(f"Target URL blocked by safety manager: {target_url}")
            scan_status["is_running"] = False
            socketio.emit('scan_error', {'message': f'Target URL blocked for safety: {target_url}'}, broadcast=True)
            return
        
        # Create UI reporter that streams findings to the dashboard
        ui_reporter = UIReporter(socketio)
        
        # Initialize HTTP client
        http_client = HttpClient(
            timeout=timeout,
            user_agents=['WebVulnScanner/1.0 (Security Testing)']
        )
        
        # Initialize crawler
        crawler = Crawler(
            start_urls=[target_url],
            max_depth=max_depth,
            request_delay=delay,
            thread_count=threads,
            custom_user_agent='WebVulnScanner/1.0'
        )
        
        # Crawl the target to get URLs
        logger.info("Starting crawl...")
        urls = crawler.crawl(lambda url, response: None)  # Simple callback
        
        scan_status["total_urls"] = len(urls)
        socketio.emit('status_update', scan_status, broadcast=True)
        
        # Get available plugins
        available_plugins = {plugin.name: plugin for plugin in Plugin.get_plugins()}
        
        # Run selected plugins on discovered URLs
        for i, url in enumerate(urls):
            if not scan_status["is_running"]:  # Check if scan was stopped
                break
                
            scan_status["scanned_urls"] = i + 1
            socketio.emit('progress_update', {
                'url': url,
                'total': len(urls),
                'current': i + 1,
                'percentage': ((i + 1) / len(urls) * 100) if len(urls) > 0 else 0
            }, broadcast=True)
            socketio.emit('status_update', scan_status, broadcast=True)
            
            # Run each selected plugin
            for plugin_name in selected_plugins:
                if plugin_name in available_plugins:
                    plugin_class = available_plugins[plugin_name]
                    plugin_instance = plugin_class(ui_reporter)
                    
                    try:
                        plugin_findings = plugin_instance.scan(url, http_client)
                        logger.info(f"Plugin {plugin_name} found {len(plugin_findings)} findings for {url}")
                    except Exception as e:
                        logger.error(f"Error running plugin {plugin_name} on {url}: {e}")
        
        # Scan completed
        scan_status["is_running"] = False
        socketio.emit('status_update', scan_status, broadcast=True)
        socketio.emit('scan_complete', {'message': f'Scan completed. Found {scan_status["findings_count"]} findings.'}, broadcast=True)
        
        logger.info(f"Scan completed. Found {scan_status['findings_count']} total findings.")
        
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        scan_status["is_running"] = False
        socketio.emit('scan_error', {'message': f'Scan error: {str(e)}'}, broadcast=True)
        socketio.emit('status_update', scan_status, broadcast=True)


class UIReporter:
    """
    Reporter implementation that sends findings to the UI via SocketIO.
    """
    def __init__(self, socket_io, min_severity=Severity.LOW):
        """Initialize the UI reporter."""
        self.socket_io = socket_io
        self.min_severity = min_severity
    
    def add_finding(self, finding: Finding):
        """Add a finding and emit it to connected clients."""
        if finding.severity.value < self.min_severity.value:
            return
        
        # Convert Finding object to dict for JSON serialization
        finding_dict = asdict(finding)
        
        # Update finding severity counters
        scan_status["findings_count"] += 1
        scan_status["findings_by_severity"][finding.severity.name] += 1
        
        # Add to findings list
        findings.append(finding_dict)
        
        # Emit updates to clients
        self.socket_io.emit('new_finding', finding_dict, broadcast=True)
        self.socket_io.emit('status_update', scan_status, broadcast=True)
    
    def update_progress(self, url: str, total: int, current: int):
        """Update scan progress."""
        scan_status["total_urls"] = total
        scan_status["scanned_urls"] = current
        self.socket_io.emit('progress_update', {
            'url': url,
            'total': total,
            'current': current,
            'percentage': (current / total * 100) if total > 0 else 0
        }, broadcast=True)
        self.socket_io.emit('status_update', scan_status, broadcast=True)


def start_server(host='localhost', port=5000, debug=False):
    """Start the Flask-SocketIO server."""
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    start_server(debug=True)
