"""
Web Vulnerability Scanner - Reporter Module

This module provides functionality to:
- Store and manage vulnerability findings
- Write findings to a database
- Export findings to various formats (JSON, HTML, etc.)
- Generate vulnerability reports
"""

import json
import logging
import sqlite3
import os
import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid
import html
from .safety import get_safety_manager, safe_file_write

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('scanner.reporter')


class Severity(Enum):
    """Enumeration of vulnerability severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Data class to represent a vulnerability finding."""
    # Required fields
    title: str
    description: str
    url: str
    severity: Severity
    plugin_name: str
    
    # Auto-generated fields
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    
    # Optional fields
    evidence: Optional[str] = None
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    false_positive: bool = False
    tags: List[str] = field(default_factory=list)


class Reporter:
    """Class to manage vulnerability findings and generate reports."""
    
    def __init__(self, db_path: Optional[str] = None, report_dir: str = "reports"):
        """
        Initialize the reporter.
        
        Args:
            db_path: Path to SQLite database file (None for in-memory only)
            report_dir: Directory for storing report files
        """
        self.findings: List[Finding] = []
        self.db_path = db_path
        self.report_dir = report_dir
        
        # Ensure report directory exists
        os.makedirs(report_dir, exist_ok=True)
        
        # Set up database if path provided
        if db_path:
            self._setup_database()
    
    def _setup_database(self) -> None:
        """Set up the SQLite database schema if it doesn't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create findings table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            url TEXT NOT NULL,
            severity TEXT NOT NULL,
            plugin_name TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            evidence TEXT,
            request_data TEXT,
            response_data TEXT,
            remediation TEXT,
            cwe_id TEXT,
            cvss_score REAL,
            false_positive INTEGER,
            tags TEXT
        )
        ''')
        
        # Create scan_metadata table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_metadata (
            scan_id TEXT PRIMARY KEY,
            start_time TEXT NOT NULL,
            end_time TEXT,
            target_urls TEXT NOT NULL,
            config TEXT,
            stats TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_finding(self, finding: Finding) -> None:
        """
        Add a vulnerability finding.
        
        Args:
            finding: Finding to add
        """
        self.findings.append(finding)
        logger.info(f"Added finding: {finding.title} ({finding.severity.value}) at {finding.url}")
        
        # Save to database if configured
        if self.db_path:
            self._save_finding_to_db(finding)
    
    def _save_finding_to_db(self, finding: Finding) -> None:
        """
        Save a finding to the SQLite database.
        
        Args:
            finding: Finding to save
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Convert dictionaries and lists to JSON strings
        request_data = json.dumps(finding.request_data) if finding.request_data else None
        response_data = json.dumps(finding.response_data) if finding.response_data else None
        tags = json.dumps(finding.tags) if finding.tags else None
        
        # Insert the finding
        cursor.execute('''
        INSERT OR REPLACE INTO findings (
            id, title, description, url, severity, plugin_name, timestamp,
            evidence, request_data, response_data, remediation,
            cwe_id, cvss_score, false_positive, tags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.id,
            finding.title,
            finding.description,
            finding.url,
            finding.severity.value,
            finding.plugin_name,
            finding.timestamp,
            finding.evidence,
            request_data,
            response_data,
            finding.remediation,
            finding.cwe_id,
            finding.cvss_score,
            1 if finding.false_positive else 0,
            tags
        ))
        
        conn.commit()
        conn.close()
    
    def get_findings(
        self, 
        severity: Optional[Union[Severity, List[Severity]]] = None,
        plugin_name: Optional[str] = None,
        url_contains: Optional[str] = None,
        false_positives: bool = False
    ) -> List[Finding]:
        """
        Get filtered findings.
        
        Args:
            severity: Filter by severity level or list of levels
            plugin_name: Filter by plugin name
            url_contains: Filter by URL substring
            false_positives: Whether to include false positives
            
        Returns:
            List[Finding]: Filtered findings
        """
        filtered = self.findings.copy()
        
        # Filter out false positives unless requested
        if not false_positives:
            filtered = [f for f in filtered if not f.false_positive]
        
        # Apply severity filter
        if severity:
            if isinstance(severity, list):
                filtered = [f for f in filtered if f.severity in severity]
            else:
                filtered = [f for f in filtered if f.severity == severity]
        
        # Apply plugin filter
        if plugin_name:
            filtered = [f for f in filtered if f.plugin_name == plugin_name]
        
        # Apply URL filter
        if url_contains:
            filtered = [f for f in filtered if url_contains in f.url]
        
        return filtered
    
    def get_finding_by_id(self, finding_id: str) -> Optional[Finding]:
        """
        Get a finding by its ID.
        
        Args:
            finding_id: ID of the finding to retrieve
            
        Returns:
            Finding or None: The finding if found, None otherwise
        """
        for finding in self.findings:
            if finding.id == finding_id:
                return finding
        return None
    
    def mark_as_false_positive(self, finding_id: str) -> bool:
        """
        Mark a finding as a false positive.
        
        Args:
            finding_id: ID of the finding to mark
            
        Returns:
            bool: True if successful, False if finding not found
        """
        finding = self.get_finding_by_id(finding_id)
        if not finding:
            return False
        
        finding.false_positive = True
        
        # Update in database if configured
        if self.db_path:
            self._save_finding_to_db(finding)
        
        return True
    
    def update_finding(self, finding: Finding) -> None:
        """
        Update an existing finding.
        
        Args:
            finding: Finding to update
        """
        # Find and replace the existing finding
        for i, existing in enumerate(self.findings):
            if existing.id == finding.id:
                self.findings[i] = finding
                break
        
        # Update in database if configured
        if self.db_path:
            self._save_finding_to_db(finding)
    
    def export_to_json(self, filename: Optional[str] = None) -> str:
        """
        Export findings to JSON format.
        
        Args:
            filename: Output file path (default: auto-generated based on scan target)
            
        Returns:
            str: Path to the exported file
        """
        if not filename:
            # Generate filename based on database name if available
            if self.db_path:
                base_name = os.path.splitext(os.path.basename(self.db_path))[0]
                filename = os.path.join(self.report_dir, f"{base_name}.json")
            else:
                filename = os.path.join(self.report_dir, "last_scan.json")
        
        # Convert findings to dictionaries
        findings_dict = [asdict(f) for f in self.findings]
        
        # Convert Severity enums to strings
        for f in findings_dict:
            f["severity"] = f["severity"].value
        
        # Add metadata
        report = {
            "scan_time": datetime.datetime.now().isoformat(),
            "findings_count": len(self.findings),
            "findings": findings_dict
        }
        
        # Write to file
        # Use safe file write to ensure security
        json_content = json.dumps(report, indent=2, ensure_ascii=False)
        if safe_file_write(filename, json_content):
            logger.info(f"JSON report exported to {filename}")
            return filename
        else:
            raise RuntimeError(f"Failed to write JSON report - file path blocked by security policy: {filename}")
    
    def export_to_html(self, filename: Optional[str] = None) -> str:
        """
        Export findings to HTML format.
        
        Args:
            filename: Output file path (default: auto-generated based on scan target)
            
        Returns:
            str: Path to the exported file
        """
        if not filename:
            # Generate filename based on database name if available
            if self.db_path:
                base_name = os.path.splitext(os.path.basename(self.db_path))[0]
                filename = os.path.join(self.report_dir, f"{base_name}.html")
            else:
                filename = os.path.join(self.report_dir, "last_scan.html")
        
        # Count findings by severity
        severity_counts = {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0
        }
        
        for finding in self.findings:
            if not finding.false_positive:
                severity_counts[finding.severity.value] += 1
        
        # Group findings by severity for the report
        findings_by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: [],
            Severity.INFO: []
        }
        
        for finding in self.findings:
            if not finding.false_positive:
                findings_by_severity[finding.severity].append(finding)
        
        # Generate the HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Vulnerability Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .summary {{ display: flex; justify-content: space-between; margin: 20px 0; }}
        .summary-box {{ padding: 15px; border-radius: 5px; width: 18%; text-align: center; }}
        .info {{ background-color: #3498db; color: white; }}
        .low {{ background-color: #2ecc71; color: white; }}
        .medium {{ background-color: #f39c12; color: white; }}
        .high {{ background-color: #e74c3c; color: white; }}
        .critical {{ background-color: #9b59b6; color: white; }}
        .finding {{ margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .finding h3 {{ margin-top: 0; }}
        .finding-critical {{ border-left: 5px solid #9b59b6; }}
        .finding-high {{ border-left: 5px solid #e74c3c; }}
        .finding-medium {{ border-left: 5px solid #f39c12; }}
        .finding-low {{ border-left: 5px solid #2ecc71; }}
        .finding-info {{ border-left: 5px solid #3498db; }}
        .evidence {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Web Vulnerability Scan Report</h1>
        <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-box critical">
                <h3>Critical</h3>
                <p>{severity_counts["critical"]}</p>
            </div>
            <div class="summary-box high">
                <h3>High</h3>
                <p>{severity_counts["high"]}</p>
            </div>
            <div class="summary-box medium">
                <h3>Medium</h3>
                <p>{severity_counts["medium"]}</p>
            </div>
            <div class="summary-box low">
                <h3>Low</h3>
                <p>{severity_counts["low"]}</p>
            </div>
            <div class="summary-box info">
                <h3>Info</h3>
                <p>{severity_counts["info"]}</p>
            </div>
        </div>
        
        <h2>Findings</h2>
"""
        
        # Add findings by severity (critical to info)
        for severity, findings in findings_by_severity.items():
            if not findings:
                continue
                
            html_content += f"""
        <h3>{severity.value.capitalize()} Severity Findings ({len(findings)})</h3>
"""
            
            for finding in findings:
                # Escape HTML in content
                safe_title = html.escape(finding.title)
                safe_description = html.escape(finding.description)
                safe_url = html.escape(finding.url)
                safe_plugin = html.escape(finding.plugin_name)
                
                # Evidence section
                evidence_html = ""
                if finding.evidence:
                    safe_evidence = html.escape(finding.evidence)
                    evidence_html = f"""
                <h4>Evidence</h4>
                <div class="evidence">
                    <pre>{safe_evidence}</pre>
                </div>"""
                
                # Remediation section
                remediation_html = ""
                if finding.remediation:
                    safe_remediation = html.escape(finding.remediation)
                    remediation_html = f"""
                <h4>Remediation</h4>
                <p>{safe_remediation}</p>"""
                
                html_content += f"""
        <div class="finding finding-{severity.value}">
            <h3>{safe_title}</h3>
            <table>
                <tr>
                    <th>URL</th>
                    <td><a href="{safe_url}" target="_blank">{safe_url}</a></td>
                </tr>
                <tr>
                    <th>Plugin</th>
                    <td>{safe_plugin}</td>
                </tr>
                <tr>
                    <th>Severity</th>
                    <td>{severity.value.upper()}</td>
                </tr>
                {"<tr><th>CWE</th><td>CWE-" + finding.cwe_id + "</td></tr>" if finding.cwe_id else ""}
                {"<tr><th>CVSS</th><td>" + str(finding.cvss_score) + "</td></tr>" if finding.cvss_score else ""}
            </table>
            <h4>Description</h4>
            <p>{safe_description}</p>
            {evidence_html}
            {remediation_html}
        </div>
"""
        
        # Close the HTML document
        html_content += """
    </div>
</body>
</html>
"""
        
        # Write to file
        # Use safe file write to ensure security
        if safe_file_write(filename, html_content):
            logger.info(f"HTML report exported to {filename}")
            return filename
        else:
            raise RuntimeError(f"Failed to write HTML report - file path blocked by security policy: {filename}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the findings.
        
        Returns:
            Dict: Statistics about the findings
        """
        stats = {
            "total": len(self.findings),
            "false_positives": len([f for f in self.findings if f.false_positive]),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "by_plugin": {}
        }
        
        for finding in self.findings:
            if not finding.false_positive:
                # Count by severity
                stats["by_severity"][finding.severity.value] += 1
                
                # Count by plugin
                plugin = finding.plugin_name
                if plugin not in stats["by_plugin"]:
                    stats["by_plugin"][plugin] = 1
                else:
                    stats["by_plugin"][plugin] += 1
                    
        return stats
    
    def load_findings_from_db(self) -> int:
        """
        Load findings from the SQLite database into memory.
        
        Returns:
            int: Number of findings loaded
        """
        if not self.db_path:
            logger.warning("No database path configured, cannot load findings")
            return 0
            
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM findings")
        rows = cursor.fetchall()
        
        # Clear current findings and load from database
        self.findings = []
        
        for row in rows:
            # Parse JSON fields
            request_data = json.loads(row["request_data"]) if row["request_data"] else None
            response_data = json.loads(row["response_data"]) if row["response_data"] else None
            tags = json.loads(row["tags"]) if row["tags"] else []
            
            # Create Finding object
            finding = Finding(
                id=row["id"],
                title=row["title"],
                description=row["description"],
                url=row["url"],
                severity=Severity(row["severity"]),
                plugin_name=row["plugin_name"],
                timestamp=row["timestamp"],
                evidence=row["evidence"],
                request_data=request_data,
                response_data=response_data,
                remediation=row["remediation"],
                cwe_id=row["cwe_id"],
                cvss_score=row["cvss_score"],
                false_positive=bool(row["false_positive"]),
                tags=tags
            )
            
            self.findings.append(finding)
            
        conn.close()
        
        logger.info(f"Loaded {len(self.findings)} findings from database")
        return len(self.findings)
    
    def clear_findings(self) -> None:
        """Clear all findings from memory."""
        self.findings = []
        logger.info("Cleared all findings from memory")
