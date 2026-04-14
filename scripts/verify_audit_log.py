#!/usr/bin/env python3
"""
Audit Log Verification Utility
CLI tool to verify audit log chain integrity and detect tampering.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
import logging

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.audit.log_verifier import LogVerifier
from core.audit.hash_chain import HashChain
from core.audit.audit_logger import AuditLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AuditLogVerifier:
    """Utility for verifying audit log integrity."""
    
    def __init__(self, log_path: str = None):
        """Initialize verifier with log path."""
        if log_path:
            self.log_path = Path(log_path)
        else:
            self.log_path = project_root / "core" / "audit" / "logs" / "audit_chain.jsonl"
        
        self.verifier = LogVerifier()
        self.hash_chain = HashChain()
    
    def verify_integrity(self) -> dict:
        """Verify complete audit log integrity."""
        logger.info(f"Verifying audit log: {self.log_path}")
        
        if not self.log_path.exists():
            raise Exception(f"Audit log not found: {self.log_path}")
        
        # Perform comprehensive verification
        verification_result = self.verifier.verify_log_integrity(str(self.log_path))
        
        return verification_result
    
    def verify_chain(self) -> dict:
        """Verify hash chain integrity."""
        logger.info("Verifying hash chain...")
        
        chain_result = self.hash_chain.verify_integrity(str(self.log_path))
        
        return chain_result
    
    def verify_signatures(self) -> dict:
        """Verify all entry signatures."""
        logger.info("Verifying entry signatures...")
        
        signature_results = {
            "total_entries": 0,
            "valid_signatures": 0,
            "invalid_signatures": 0,
            "missing_signatures": 0,
            "details": []
        }
        
        with open(self.log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                
                try:
                    entry = json.loads(line)
                    signature_results["total_entries"] += 1
                    
                    if "signature" not in entry:
                        signature_results["missing_signatures"] += 1
                        signature_results["details"].append({
                            "line": line_num,
                            "log_id": entry.get("log_id", "unknown"),
                            "status": "MISSING_SIGNATURE"
                        })
                        continue
                    
                    # Verify signature
                    entry_verification = self.verifier.verify_entry_signature(
                        str(self.log_path),
                        entry.get("log_id")
                    )
                    
                    if entry_verification.get("signature_verified", False):
                        signature_results["valid_signatures"] += 1
                        signature_results["details"].append({
                            "line": line_num,
                            "log_id": entry.get("log_id", "unknown"),
                            "status": "VALID"
                        })
                    else:
                        signature_results["invalid_signatures"] += 1
                        signature_results["details"].append({
                            "line": line_num,
                            "log_id": entry.get("log_id", "unknown"),
                            "status": "INVALID"
                        })
                
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON on line {line_num}: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Error verifying entry on line {line_num}: {e}")
                    continue
        
        return signature_results
    
    def detect_tampering(self) -> dict:
        """Detect specific tampering patterns."""
        logger.info("Detecting tampering patterns...")
        
        tampering_results = {
            "total_entries": 0,
            "suspicious_entries": 0,
            "tampering_detected": False,
            "patterns": {
                "missing_entries": [],
                "duplicate_entries": [],
                "out_of_sequence": [],
                "modified_timestamps": [],
                "suspicious_gaps": []
            }
        }
        
        entries = []
        log_ids = set()
        timestamps = []
        
        # Load all entries
        with open(self.log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                    log_ids.add(entry.get("log_id"))
                    
                    if "timestamp" in entry:
                        timestamps.append((line_num, entry["timestamp"]))
                    
                    tampering_results["total_entries"] += 1
                
                except json.JSONDecodeError:
                    continue
        
        # Check for duplicate log IDs
        if len(log_ids) != len(entries):
            seen_ids = set()
            for i, entry in enumerate(entries):
                log_id = entry.get("log_id")
                if log_id in seen_ids:
                    tampering_results["patterns"]["duplicate_entries"].append({
                        "line": i + 1,
                        "log_id": log_id
                    })
                    tampering_results["suspicious_entries"] += 1
                seen_ids.add(log_id)
        
        # Check timestamp sequence
        sorted_timestamps = sorted(timestamps, key=lambda x: x[1])
        for i in range(1, len(sorted_timestamps)):
            prev_line, prev_time = sorted_timestamps[i-1]
            curr_line, curr_time = sorted_timestamps[i]
            
            prev_dt = datetime.fromisoformat(prev_time.replace('Z', '+00:00'))
            curr_dt = datetime.fromisoformat(curr_time.replace('Z', '+00:00'))
            
            if curr_dt < prev_dt:  # Timestamp went backwards
                tampering_results["patterns"]["out_of_sequence"].append({
                    "line": curr_line,
                    "timestamp": curr_time,
                    "previous_timestamp": prev_time
                })
                tampering_results["suspicious_entries"] += 1
        
        # Check for suspicious gaps in timestamps
        if len(timestamps) > 1:
            sorted_timestamps = sorted(timestamps, key=lambda x: x[1])
            gaps = []
            for i in range(1, len(sorted_timestamps)):
                prev_time = datetime.fromisoformat(sorted_timestamps[i-1][1].replace('Z', '+00:00'))
                curr_time = datetime.fromisoformat(sorted_timestamps[i][1].replace('Z', '+00:00'))
                gap = (curr_time - prev_time).total_seconds()
                
                if gap > 3600:  # Gap > 1 hour
                    gaps.append({
                        "line": sorted_timestamps[i][0],
                        "gap_seconds": gap,
                        "start_time": sorted_timestamps[i-1][1],
                        "end_time": sorted_timestamps[i][1]
                    })
            
            tampering_results["patterns"]["suspicious_gaps"] = gaps
            if gaps:
                tampering_results["suspicious_entries"] += len(gaps)
        
        tampering_results["tampering_detected"] = (
            tampering_results["suspicious_entries"] > 0 or
            any(len(pattern) > 0 for pattern in tampering_results["patterns"].values())
        )
        
        return tampering_results
    
    def generate_report(self, output_file: str = None) -> dict:
        """Generate comprehensive verification report."""
        logger.info("Generating verification report...")
        
        # Run all verifications
        integrity_result = self.verify_integrity()
        chain_result = self.verify_chain()
        signature_result = self.verify_signatures()
        tampering_result = self.detect_tampering()
        
        # Compile report
        report = {
            "report_generated_at": datetime.utcnow().isoformat(),
            "audit_log_path": str(self.log_path),
            "summary": {
                "total_entries": signature_result["total_entries"],
                "valid_signatures": signature_result["valid_signatures"],
                "invalid_signatures": signature_result["invalid_signatures"],
                "missing_signatures": signature_result["missing_signatures"],
                "integrity_valid": integrity_result.get("valid", False),
                "chain_valid": chain_result.get("valid", False),
                "tampering_detected": tampering_result["tampering_detected"]
            },
            "integrity_verification": integrity_result,
            "hash_chain_verification": chain_result,
            "signature_verification": signature_result,
            "tampering_analysis": tampering_result,
            "recommendations": self._generate_recommendations(
                integrity_result, chain_result, signature_result, tampering_result
            )
        }
        
        # Save report if output file specified
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to: {output_file}")
        
        return report
    
    def _generate_recommendations(self, integrity_result, chain_result, 
                                signature_result, tampering_result) -> list:
        """Generate recommendations based on verification results."""
        recommendations = []
        
        if not integrity_result.get("valid", False):
            recommendations.append({
                "priority": "CRITICAL",
                "issue": "Audit log integrity compromised",
                "action": "Investigate potential tampering and restore from backup"
            })
        
        if not chain_result.get("valid", False):
            recommendations.append({
                "priority": "CRITICAL",
                "issue": "Hash chain integrity broken",
                "action": "Rebuild audit chain from trusted backup"
            })
        
        if signature_result["invalid_signatures"] > 0:
            recommendations.append({
                "priority": "HIGH",
                "issue": f"{signature_result['invalid_signatures']} invalid signatures found",
                "action": "Review tampered entries and investigate source"
            })
        
        if signature_result["missing_signatures"] > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "issue": f"{signature_result['missing_signatures']} entries missing signatures",
                "action": "Ensure all audit entries are properly signed"
            })
        
        if tampering_result["tampering_detected"]:
            recommendations.append({
                "priority": "CRITICAL",
                "issue": "Tampering patterns detected",
                "action": "Conduct full security audit and review access logs"
            })
        
        if (integrity_result.get("valid", False) and 
            chain_result.get("valid", False) and 
            signature_result["invalid_signatures"] == 0 and
            not tampering_result["tampering_detected"]):
            recommendations.append({
                "priority": "INFO",
                "issue": "All verifications passed",
                "action": "Audit log is secure and intact"
            })
        
        return recommendations
    
    def print_summary(self, report: dict):
        """Print verification summary."""
        print("\n" + "="*60)
        print("AUDIT LOG VERIFICATION REPORT")
        print("="*60)
        
        summary = report["summary"]
        print(f"Log File: {report['audit_log_path']}")
        print(f"Total Entries: {summary['total_entries']}")
        print(f"Valid Signatures: {summary['valid_signatures']}")
        print(f"Invalid Signatures: {summary['invalid_signatures']}")
        print(f"Missing Signatures: {summary['missing_signatures']}")
        print(f"Integrity Valid: {'YES' if summary['integrity_valid'] else 'NO'}")
        print(f"Chain Valid: {'YES' if summary['chain_valid'] else 'NO'}")
        print(f"Tampering Detected: {'YES' if summary['tampering_detected'] else 'NO'}")
        
        # Print recommendations
        print("\nRECOMMENDATIONS:")
        print("-" * 40)
        
        for i, rec in enumerate(report["recommendations"], 1):
            priority_icon = {
                "CRITICAL": "!!!",
                "HIGH": "!!",
                "MEDIUM": "!",
                "INFO": "i"
            }.get(rec["priority"], "?")
            
            print(f"{priority_icon} [{rec['priority']}] {rec['issue']}")
            print(f"   Action: {rec['action']}")
        
        print("="*60)
    
    def export_entries(self, start_date: str = None, end_date: str = None, 
                      output_file: str = None) -> list:
        """Export audit entries within date range."""
        logger.info("Exporting audit entries...")
        
        entries = []
        
        with open(self.log_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    entry = json.loads(line)
                    
                    # Filter by date range if specified
                    if start_date or end_date:
                        entry_time = datetime.fromisoformat(entry["timestamp"].replace('Z', '+00:00'))
                        
                        if start_date:
                            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                            if entry_time < start_dt:
                                continue
                        
                        if end_date:
                            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                            if entry_time > end_dt:
                                continue
                    
                    entries.append(entry)
                
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.warning(f"Error processing entry: {e}")
                    continue
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(entries, f, indent=2)
            logger.info(f"Exported {len(entries)} entries to: {output_file}")
        
        return entries

def main():
    """Main function for audit log verification utility."""
    parser = argparse.ArgumentParser(description="Audit Log Verification Utility")
    
    # Verification commands
    parser.add_argument("command", choices=[
        "verify", "chain", "signatures", "tampering", "report", "export"
    ], help="Verification command to execute")
    
    # Arguments
    parser.add_argument("--log-path", help="Path to audit log file")
    parser.add_argument("--output", help="Output file for reports/exports")
    parser.add_argument("--start-date", help="Start date for export (ISO format)")
    parser.add_argument("--end-date", help="End date for export (ISO format)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        verifier = AuditLogVerifier(args.log_path)
        
        if args.command == "verify":
            result = verifier.verify_integrity()
            print(json.dumps(result, indent=2))
        
        elif args.command == "chain":
            result = verifier.verify_chain()
            print(json.dumps(result, indent=2))
        
        elif args.command == "signatures":
            result = verifier.verify_signatures()
            print(json.dumps(result, indent=2))
        
        elif args.command == "tampering":
            result = verifier.detect_tampering()
            print(json.dumps(result, indent=2))
        
        elif args.command == "report":
            report = verifier.generate_report(args.output)
            verifier.print_summary(report)
        
        elif args.command == "export":
            entries = verifier.export_entries(
                args.start_date, 
                args.end_date, 
                args.output
            )
            print(f"Exported {len(entries)} entries")
        
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Operation failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
