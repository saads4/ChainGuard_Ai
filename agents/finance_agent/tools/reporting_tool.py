"""
Financial reporting tool for finance agent.
Handles report generation and financial data analysis.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class ReportingTool:
    """Tool for generating financial reports."""
    
    def __init__(self):
        self.supported_report_types = [
            "transaction_summary",
            "cash_flow",
            "expense_analysis",
            "revenue_report"
        ]
    
    def generate_report(self, report_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a financial report.
        
        Args:
            report_request: Dictionary containing report parameters
                - report_type: str
                - start_date: str (ISO format)
                - end_date: str (ISO format)
                - filters: Dict (optional)
        
        Returns:
            Dict containing generated report
        """
        try:
            # Validate report request
            validation_result = self._validate_report_request(report_request)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": validation_result["error"],
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Generate report
            report_id = self._generate_report_id()
            report_data = self._create_report_data(report_request)
            
            report = {
                "report_id": report_id,
                "report_type": report_request["report_type"],
                "period": {
                    "start_date": report_request["start_date"],
                    "end_date": report_request["end_date"]
                },
                "generated_at": datetime.utcnow().isoformat(),
                "data": report_data
            }
            
            logger.info(f"Report generated: {report_id}")
            
            return {
                "success": True,
                "report": report,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Report generation error: {str(e)}")
            return {
                "success": False,
                "error": f"Report generation failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def _validate_report_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Validate report request."""
        # Check required fields
        required_fields = ["report_type", "start_date", "end_date"]
        for field in required_fields:
            if field not in request:
                return {"valid": False, "error": f"Missing required field: {field}"}
        
        # Validate report type
        if request["report_type"] not in self.supported_report_types:
            return {"valid": False, "error": f"Unsupported report type: {request['report_type']}"}
        
        # Validate dates
        try:
            start_date = datetime.fromisoformat(request["start_date"].replace('Z', '+00:00'))
            end_date = datetime.fromisoformat(request["end_date"].replace('Z', '+00:00'))
            
            if start_date >= end_date:
                return {"valid": False, "error": "Start date must be before end date"}
            
            # Check if date range is reasonable (not more than 1 year)
            if end_date - start_date > timedelta(days=365):
                return {"valid": False, "error": "Date range cannot exceed 1 year"}
                
        except ValueError:
            return {"valid": False, "error": "Invalid date format. Use ISO format (YYYY-MM-DDTHH:MM:SSZ)"}
        
        return {"valid": True}
    
    def _create_report_data(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Create report data based on type."""
        report_type = request["report_type"]
        
        if report_type == "transaction_summary":
            return self._create_transaction_summary(request)
        elif report_type == "cash_flow":
            return self._create_cash_flow_report(request)
        elif report_type == "expense_analysis":
            return self._create_expense_analysis(request)
        elif report_type == "revenue_report":
            return self._create_revenue_report(request)
        else:
            return {"error": "Unknown report type"}
    
    def _create_transaction_summary(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Create transaction summary report."""
        # Mock data - in real implementation, this would query database
        return {
            "total_transactions": 1250,
            "total_amount": 457890.50,
            "average_transaction": 366.31,
            "currency_breakdown": {
                "USD": 85.2,
                "EUR": 10.1,
                "GBP": 4.7
            },
            "daily_averages": {
                "transactions_per_day": 42.5,
                "amount_per_day": 15263.02
            }
        }
    
    def _create_cash_flow_report(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Create cash flow report."""
        return {
            "inflows": {
                "total": 678900.00,
                "sources": {
                    "sales": 523400.00,
                    "investments": 89500.00,
                    "other": 66000.00
                }
            },
            "outflows": {
                "total": 456780.00,
                "categories": {
                    "operations": 234560.00,
                    "salaries": 123450.00,
                    "expenses": 98770.00
                }
            },
            "net_cash_flow": 222120.00
        }
    
    def _create_expense_analysis(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Create expense analysis report."""
        return {
            "total_expenses": 234560.00,
            "expense_categories": {
                "operations": 45.2,
                "salaries": 26.3,
                "marketing": 15.8,
                "infrastructure": 8.7,
                "other": 4.0
            },
            "trend_analysis": {
                "month_over_month_change": 2.3,
                "year_over_year_change": 8.7
            }
        }
    
    def _create_revenue_report(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Create revenue report."""
        return {
            "total_revenue": 678900.00,
            "revenue_streams": {
                "product_sales": 423400.00,
                "services": 156500.00,
                "subscriptions": 89000.00,
                "other": 10000.00
            },
            "growth_metrics": {
                "monthly_growth_rate": 5.2,
                "yearly_growth_rate": 23.8
            }
        }
    
    def _generate_report_id(self) -> str:
        """Generate unique report ID."""
        import uuid
        return f"RPT_{uuid.uuid4().hex[:12].upper()}"
    
    def list_available_reports(self) -> Dict[str, Any]:
        """List available report types."""
        return {
            "supported_report_types": self.supported_report_types,
            "description": {
                "transaction_summary": "Summary of all transactions within period",
                "cash_flow": "Detailed cash flow analysis",
                "expense_analysis": "Breakdown of expenses by category",
                "revenue_report": "Revenue analysis by stream"
            }
        }
