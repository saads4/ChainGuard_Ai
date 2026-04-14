"""
Campaign management tool for marketing agent.
Handles marketing campaign creation, management, and tracking.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class CampaignTool:
    """Tool for managing marketing campaigns."""
    
    def __init__(self):
        self.supported_campaign_types = [
            "email",
            "social_media",
            "content_marketing",
            "paid_advertising",
            "influencer"
        ]
        self.campaign_statuses = ["draft", "active", "paused", "completed", "cancelled"]
    
    def create_campaign(self, campaign_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new marketing campaign.
        
        Args:
            campaign_data: Dictionary containing campaign information
                - name: str
                - type: str
                - budget: float
                - start_date: str (ISO format)
                - end_date: str (ISO format)
                - target_audience: Dict
                - objectives: List[str]
        
        Returns:
            Dict containing campaign creation result
        """
        try:
            # Validate campaign data
            validation_result = self._validate_campaign_data(campaign_data)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": validation_result["error"],
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Create campaign
            campaign_id = self._generate_campaign_id()
            campaign = {
                "campaign_id": campaign_id,
                "name": campaign_data["name"],
                "type": campaign_data["type"],
                "budget": campaign_data["budget"],
                "actual_spend": 0.0,
                "start_date": campaign_data["start_date"],
                "end_date": campaign_data["end_date"],
                "target_audience": campaign_data["target_audience"],
                "objectives": campaign_data["objectives"],
                "status": "draft",
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
                "metrics": {
                    "impressions": 0,
                    "clicks": 0,
                    "conversions": 0,
                    "engagement_rate": 0.0
                }
            }
            
            logger.info(f"Campaign created: {campaign_id}")
            
            return {
                "success": True,
                "campaign": campaign,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Campaign creation error: {str(e)}")
            return {
                "success": False,
                "error": f"Campaign creation failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def update_campaign(self, campaign_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing campaign."""
        try:
            # Validate campaign exists (in real implementation, check database)
            if not self._campaign_exists(campaign_id):
                return {
                    "success": False,
                    "error": f"Campaign {campaign_id} not found",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Validate updates
            validation_result = self._validate_campaign_updates(updates)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": validation_result["error"],
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Apply updates
            updated_campaign = {
                "campaign_id": campaign_id,
                "updated_at": datetime.utcnow().isoformat(),
                **updates
            }
            
            logger.info(f"Campaign updated: {campaign_id}")
            
            return {
                "success": True,
                "campaign": updated_campaign,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Campaign update error: {str(e)}")
            return {
                "success": False,
                "error": f"Campaign update failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def get_campaign_performance(self, campaign_id: str) -> Dict[str, Any]:
        """Get performance metrics for a campaign."""
        try:
            if not self._campaign_exists(campaign_id):
                return {
                    "success": False,
                    "error": f"Campaign {campaign_id} not found",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Mock performance data
            performance = {
                "campaign_id": campaign_id,
                "period": "last_30_days",
                "metrics": {
                    "impressions": 45230,
                    "clicks": 1847,
                    "conversions": 89,
                    "engagement_rate": 4.08,
                    "cost_per_click": 2.34,
                    "cost_per_acquisition": 48.56,
                    "return_on_ad_spend": 3.42
                },
                "trend": {
                    "impressions_change": 12.3,
                    "clicks_change": 8.7,
                    "conversions_change": -2.1
                },
                "generated_at": datetime.utcnow().isoformat()
            }
            
            return {
                "success": True,
                "performance": performance,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Performance retrieval error: {str(e)}")
            return {
                "success": False,
                "error": f"Performance retrieval failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def list_campaigns(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """List campaigns with optional filters."""
        try:
            # Mock campaign list
            campaigns = [
                {
                    "campaign_id": "CAMPAIGN_001",
                    "name": "Q1 Product Launch",
                    "type": "email",
                    "status": "active",
                    "budget": 5000.0,
                    "actual_spend": 2345.67,
                    "start_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-03-31T23:59:59Z"
                },
                {
                    "campaign_id": "CAMPAIGN_002",
                    "name": "Social Media Awareness",
                    "type": "social_media",
                    "status": "completed",
                    "budget": 3000.0,
                    "actual_spend": 2987.45,
                    "start_date": "2023-11-01T00:00:00Z",
                    "end_date": "2023-11-30T23:59:59Z"
                }
            ]
            
            # Apply filters if provided
            if filters:
                campaigns = self._apply_filters(campaigns, filters)
            
            return {
                "success": True,
                "campaigns": campaigns,
                "total_count": len(campaigns),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Campaign listing error: {str(e)}")
            return {
                "success": False,
                "error": f"Campaign listing failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def _validate_campaign_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate campaign creation data."""
        required_fields = ["name", "type", "budget", "start_date", "end_date", "target_audience", "objectives"]
        for field in required_fields:
            if field not in data:
                return {"valid": False, "error": f"Missing required field: {field}"}
        
        # Validate campaign type
        if data["type"] not in self.supported_campaign_types:
            return {"valid": False, "error": f"Unsupported campaign type: {data['type']}"}
        
        # Validate budget
        try:
            budget = float(data["budget"])
            if budget <= 0:
                return {"valid": False, "error": "Budget must be positive"}
            if budget > 1000000:  # $1M limit
                return {"valid": False, "error": "Budget exceeds maximum limit"}
        except (ValueError, TypeError):
            return {"valid": False, "error": "Invalid budget format"}
        
        # Validate dates
        try:
            start_date = datetime.fromisoformat(data["start_date"].replace('Z', '+00:00'))
            end_date = datetime.fromisoformat(data["end_date"].replace('Z', '+00:00'))
            
            if start_date >= end_date:
                return {"valid": False, "error": "Start date must be before end date"}
            
            if start_date < datetime.now():
                return {"valid": False, "error": "Start date cannot be in the past"}
                
        except ValueError:
            return {"valid": False, "error": "Invalid date format"}
        
        return {"valid": True}
    
    def _validate_campaign_updates(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Validate campaign update data."""
        if "status" in updates and updates["status"] not in self.campaign_statuses:
            return {"valid": False, "error": f"Invalid status: {updates['status']}"}
        
        if "budget" in updates:
            try:
                budget = float(updates["budget"])
                if budget <= 0:
                    return {"valid": False, "error": "Budget must be positive"}
            except (ValueError, TypeError):
                return {"valid": False, "error": "Invalid budget format"}
        
        return {"valid": True}
    
    def _campaign_exists(self, campaign_id: str) -> bool:
        """Check if campaign exists (mock implementation)."""
        # In real implementation, this would check database
        return campaign_id.startswith("CAMPAIGN_")
    
    def _apply_filters(self, campaigns: List[Dict], filters: Dict[str, Any]) -> List[Dict]:
        """Apply filters to campaign list."""
        filtered = campaigns.copy()
        
        if "status" in filters:
            filtered = [c for c in filtered if c["status"] == filters["status"]]
        
        if "type" in filters:
            filtered = [c for c in filtered if c["type"] == filters["type"]]
        
        return filtered
    
    def _generate_campaign_id(self) -> str:
        """Generate unique campaign ID."""
        import uuid
        return f"CAMPAIGN_{uuid.uuid4().hex[:12].upper()}"
