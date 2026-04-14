"""
Marketing Agent - Marketing agent logic (wrapped with ChainGuardAI)

Example marketing agent that handles marketing operations with ChainGuardAI protection:
- Campaign management
- Content creation
- Analytics processing
- Performance reporting
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from loguru import logger
from ..base_agent import BaseAgent


class MarketingAgent(BaseAgent):
    """Marketing agent with ChainGuardAI protection for handling marketing operations."""
    
    def __init__(self, agent_id: str = None, config: Dict[str, Any] = None):
        """
        Initialize MarketingAgent.
        
        Args:
            agent_id: Unique identifier for the agent
            config: Agent configuration
        """
        if agent_id is None:
            agent_id = f"marketing_agent_{uuid.uuid4().hex[:8]}"
        
        super().__init__(agent_id, "marketing_agent", config)
        
        # Marketing-specific configuration
        self.max_campaign_budget = self.config.get("max_campaign_budget", 10000)
        self.supported_platforms = self.config.get("supported_platforms", 
                                                   ["google_ads", "facebook", "twitter", "linkedin", "instagram"])
        self.content_types = self.config.get("content_types", ["text", "image", "video", "carousel"])
        
        # Campaign database (simplified for example)
        self.campaigns = {
            "demo_campaign_1": {
                "name": "Summer Sale 2024",
                "platform": "google_ads",
                "budget": 5000.00,
                "spent": 1250.50,
                "status": "active",
                "start_date": "2024-06-01",
                "end_date": "2024-08-31",
                "metrics": {
                    "impressions": 45000,
                    "clicks": 1200,
                    "conversions": 45,
                    "ctr": 2.67,
                    "cpc": 1.04,
                    "conversion_rate": 3.75
                }
            },
            "demo_campaign_2": {
                "name": "Product Launch",
                "platform": "facebook",
                "budget": 3000.00,
                "spent": 2100.00,
                "status": "active",
                "start_date": "2024-05-15",
                "end_date": "2024-07-15",
                "metrics": {
                    "impressions": 32000,
                    "clicks": 890,
                    "conversions": 28,
                    "ctr": 2.78,
                    "cpc": 2.36,
                    "conversion_rate": 3.15
                }
            }
        }
        
        # Content database
        self.content_library = {
            "content_1": {
                "title": "Summer Sale Announcement",
                "type": "text",
                "platform": "facebook",
                "content": "Don't miss our biggest summer sale! Up to 50% off on selected items. Limited time offer!",
                "created_date": "2024-06-01",
                "status": "published"
            },
            "content_2": {
                "title": "Product Showcase Video",
                "type": "video",
                "platform": "instagram",
                "content": "Video showcasing new product features and benefits",
                "created_date": "2024-05-20",
                "status": "draft"
            }
        }
        
        logger.info(f"MarketingAgent initialized: {agent_id}")
    
    def get_capabilities(self) -> List[str]:
        """Get marketing agent capabilities."""
        return [
            "campaign",
            "content",
            "analytics",
            "report",
            "create",
            "update",
            "publish"
        ]
    
    def handle_request(self, request: str) -> str:
        """
        Handle marketing-related requests.
        
        Args:
            request: User request string
            
        Returns:
            Response string
        """
        try:
            request_lower = request.lower().strip()
            
            # Parse request type
            if "campaign" in request_lower:
                return self._handle_campaign_request(request)
            elif "content" in request_lower:
                return self._handle_content_request(request)
            elif "analytics" in request_lower or "metrics" in request_lower:
                return self._handle_analytics_request(request)
            elif "report" in request_lower:
                return self._handle_report_request(request)
            elif "create" in request_lower:
                return self._handle_create_request(request)
            elif "publish" in request_lower:
                return self._handle_publish_request(request)
            else:
                return self._handle_general_request(request)
                
        except Exception as e:
            logger.error(f"Error handling request: {str(e)}")
            return f"Error processing request: {str(e)}"
    
    def _handle_campaign_request(self, request: str) -> str:
        """Handle campaign-related requests."""
        try:
            if "create" in request.lower():
                return self._create_campaign(request)
            elif "list" in request.lower() or "show" in request.lower():
                return self._list_campaigns()
            elif "details" in request.lower():
                campaign_name = self._extract_campaign_name(request)
                if campaign_name:
                    return self._get_campaign_details(campaign_name)
                else:
                    return "Please specify which campaign details you want."
            elif "pause" in request.lower() or "stop" in request.lower():
                campaign_name = self._extract_campaign_name(request)
                if campaign_name:
                    return self._pause_campaign(campaign_name)
                else:
                    return "Please specify which campaign to pause."
            elif "resume" in request.lower() or "start" in request.lower():
                campaign_name = self._extract_campaign_name(request)
                if campaign_name:
                    return self._resume_campaign(campaign_name)
                else:
                    return "Please specify which campaign to resume."
            else:
                return self._list_campaigns()
                
        except Exception as e:
            logger.error(f"Error in campaign request: {str(e)}")
            return f"Error processing campaign request: {str(e)}"
    
    def _handle_content_request(self, request: str) -> str:
        """Handle content-related requests."""
        try:
            if "create" in request.lower():
                return self._create_content(request)
            elif "list" in request.lower() or "show" in request.lower():
                return self._list_content()
            elif "edit" in request.lower() or "update" in request.lower():
                content_id = self._extract_content_id(request)
                if content_id:
                    return self._edit_content(content_id, request)
                else:
                    return "Please specify which content to edit."
            else:
                return self._list_content()
                
        except Exception as e:
            logger.error(f"Error in content request: {str(e)}")
            return f"Error processing content request: {str(e)}"
    
    def _handle_analytics_request(self, request: str) -> str:
        """Handle analytics-related requests."""
        try:
            if "campaign" in request.lower():
                campaign_name = self._extract_campaign_name(request)
                if campaign_name:
                    return self._get_campaign_analytics(campaign_name)
                else:
                    return self._get_overall_analytics()
            else:
                return self._get_overall_analytics()
                
        except Exception as e:
            logger.error(f"Error in analytics request: {str(e)}")
            return f"Error processing analytics request: {str(e)}"
    
    def _handle_report_request(self, request: str) -> str:
        """Handle report requests."""
        try:
            if "performance" in request.lower():
                return self._generate_performance_report()
            elif "campaign" in request.lower():
                campaign_name = self._extract_campaign_name(request)
                if campaign_name:
                    return self._generate_campaign_report(campaign_name)
                else:
                    return "Please specify which campaign report you want."
            else:
                return self._generate_performance_report()
                
        except Exception as e:
            logger.error(f"Error in report request: {str(e)}")
            return f"Error processing report request: {str(e)}"
    
    def _handle_create_request(self, request: str) -> str:
        """Handle general create requests."""
        try:
            if "campaign" in request.lower():
                return self._create_campaign(request)
            elif "content" in request.lower():
                return self._create_content(request)
            else:
                return "Please specify what you want to create (campaign or content)."
                
        except Exception as e:
            logger.error(f"Error in create request: {str(e)}")
            return f"Error processing create request: {str(e)}"
    
    def _handle_publish_request(self, request: str) -> str:
        """Handle publish requests."""
        try:
            content_id = self._extract_content_id(request)
            if content_id:
                return self._publish_content(content_id)
            else:
                return "Please specify which content to publish."
                
        except Exception as e:
            logger.error(f"Error in publish request: {str(e)}")
            return f"Error processing publish request: {str(e)}"
    
    def _handle_general_request(self, request: str) -> str:
        """Handle general marketing-related requests."""
        help_text = """
I can help you with the following marketing operations:
- Campaign management:
  * Create campaign: "Create a new Google Ads campaign with $5000 budget"
  * List campaigns: "Show all campaigns"
  * Campaign details: "Show details for Summer Sale campaign"
  * Pause campaign: "Pause the Product Launch campaign"
  * Resume campaign: "Resume the Summer Sale campaign"

- Content management:
  * Create content: "Create Facebook content about summer sale"
  * List content: "Show all content"
  * Edit content: "Edit content_1 with new text"
  * Publish content: "Publish content_2"

- Analytics:
  * Campaign analytics: "Show analytics for Summer Sale campaign"
  * Overall analytics: "Show overall marketing analytics"

- Reports:
  * Performance report: "Generate performance report"
  * Campaign report: "Generate report for Product Launch campaign"

Available campaigns: demo_campaign_1, demo_campaign_2
Available content: content_1, content_2
        """.strip()
        
        return help_text
    
    def _create_campaign(self, request: str) -> str:
        """Create a new marketing campaign."""
        try:
            # Extract campaign details
            name = self._extract_campaign_name(request) or f"Campaign_{int(time.time())}"
            platform = self._extract_platform(request) or "google_ads"
            budget = self._extract_budget(request) or 1000.00
            
            # Validate campaign
            if platform not in self.supported_platforms:
                return f"Platform '{platform}' not supported. Supported platforms: {', '.join(self.supported_platforms)}"
            
            if budget > self.max_campaign_budget:
                return f"Budget ${budget} exceeds maximum limit of ${self.max_campaign_budget}."
            
            # Create campaign
            campaign_id = f"campaign_{int(time.time() * 1000000)}"
            
            self.campaigns[campaign_id] = {
                "name": name,
                "platform": platform,
                "budget": budget,
                "spent": 0.00,
                "status": "active",
                "start_date": datetime.now().strftime("%Y-%m-%d"),
                "end_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
                "metrics": {
                    "impressions": 0,
                    "clicks": 0,
                    "conversions": 0,
                    "ctr": 0.0,
                    "cpc": 0.0,
                    "conversion_rate": 0.0
                }
            }
            
            return f"Campaign created successfully: {name} on {platform} with ${budget} budget. Campaign ID: {campaign_id}"
            
        except Exception as e:
            logger.error(f"Error creating campaign: {str(e)}")
            return f"Error creating campaign: {str(e)}"
    
    def _list_campaigns(self) -> str:
        """List all campaigns."""
        try:
            if not self.campaigns:
                return "No campaigns found."
            
            campaigns_list = "Active Campaigns:\n"
            
            for campaign_id, campaign in self.campaigns.items():
                status = campaign["status"]
                name = campaign["name"]
                platform = campaign["platform"]
                budget = campaign["budget"]
                spent = campaign["spent"]
                
                campaigns_list += f"- {name} ({platform}) - ${spent:.2f}/${budget:.2f} - Status: {status}\n"
            
            return campaigns_list.strip()
            
        except Exception as e:
            logger.error(f"Error listing campaigns: {str(e)}")
            return f"Error listing campaigns: {str(e)}"
    
    def _get_campaign_details(self, campaign_name: str) -> str:
        """Get detailed information about a campaign."""
        try:
            # Find campaign by name
            campaign = None
            campaign_id = None
            
            for cid, c in self.campaigns.items():
                if c["name"].lower() == campaign_name.lower() or cid == campaign_name:
                    campaign = c
                    campaign_id = cid
                    break
            
            if not campaign:
                return f"Campaign '{campaign_name}' not found."
            
            details = f"Campaign Details: {campaign['name']}\n"
            details += f"Platform: {campaign['platform']}\n"
            details += f"Budget: ${campaign['budget']:.2f}\n"
            details += f"Spent: ${campaign['spent']:.2f}\n"
            details += f"Status: {campaign['status']}\n"
            details += f"Start Date: {campaign['start_date']}\n"
            details += f"End Date: {campaign['end_date']}\n"
            
            details += "\nMetrics:\n"
            metrics = campaign["metrics"]
            details += f"  Impressions: {metrics['impressions']:,}\n"
            details += f"  Clicks: {metrics['clicks']:,}\n"
            details += f"  Conversions: {metrics['conversions']:,}\n"
            details += f"  CTR: {metrics['ctr']:.2f}%\n"
            details += f"  CPC: ${metrics['cpc']:.2f}\n"
            details += f"  Conversion Rate: {metrics['conversion_rate']:.2f}%"
            
            return details
            
        except Exception as e:
            logger.error(f"Error getting campaign details: {str(e)}")
            return f"Error getting campaign details: {str(e)}"
    
    def _pause_campaign(self, campaign_name: str) -> str:
        """Pause a campaign."""
        try:
            # Find campaign
            for campaign_id, campaign in self.campaigns.items():
                if campaign["name"].lower() == campaign_name.lower() or campaign_id == campaign_name:
                    if campaign["status"] == "paused":
                        return f"Campaign '{campaign_name}' is already paused."
                    
                    campaign["status"] = "paused"
                    return f"Campaign '{campaign_name}' has been paused."
            
            return f"Campaign '{campaign_name}' not found."
            
        except Exception as e:
            logger.error(f"Error pausing campaign: {str(e)}")
            return f"Error pausing campaign: {str(e)}"
    
    def _resume_campaign(self, campaign_name: str) -> str:
        """Resume a paused campaign."""
        try:
            # Find campaign
            for campaign_id, campaign in self.campaigns.items():
                if campaign["name"].lower() == campaign_name.lower() or campaign_id == campaign_name:
                    if campaign["status"] == "active":
                        return f"Campaign '{campaign_name}' is already active."
                    
                    campaign["status"] = "active"
                    return f"Campaign '{campaign_name}' has been resumed."
            
            return f"Campaign '{campaign_name}' not found."
            
        except Exception as e:
            logger.error(f"Error resuming campaign: {str(e)}")
            return f"Error resuming campaign: {str(e)}"
    
    def _create_content(self, request: str) -> str:
        """Create new marketing content."""
        try:
            # Extract content details
            title = self._extract_content_title(request) or f"Content_{int(time.time())}"
            content_type = self._extract_content_type(request) or "text"
            platform = self._extract_platform(request) or "facebook"
            content_text = self._extract_content_text(request) or "New marketing content"
            
            # Validate content
            if content_type not in self.content_types:
                return f"Content type '{content_type}' not supported. Supported types: {', '.join(self.content_types)}"
            
            if platform not in self.supported_platforms:
                return f"Platform '{platform}' not supported. Supported platforms: {', '.join(self.supported_platforms)}"
            
            # Create content
            content_id = f"content_{int(time.time() * 1000000)}"
            
            self.content_library[content_id] = {
                "title": title,
                "type": content_type,
                "platform": platform,
                "content": content_text,
                "created_date": datetime.now().strftime("%Y-%m-%d"),
                "status": "draft"
            }
            
            return f"Content created successfully: {title} ({content_type}) for {platform}. Content ID: {content_id}"
            
        except Exception as e:
            logger.error(f"Error creating content: {str(e)}")
            return f"Error creating content: {str(e)}"
    
    def _list_content(self) -> str:
        """List all content."""
        try:
            if not self.content_library:
                return "No content found."
            
            content_list = "Marketing Content:\n"
            
            for content_id, content in self.content_library.items():
                title = content["title"]
                content_type = content["type"]
                platform = content["platform"]
                status = content["status"]
                
                content_list += f"- {title} ({content_type}, {platform}) - Status: {status} (ID: {content_id})\n"
            
            return content_list.strip()
            
        except Exception as e:
            logger.error(f"Error listing content: {str(e)}")
            return f"Error listing content: {str(e)}"
    
    def _edit_content(self, content_id: str, request: str) -> str:
        """Edit existing content."""
        try:
            if content_id not in self.content_library:
                return f"Content '{content_id}' not found."
            
            content = self.content_library[content_id]
            
            # Extract new content text
            new_text = self._extract_content_text(request)
            if new_text and new_text != "New marketing content":
                content["content"] = new_text
                return f"Content '{content_id}' updated successfully."
            else:
                return "Please provide the new content text."
            
        except Exception as e:
            logger.error(f"Error editing content: {str(e)}")
            return f"Error editing content: {str(e)}"
    
    def _publish_content(self, content_id: str) -> str:
        """Publish content."""
        try:
            if content_id not in self.content_library:
                return f"Content '{content_id}' not found."
            
            content = self.content_library[content_id]
            
            if content["status"] == "published":
                return f"Content '{content_id}' is already published."
            
            content["status"] = "published"
            content["published_date"] = datetime.now().strftime("%Y-%m-%d")
            
            return f"Content '{content_id}' has been published successfully."
            
        except Exception as e:
            logger.error(f"Error publishing content: {str(e)}")
            return f"Error publishing content: {str(e)}"
    
    def _get_campaign_analytics(self, campaign_name: str) -> str:
        """Get analytics for a specific campaign."""
        try:
            # Find campaign
            for campaign_id, campaign in self.campaigns.items():
                if campaign["name"].lower() == campaign_name.lower() or campaign_id == campaign_name:
                    metrics = campaign["metrics"]
                    
                    analytics = f"Analytics for {campaign['name']}:\n"
                    analytics += f"Impressions: {metrics['impressions']:,}\n"
                    analytics += f"Clicks: {metrics['clicks']:,}\n"
                    analytics += f"Conversions: {metrics['conversions']:,}\n"
                    analytics += f"Click-Through Rate: {metrics['ctr']:.2f}%\n"
                    analytics += f"Cost Per Click: ${metrics['cpc']:.2f}\n"
                    analytics += f"Conversion Rate: {metrics['conversion_rate']:.2f}%\n"
                    analytics += f"Spend: ${campaign['spent']:.2f} of ${campaign['budget']:.2f}"
                    
                    return analytics
            
            return f"Campaign '{campaign_name}' not found."
            
        except Exception as e:
            logger.error(f"Error getting campaign analytics: {str(e)}")
            return f"Error getting campaign analytics: {str(e)}"
    
    def _get_overall_analytics(self) -> str:
        """Get overall marketing analytics."""
        try:
            total_impressions = sum(c["metrics"]["impressions"] for c in self.campaigns.values())
            total_clicks = sum(c["metrics"]["clicks"] for c in self.campaigns.values())
            total_conversions = sum(c["metrics"]["conversions"] for c in self.campaigns.values())
            total_budget = sum(c["budget"] for c in self.campaigns.values())
            total_spent = sum(c["spent"] for c in self.campaigns.values())
            
            overall_ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0
            overall_cpc = (total_spent / total_clicks) if total_clicks > 0 else 0
            overall_conversion_rate = (total_conversions / total_clicks * 100) if total_clicks > 0 else 0
            
            analytics = f"Overall Marketing Analytics:\n"
            analytics += f"Total Campaigns: {len(self.campaigns)}\n"
            analytics += f"Total Impressions: {total_impressions:,}\n"
            analytics += f"Total Clicks: {total_clicks:,}\n"
            analytics += f"Total Conversions: {total_conversions:,}\n"
            analytics += f"Overall CTR: {overall_ctr:.2f}%\n"
            analytics += f"Overall CPC: ${overall_cpc:.2f}\n"
            analytics += f"Overall Conversion Rate: {overall_conversion_rate:.2f}%\n"
            analytics += f"Total Budget: ${total_budget:.2f}\n"
            analytics += f"Total Spent: ${total_spent:.2f}\n"
            analytics += f"Budget Utilization: {(total_spent/total_budget*100):.1f}%"
            
            return analytics
            
        except Exception as e:
            logger.error(f"Error getting overall analytics: {str(e)}")
            return f"Error getting overall analytics: {str(e)}"
    
    def _generate_performance_report(self) -> str:
        """Generate a performance report."""
        try:
            report = "Marketing Performance Report\n"
            report += "=" * 40 + "\n\n"
            
            # Overall summary
            report += "Overall Summary:\n"
            overall_analytics = self._get_overall_analytics()
            report += overall_analytics + "\n\n"
            
            # Campaign breakdown
            report += "Campaign Breakdown:\n"
            for campaign_id, campaign in self.campaigns.items():
                report += f"\n{campaign['name']}:\n"
                report += f"  Platform: {campaign['platform']}\n"
                report += f"  Status: {campaign['status']}\n"
                report += f"  Budget: ${campaign['budget']:.2f}\n"
                report += f"  Spent: ${campaign['spent']:.2f}\n"
                report += f"  CTR: {campaign['metrics']['ctr']:.2f}%\n"
                report += f"  Conversions: {campaign['metrics']['conversions']}\n"
            
            # Content summary
            report += f"\nContent Summary:\n"
            published_content = sum(1 for c in self.content_library.values() if c["status"] == "published")
            draft_content = sum(1 for c in self.content_library.values() if c["status"] == "draft")
            report += f"Published Content: {published_content}\n"
            report += f"Draft Content: {draft_content}\n"
            report += f"Total Content: {len(self.content_library)}\n"
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating performance report: {str(e)}")
            return f"Error generating performance report: {str(e)}"
    
    def _generate_campaign_report(self, campaign_name: str) -> str:
        """Generate a report for a specific campaign."""
        try:
            # Find campaign
            for campaign_id, campaign in self.campaigns.items():
                if campaign["name"].lower() == campaign_name.lower() or campaign_id == campaign_name:
                    report = f"Campaign Report: {campaign['name']}\n"
                    report += "=" * 40 + "\n\n"
                    
                    # Campaign details
                    report += "Campaign Details:\n"
                    report += f"Name: {campaign['name']}\n"
                    report += f"Platform: {campaign['platform']}\n"
                    report += f"Status: {campaign['status']}\n"
                    report += f"Start Date: {campaign['start_date']}\n"
                    report += f"End Date: {campaign['end_date']}\n\n"
                    
                    # Budget information
                    report += "Budget Information:\n"
                    report += f"Total Budget: ${campaign['budget']:.2f}\n"
                    report += f"Amount Spent: ${campaign['spent']:.2f}\n"
                    report += f"Remaining: ${campaign['budget'] - campaign['spent']:.2f}\n"
                    report += f"Utilization: {(campaign['spent']/campaign['budget']*100):.1f}%\n\n"
                    
                    # Performance metrics
                    report += "Performance Metrics:\n"
                    metrics = campaign["metrics"]
                    report += f"Impressions: {metrics['impressions']:,}\n"
                    report += f"Clicks: {metrics['clicks']:,}\n"
                    report += f"Conversions: {metrics['conversions']:,}\n"
                    report += f"Click-Through Rate: {metrics['ctr']:.2f}%\n"
                    report += f"Cost Per Click: ${metrics['cpc']:.2f}\n"
                    report += f"Conversion Rate: {metrics['conversion_rate']:.2f}%\n"
                    report += f"Cost Per Conversion: ${(campaign['spent']/metrics['conversions']):.2f}" if metrics['conversions'] > 0 else "Cost Per Conversion: N/A"
                    
                    return report
            
            return f"Campaign '{campaign_name}' not found."
            
        except Exception as e:
            logger.error(f"Error generating campaign report: {str(e)}")
            return f"Error generating campaign report: {str(e)}"
    
    # Helper methods for extracting information from requests
    def _extract_campaign_name(self, request: str) -> Optional[str]:
        """Extract campaign name from request."""
        try:
            import re
            
            # Look for campaign names
            patterns = [
                r'campaign\s+([A-Za-z0-9_]+)',
                r'for\s+([A-Za-z\s]+)\s+campaign',
                r'([A-Za-z_]+)\s+campaign'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, request, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
            
            return None
            
        except Exception:
            return None
    
    def _extract_platform(self, request: str) -> Optional[str]:
        """Extract platform from request."""
        try:
            for platform in self.supported_platforms:
                if platform.lower() in request.lower():
                    return platform
            return None
        except Exception:
            return None
    
    def _extract_budget(self, request: str) -> Optional[float]:
        """Extract budget amount from request."""
        try:
            import re
            
            # Look for dollar amounts
            dollar_pattern = r'\$(\d+(?:\.\d{2})?)'
            match = re.search(dollar_pattern, request)
            
            if match:
                return float(match.group(1))
            
            return None
            
        except Exception:
            return None
    
    def _extract_content_title(self, request: str) -> Optional[str]:
        """Extract content title from request."""
        try:
            import re
            
            # Look for content title patterns
            patterns = [
                r'title\s+[\'"]([^\'"]+)[\'"]',
                r'content\s+[\'"]([^\'"]+)[\'"]',
                r'about\s+([A-Za-z\s]+)',
                r'([A-Za-z\s]+)\s+content'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, request, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
            
            return None
            
        except Exception:
            return None
    
    def _extract_content_type(self, request: str) -> Optional[str]:
        """Extract content type from request."""
        try:
            for content_type in self.content_types:
                if content_type.lower() in request.lower():
                    return content_type
            return None
        except Exception:
            return None
    
    def _extract_content_text(self, request: str) -> Optional[str]:
        """Extract content text from request."""
        try:
            import re
            
            # Look for quoted text
            quote_pattern = r'[\'"]([^\'"]+)[\'"]'
            matches = re.findall(quote_pattern, request)
            
            if matches:
                # Return the last match (most likely to be the content)
                return matches[-1]
            
            return None
            
        except Exception:
            return None
    
    def _extract_content_id(self, request: str) -> Optional[str]:
        """Extract content ID from request."""
        try:
            import re
            
            # Look for content IDs
            pattern = r'(content_\d+)'
            match = re.search(pattern, request, re.IGNORECASE)
            
            if match:
                return match.group(1).lower()
            
            return None
            
        except Exception:
            return None
    
    def get_marketing_summary(self) -> Dict[str, Any]:
        """Get marketing summary."""
        try:
            summary = {
                "total_campaigns": len(self.campaigns),
                "active_campaigns": sum(1 for c in self.campaigns.values() if c["status"] == "active"),
                "total_budget": sum(c["budget"] for c in self.campaigns.values()),
                "total_spent": sum(c["spent"] for c in self.campaigns.values()),
                "total_content": len(self.content_library),
                "published_content": sum(1 for c in self.content_library.values() if c["status"] == "published"),
                "platforms_used": list(set(c["platform"] for c in self.campaigns.values())),
                "content_types_used": list(set(c["type"] for c in self.content_library.values()))
            }
            
            # Calculate overall metrics
            summary["total_impressions"] = sum(c["metrics"]["impressions"] for c in self.campaigns.values())
            summary["total_clicks"] = sum(c["metrics"]["clicks"] for c in self.campaigns.values())
            summary["total_conversions"] = sum(c["metrics"]["conversions"] for c in self.campaigns.values())
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating marketing summary: {str(e)}")
            return {}
