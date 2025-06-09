#!/usr/bin/env python3
"""
Integration tests for SOC Automation Bot
"""

import pytest
import json
import pandas as pd
from unittest.mock import patch, MagicMock
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingestion import ingest_alerts
from enrichment import enrich_alerts
from triage import triage
from response import execute_actions
from main import SOCAutomationBot


class TestSOCPipeline:
    """Test the complete SOC automation pipeline"""
    
    def test_full_pipeline(self):
        """Test the complete pipeline from ingestion to response"""
        # Step 1: Ingest alerts
        raw_alerts = ingest_alerts(use_sample=True)
        assert len(raw_alerts) > 0
        assert isinstance(raw_alerts, pd.DataFrame)
        
        # Step 2: Enrich alerts
        enriched_alerts = enrich_alerts(raw_alerts)
        assert len(enriched_alerts) == len(raw_alerts)
        assert 'threat_score' in enriched_alerts.columns
        assert 'geo_country' in enriched_alerts.columns
        
        # Step 3: Triage alerts
        triaged_alerts = triage(enriched_alerts)
        assert len(triaged_alerts) == len(enriched_alerts)
        assert 'risk_level' in triaged_alerts.columns
        assert 'confidence' in triaged_alerts.columns
        
        # Step 4: Execute responses
        processed_alerts = []
        for _, alert in triaged_alerts.iterrows():
            alert_dict = alert.to_dict()
            response = execute_actions(alert_dict)
            processed_alerts.append(response)
        
        assert len(processed_alerts) == len(triaged_alerts)
        assert all('actions_taken' in alert for alert in processed_alerts)
    
    def test_pipeline_performance(self):
        """Test pipeline performance meets SLA requirements"""
        import time
        
        start_time = time.time()
        
        # Run pipeline
        raw_alerts = ingest_alerts(use_sample=True)
        enriched_alerts = enrich_alerts(raw_alerts)
        triaged_alerts = triage(enriched_alerts)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process 50 alerts in under 5 seconds
        assert processing_time < 5.0
        print(f"Pipeline processed {len(raw_alerts)} alerts in {processing_time:.2f} seconds")
    
    def test_data_quality(self):
        """Test data quality throughout the pipeline"""
        raw_alerts = ingest_alerts(use_sample=True)
        enriched_alerts = enrich_alerts(raw_alerts)
        triaged_alerts = triage(enriched_alerts)
        
        # Check for data completeness
        assert not raw_alerts.empty
        assert not enriched_alerts.empty
        assert not triaged_alerts.empty
        
        # Check for required columns
        required_raw_cols = ['id', 'timestamp', 'source_ip', 'event_type']
        assert all(col in raw_alerts.columns for col in required_raw_cols)
        
        required_enriched_cols = required_raw_cols + ['threat_score', 'geo_country']
        assert all(col in enriched_alerts.columns for col in required_enriched_cols)
        
        required_triaged_cols = required_enriched_cols + ['risk_level', 'confidence']
        assert all(col in triaged_alerts.columns for col in required_triaged_cols)
    
    def test_alert_classification(self):
        """Test alert risk classification accuracy"""
        raw_alerts = ingest_alerts(use_sample=True)
        enriched_alerts = enrich_alerts(raw_alerts)
        triaged_alerts = triage(enriched_alerts)
        
        # Check risk level distribution
        risk_counts = triaged_alerts['risk_level'].value_counts()
        
        # Should have alerts in multiple risk categories
        assert len(risk_counts) >= 2
        
        # Risk levels should be valid
        valid_risk_levels = {'Low', 'Medium', 'High'}
        assert all(level in valid_risk_levels for level in risk_counts.index)
        
        # Confidence scores should be reasonable
        confidence_scores = triaged_alerts['confidence'].dropna()
        assert all(0 <= score <= 1 for score in confidence_scores)


class TestSOCBot:
    """Test the SOC Automation Bot main class"""
    
    def test_bot_initialization(self):
        """Test SOC bot initializes correctly"""
        bot = SOCAutomationBot()
        assert bot.config is not None
        assert hasattr(bot, 'logger')
    
    def test_pipeline_execution(self):
        """Test bot can execute pipeline"""
        bot = SOCAutomationBot()
        result = bot.run_pipeline_once()
        
        assert 'processing_time' in result
        assert 'total_alerts' in result
        assert 'status' in result
        assert result['status'] == 'success'


class TestErrorHandling:
    """Test error handling and resilience"""
    
    def test_empty_alert_handling(self):
        """Test handling of empty alert datasets"""
        empty_df = pd.DataFrame()
        
        # Should handle empty dataframes gracefully
        enriched = enrich_alerts(empty_df)
        assert enriched.empty
        
        triaged = triage(empty_df)
        assert triaged.empty
    
    @patch('enrichment.requests.get')
    def test_api_failure_handling(self, mock_get):
        """Test handling of API failures"""
        # Mock API failure
        mock_get.side_effect = Exception("API Error")
        
        raw_alerts = ingest_alerts(use_sample=True)
        
        # Should continue processing even with API failures
        enriched_alerts = enrich_alerts(raw_alerts)
        assert len(enriched_alerts) > 0
    
    def test_malformed_data_handling(self):
        """Test handling of malformed data"""
        # Create malformed data
        malformed_data = pd.DataFrame({
            'id': ['TEST-001'],
            'invalid_field': ['invalid']
        })
        
        # Should handle gracefully without crashing
        try:
            enriched = enrich_alerts(malformed_data)
            triaged = triage(enriched)
            assert True  # If we get here, error handling worked
        except Exception as e:
            pytest.fail(f"Failed to handle malformed data: {e}")


class TestSecurity:
    """Test security-related functionality"""
    
    def test_ip_validation(self):
        """Test IP address validation"""
        raw_alerts = ingest_alerts(use_sample=True)
        
        # Check that source IPs are valid
        for _, alert in raw_alerts.iterrows():
            source_ip = alert.get('source_ip')
            if source_ip and source_ip != 'unknown':
                # Basic IP format validation
                parts = source_ip.split('.')
                assert len(parts) == 4
                assert all(0 <= int(part) <= 255 for part in parts)
    
    def test_threat_scoring(self):
        """Test threat scoring mechanism"""
        raw_alerts = ingest_alerts(use_sample=True)
        enriched_alerts = enrich_alerts(raw_alerts)
        
        # Check threat scores are within valid range
        threat_scores = enriched_alerts['threat_score'].dropna()
        assert all(0 <= score <= 100 for score in threat_scores)
    
    def test_response_actions(self):
        """Test security response actions"""
        # Create a high-risk alert
        high_risk_alert = {
            'id': 'TEST-HIGH-001',
            'risk_level': 'High',
            'source_ip': '192.168.1.100',
            'event_type': 'Malware Detection'
        }
        
        response = execute_actions(high_risk_alert)
        
        # High-risk alerts should trigger multiple actions
        assert 'actions_taken' in response
        actions = response['actions_taken']
        
        # Should include blocking and ticketing for high-risk
        action_types = [action['action'] for action in actions]
        assert 'block_ip' in action_types
        assert 'create_ticket' in action_types


@pytest.fixture
def sample_alerts():
    """Fixture providing sample alerts for testing"""
    return ingest_alerts(use_sample=True)


def test_end_to_end_workflow(sample_alerts):
    """Test complete end-to-end workflow"""
    # Process through entire pipeline
    enriched = enrich_alerts(sample_alerts)
    triaged = triage(enriched)
    
    # Verify each step adds value
    assert len(enriched.columns) > len(sample_alerts.columns)
    assert len(triaged.columns) > len(enriched.columns)
    
    # Verify data integrity
    assert len(sample_alerts) == len(enriched) == len(triaged)


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 