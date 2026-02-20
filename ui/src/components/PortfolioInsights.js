import React, { useState, useCallback } from 'react';
import { getPortfolioInsights } from '../services/api';
import AiInsights from './AiInsights';

export default function PortfolioInsights() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleGenerate = useCallback(() => {
    setLoading(true);
    setError(null);
    getPortfolioInsights()
      .then(setData)
      .catch((err) => {
        const msg = err.response?.data?.detail || err.message || 'Unknown error';
        setError(msg);
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="section">
      <div className="section-header">
        <h3 className="section-title">Portfolio AI Risk Analysis</h3>
        {!data && !loading && (
          <button className="btn-ai" onClick={handleGenerate}>
            <span className="btn-ai-icon">*</span>
            Generate Portfolio Insights
          </button>
        )}
      </div>

      {!data && !loading && !error && (
        <p style={{ fontSize: 14, color: '#64748b', marginTop: 8 }}>
          Generate an AI-powered analysis of your entire vulnerability portfolio. The analysis
          covers security posture, risk distribution, CWE patterns, and prioritised remediation actions.
        </p>
      )}

      {data && data.summary_stats && (
        <div className="summary-cards" style={{ marginBottom: 16 }}>
          <div className="card">
            <div className="card-label">Total Vulnerabilities</div>
            <div className="card-value">{data.summary_stats.total_vulnerabilities}</div>
          </div>
          <div className="card">
            <div className="card-label">Avg Risk Score</div>
            <div className="card-value">{data.summary_stats.avg_risk_score}</div>
          </div>
          {data.summary_stats.tier_counts && (
            <>
              <div className="card card-critical">
                <div className="card-label">Critical</div>
                <div className="card-value">{data.summary_stats.tier_counts.CRITICAL || 0}</div>
              </div>
              <div className="card card-high">
                <div className="card-label">High</div>
                <div className="card-value">{data.summary_stats.tier_counts.HIGH || 0}</div>
              </div>
            </>
          )}
        </div>
      )}

      <AiInsights
        context={data?.context || ''}
        impact={data?.impact || ''}
        remedy={data?.remedy || ''}
        loading={loading}
        error={error}
        onRetry={handleGenerate}
      />
    </div>
  );
}
