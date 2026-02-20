import React from 'react';

export default function SummaryCards({ summary, tierDist }) {
  const critical = tierDist?.find(t => t.name === 'CRITICAL')?.value || 0;
  const high = tierDist?.find(t => t.name === 'HIGH')?.value || 0;

  return (
    <div className="summary-cards">
      <div className="card">
        <div className="card-label">Total Vulnerabilities</div>
        <div className="card-value">{summary.total_vulnerabilities.toLocaleString()}</div>
      </div>
      <div className="card card-critical">
        <div className="card-label">Critical</div>
        <div className="card-value">{critical}</div>
      </div>
      <div className="card card-high">
        <div className="card-label">High</div>
        <div className="card-value">{high}</div>
      </div>
      <div className="card">
        <div className="card-label">Avg Risk Score</div>
        <div className="card-value">{summary.avg_risk_score.toFixed(3)}</div>
      </div>
      <div className="card">
        <div className="card-label">Repos</div>
        <div className="card-value">{summary.unique_repos}</div>
      </div>
      <div className="card">
        <div className="card-label">Packages</div>
        <div className="card-value">{summary.unique_packages}</div>
      </div>
    </div>
  );
}
