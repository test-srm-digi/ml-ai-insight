import React, { useEffect, useState } from 'react';
import { getVulnerabilityDetail } from '../services/api';

export default function VulnDetail({ cveId, onClose }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getVulnerabilityDetail(cveId)
      .then(setDetail)
      .catch(() => setDetail(null))
      .finally(() => setLoading(false));
  }, [cveId]);

  if (!cveId) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{cveId}</h2>
          <button onClick={onClose} className="modal-close">&times;</button>
        </div>

        {loading && <div className="modal-loading"><div className="spinner" /></div>}

        {!loading && detail && (
          <div className="modal-body">
            <div className="detail-grid">
              <div className="detail-section">
                <h4>Risk Assessment</h4>
                <div className="score-display">
                  <div className={`score-circle tier-bg-${(detail.tier || '').toLowerCase()}`}>
                    <span className="score-value">{detail.risk_score?.toFixed(3)}</span>
                    <span className="score-label">{detail.tier}</span>
                  </div>
                </div>
                <table className="detail-table">
                  <tbody>
                    <tr><td>ML Score</td><td>{detail.ml_score}</td></tr>
                    <tr><td>CVSS Score</td><td>{detail.cvss_score}</td></tr>
                    <tr><td>EPSS Score</td><td>{detail.epss_score}</td></tr>
                    <tr><td>Severity</td><td><span className={`badge severity-${(detail.severity || '').toLowerCase()}`}>{detail.severity}</span></td></tr>
                  </tbody>
                </table>
              </div>

              <div className="detail-section">
                <h4>Vulnerability Info</h4>
                <table className="detail-table">
                  <tbody>
                    <tr><td>Package</td><td>{detail.package_name}</td></tr>
                    <tr><td>Repo</td><td>{detail.repo}</td></tr>
                    {detail.primary_cwe && <tr><td>CWE</td><td>{detail.primary_cwe}</td></tr>}
                    {detail.user_action && <tr><td>User Action</td><td>{detail.user_action}</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>

            {detail.cve_description && (
              <div className="detail-section">
                <h4>Description</h4>
                <p className="description-text">{detail.cve_description}</p>
              </div>
            )}

            {detail.top_shap_features && detail.top_shap_features.length > 0 && (
              <div className="detail-section">
                <h4>Top Contributing Factors (Model Feature Importance)</h4>
                <div className="shap-list">
                  {detail.top_shap_features.map((f, i) => (
                    <div key={i} className="shap-item">
                      <span className="shap-name">{f.feature}</span>
                      <div className="shap-bar-container">
                        <div
                          className="shap-bar"
                          style={{
                            width: `${Math.min(100, f.importance * 500)}%`,
                            backgroundColor: '#6366f1',
                          }}
                        />
                      </div>
                      <span className="shap-value">{f.importance?.toFixed(4)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {!loading && !detail && (
          <div className="modal-body">
            <p>Could not load details for {cveId}.</p>
          </div>
        )}
      </div>
    </div>
  );
}
